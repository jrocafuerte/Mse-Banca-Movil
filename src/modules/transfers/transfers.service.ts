import {
  ForbiddenException,
  Inject,
  Injectable,
  Logger,
  NotFoundException,
  UnauthorizedException,
  UnprocessableEntityException,
} from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import { ENV, type Env, requiresDeviceSignature } from '../../config/env.js';
import { maskAccount } from '../../common/security/mask.js';
import { CoreBankingPort } from '../../core-banking/core-banking.port.js';
import { OtpService } from '../auth/otp.service.js';
import { DeviceKeysStore } from '../devices/device-keys.store.js';
import type { ConfirmTransferDto, PrepareTransferDto } from './transfers.schemas.js';

interface PendingTransfer extends PrepareTransferDto {
  id: string;
  customerId: string;
  toAccountId?: string;
  challengeId?: string;
  expiresAt: number;
}

const PENDING_TTL_MS = 5 * 60 * 1000;

/**
 * Flujo en dos pasos: prepare (valida, calcula y decide si requiere OTP) y
 * confirm (ejecuta). El monto/destino quedan congelados en el servidor, por lo
 * que el cliente no puede alterarlos entre ambos pasos.
 */
@Injectable()
export class TransfersService {
  private readonly logger = new Logger(TransfersService.name);
  private readonly pending = new Map<string, PendingTransfer>();

  constructor(
    @Inject(ENV) private readonly env: Env,
    private readonly core: CoreBankingPort,
    private readonly otp: OtpService,
    private readonly deviceKeys: DeviceKeysStore,
  ) {}

  async prepare(customerId: string, dto: PrepareTransferDto) {
    const accounts = await this.core.listAccounts(customerId);
    const from = accounts.find((a) => a.id === dto.fromAccountId);
    if (!from) throw new ForbiddenException('Cuenta origen no pertenece al cliente');
    if (from.currency !== dto.currency) throw new UnprocessableEntityException('Moneda no coincide');
    if (from.availableBalance < dto.amount) throw new UnprocessableEntityException('Fondos insuficientes');

    let toAccountId: string | undefined;
    let beneficiary = 'Cuenta externa';
    if (dto.type !== 'INTERBANK') {
      const to = await this.core.findAccountByNumber(dto.toAccountNumber);
      if (!to) throw new UnprocessableEntityException('Cuenta destino no existe');
      if (to.id === from.id) throw new UnprocessableEntityException('Origen y destino iguales');
      const isOwn = to.ownerId === customerId;
      if ((dto.type === 'OWN') !== isOwn) throw new UnprocessableEntityException('Tipo de transferencia inválido');
      toAccountId = to.id;
      beneficiary = isOwn ? 'Cuenta propia' : 'Tercero';
    }

    const id = randomUUID();
    const otpRequired = dto.type !== 'OWN' && dto.amount >= this.env.STEP_UP_THRESHOLD;
    const challenge = otpRequired
      ? this.otp.issue(customerId, 'transfer', { id, amount: dto.amount, to: dto.toAccountNumber })
      : undefined;
    this.pending.set(id, {
      ...dto,
      id,
      customerId,
      toAccountId,
      challengeId: challenge?.challengeId,
      expiresAt: Date.now() + PENDING_TTL_MS,
    });

    return {
      transferId: id,
      summary: {
        from: maskAccount(from.number),
        to: maskAccount(dto.toAccountNumber),
        beneficiary,
        amount: dto.amount,
        currency: dto.currency,
        fee: dto.type === 'INTERBANK' ? 1.5 : 0,
      },
      otpRequired,
      challengeId: challenge?.challengeId,
      expiresIn: PENDING_TTL_MS / 1000,
    };
  }

  async confirm(customerId: string, deviceId: string, id: string, dto: ConfirmTransferDto) {
    const t = this.pending.get(id);
    if (!t || t.customerId !== customerId || t.expiresAt < Date.now())
      throw new NotFoundException('Transferencia no encontrada o expirada');
    if (t.challengeId) {
      const ok =
        dto.otp && this.otp.verify(t.challengeId, dto.otp, 'transfer', { id, amount: t.amount, to: t.toAccountNumber });
      if (!ok) throw new UnauthorizedException('OTP inválido');
    }
    this.deviceKeys.authorize(
      { customerId, deviceId, operationId: id, amount: t.amount, currency: t.currency, signature: dto.signature },
      requiresDeviceSignature(this.env),
    );
    this.pending.delete(id); // un solo uso
    const result = await this.core.debitCredit({
      fromAccountId: t.fromAccountId,
      toAccountId: t.toAccountId,
      toExternal: t.type === 'INTERBANK' ? { bankCode: t.bankCode!, account: t.toAccountNumber } : undefined,
      amount: t.amount,
      currency: t.currency,
      description: t.description,
    });
    this.logger.log({ msg: 'transfer.executed', transferId: id, type: t.type, operationId: result.operationId });
    return { transferId: id, status: 'COMPLETED', ...result };
  }
}
