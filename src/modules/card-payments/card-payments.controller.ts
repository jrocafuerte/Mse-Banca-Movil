import {
  Body,
  Controller,
  ForbiddenException,
  Headers,
  HttpCode,
  Inject,
  Logger,
  Post,
  UnprocessableEntityException,
  UseInterceptors,
} from '@nestjs/common';
import { z } from 'zod';
import { IdempotencyInterceptor } from '../../common/idempotency/idempotency.interceptor.js';
import { CurrentUser } from '../../common/security/auth.guard.js';
import { maskPan } from '../../common/security/mask.js';
import { CoreBankingPort } from '../../core-banking/core-banking.port.js';
import type { AccessClaims } from '../../crypto/token.service.js';
import { DeviceSignature, Money } from '../transfers/transfers.schemas.js';
import { DeviceKeysStore } from '../devices/device-keys.store.js';
import { ENV, type Env, requiresDeviceSignature } from '../../config/env.js';

const PayCardSchema = z
  .strictObject({
    cardId: z.string().regex(/^card-\d{3,6}$/),
    fromAccountId: z.string().regex(/^acc-\d{3,6}$/),
    amountType: z.enum(['MINIMUM', 'TOTAL', 'OTHER']),
    amount: Money.optional(),
    /** HMAC de "Idempotency-Key|monto|moneda" con la clave del dispositivo (biometría). */
    signature: DeviceSignature,
  })
  .refine((p) => p.amountType !== 'OTHER' || p.amount !== undefined, { message: 'amount requerido', path: ['amount'] });
type PayCardDto = z.infer<typeof PayCardSchema>;

@Controller('v1/card-payments')
export class CardPaymentsController {
  private readonly logger = new Logger(CardPaymentsController.name);

  constructor(
    private readonly core: CoreBankingPort,
    private readonly deviceKeys: DeviceKeysStore,
    @Inject(ENV) private readonly env: Env,
  ) {}

  @Post()
  @HttpCode(201)
  @UseInterceptors(IdempotencyInterceptor)
  async pay(
    @CurrentUser() user: AccessClaims,
    @Body({ schema: PayCardSchema }) dto: PayCardDto,
    @Headers('idempotency-key') idempotencyKey: string,
  ) {
    const [cards, accounts] = await Promise.all([this.core.listCards(user.sub), this.core.listAccounts(user.sub)]);
    const card = cards.find((c) => c.id === dto.cardId);
    const from = accounts.find((a) => a.id === dto.fromAccountId);
    if (!card || !from) throw new ForbiddenException();
    if (card.currency !== from.currency) throw new UnprocessableEntityException('Moneda no coincide');

    // El monto se resuelve en servidor: el cliente no decide cuánto es "mínimo" o "total".
    const amount =
      dto.amountType === 'MINIMUM'
        ? card.minimumPayment
        : dto.amountType === 'TOTAL'
          ? card.statementBalance
          : dto.amount!;
    if (amount <= 0) throw new UnprocessableEntityException('No hay deuda pendiente');
    if (amount > card.statementBalance) throw new UnprocessableEntityException('Monto mayor a la deuda');

    this.deviceKeys.authorize(
      {
        customerId: user.sub,
        deviceId: user.did,
        operationId: idempotencyKey,
        amount,
        currency: card.currency,
        signature: dto.signature,
      },
      requiresDeviceSignature(this.env),
    );
    const result = await this.core.payCard({ fromAccountId: from.id, cardId: card.id, amount });
    this.logger.log({ msg: 'card.payment.executed', operationId: result.operationId });
    return { status: 'COMPLETED', card: maskPan(card.pan), amount, currency: card.currency, ...result };
  }
}
