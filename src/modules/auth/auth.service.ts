import { HttpException, HttpStatus, Inject, Injectable, Logger, UnauthorizedException } from '@nestjs/common';
import { ENV, type Env } from '../../config/env.js';
import { CoreBankingPort } from '../../core-banking/core-banking.port.js';
import { verifyPassword } from '../../core-banking/password.js';
import { TokenService } from '../../crypto/token.service.js';
import { ACCESS_AUDIENCE, ACCESS_TOKEN_TYPE } from '../../common/security/auth.guard.js';
import { maskDocument } from '../../common/security/mask.js';
import type { LoginDto, RefreshDto, VerifyMfaDto } from './auth.schemas.js';
import { OtpService } from './otp.service.js';
import { SessionStore } from './session.store.js';

const MAX_FAILED = 5;
const LOCK_MS = 15 * 60 * 1000;
// Hash señuelo: se verifica aunque el usuario no exista para no filtrar su existencia por tiempo de respuesta.
const DUMMY_HASH = 'scrypt$32768$AAAAAAAAAAAAAAAAAAAAAA==$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=';

export interface TokenPair {
  accessToken: string;
  refreshToken: string;
  tokenType: 'Bearer';
  expiresIn: number;
}

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);
  private readonly failed = new Map<string, { count: number; until: number }>();

  constructor(
    @Inject(ENV) private readonly env: Env,
    private readonly core: CoreBankingPort,
    private readonly otp: OtpService,
    private readonly sessions: SessionStore,
    private readonly tokens: TokenService,
  ) {}

  async login(dto: LoginDto) {
    const lock = this.failed.get(dto.documentId);
    if (lock && lock.until > Date.now()) {
      throw new HttpException('Usuario bloqueado temporalmente', HttpStatus.TOO_MANY_REQUESTS);
    }
    const customer = await this.core.findCustomerByDocument(dto.documentId);
    const valid = await verifyPassword(dto.password, customer?.passwordHash ?? DUMMY_HASH);
    if (!customer || !valid) {
      this.registerFailure(dto.documentId);
      this.logger.warn({ msg: 'auth.login.failed', doc: maskDocument(dto.documentId) });
      throw new UnauthorizedException('Credenciales inválidas'); // mensaje genérico (no enumera usuarios)
    }
    this.failed.delete(dto.documentId);
    const challenge = this.otp.issue(customer.id, 'login', { deviceId: dto.deviceId });
    return { mfaRequired: true, channel: 'SMS', destination: customer.phoneMasked, ...challenge };
  }

  async verifyMfa(dto: VerifyMfaDto): Promise<TokenPair & { customer: { name: string } }> {
    const customerId = this.otp.verify(dto.challengeId, dto.otp, 'login', { deviceId: dto.deviceId });
    if (!customerId) throw new UnauthorizedException('Código inválido o expirado');
    const customer = await this.core.findCustomer(customerId);
    const { sid, refreshToken } = this.sessions.create(customerId, dto.deviceId, this.env.REFRESH_TOKEN_TTL_SECONDS);
    const access = await this.issueAccess(customerId, sid, dto.deviceId);
    this.logger.log({ msg: 'auth.login.success', sid });
    return { ...access, refreshToken, customer: { name: customer?.fullName.split(' ')[0] ?? '' } };
  }

  async refresh(dto: RefreshDto): Promise<TokenPair> {
    const rotated = this.sessions.rotate(dto.refreshToken, dto.deviceId, this.env.REFRESH_TOKEN_TTL_SECONDS);
    if (!rotated) throw new UnauthorizedException('Sesión expirada');
    const access = await this.issueAccess(rotated.customerId, rotated.sid, dto.deviceId);
    return { ...access, refreshToken: rotated.refreshToken };
  }

  logout(sid: string): void {
    this.sessions.revoke(sid);
  }

  private async issueAccess(sub: string, sid: string, did: string) {
    const { token, expiresIn } = await this.tokens.sign(
      { sub, sid, did, scope: 'accounts transfers cards payments' },
      { audience: ACCESS_AUDIENCE, ttlSeconds: this.env.ACCESS_TOKEN_TTL_SECONDS, type: ACCESS_TOKEN_TYPE },
    );
    return { accessToken: token, tokenType: 'Bearer' as const, expiresIn };
  }

  private registerFailure(doc: string): void {
    const f = this.failed.get(doc) ?? { count: 0, until: 0 };
    f.count += 1;
    if (f.count >= MAX_FAILED) {
      f.until = Date.now() + LOCK_MS;
      f.count = 0;
    }
    this.failed.set(doc, f);
  }
}
