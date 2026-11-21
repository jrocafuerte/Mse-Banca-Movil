import { Inject, Injectable, Logger } from '@nestjs/common';
import { createHash, randomInt, randomUUID, timingSafeEqual } from 'node:crypto';
import { ENV, type Env } from '../../config/env.js';

interface Challenge {
  customerId: string;
  purpose: string;
  /** Hash del contexto de la operación (monto, destino): el OTP solo vale para esa operación. */
  contextHash: string;
  otpHash: Buffer;
  attempts: number;
  expiresAt: number;
}

const MAX_ATTEMPTS = 3;
const TTL_MS = 120_000;
const hash = (v: string) => createHash('sha256').update(v).digest();

/**
 * OTP de un solo uso (SMS / push / soft token). En producción se delega a un
 * servicio de autenticación fuerte (p. ej. un IdP con MFA) y nunca se registra.
 */
@Injectable()
export class OtpService {
  private readonly logger = new Logger(OtpService.name);
  private readonly challenges = new Map<string, Challenge>();

  constructor(@Inject(ENV) private readonly env: Env) {}

  issue(customerId: string, purpose: string, context: unknown = {}): { challengeId: string; expiresIn: number } {
    const challengeId = randomUUID();
    // En dev/test el OTP es fijo para facilitar pruebas; en prod es aleatorio y se envía por canal seguro.
    const otp = this.env.NODE_ENV === 'production' ? randomInt(0, 1_000_000).toString().padStart(6, '0') : '123456';
    this.challenges.set(challengeId, {
      customerId,
      purpose,
      contextHash: hash(JSON.stringify(context)).toString('hex'),
      otpHash: hash(otp),
      attempts: 0,
      expiresAt: Date.now() + TTL_MS,
    });
    this.logger.log({ msg: 'otp.issued', purpose, challengeId });
    // TODO(prod): notificationGateway.sendOtp(customerId, otp)
    return { challengeId, expiresIn: TTL_MS / 1000 };
  }

  /** Verifica y consume el desafío. Devuelve el customerId o undefined. */
  verify(challengeId: string, otp: string, purpose: string, context: unknown = {}): string | undefined {
    const c = this.challenges.get(challengeId);
    if (!c || c.purpose !== purpose || c.expiresAt < Date.now()) return undefined;
    c.attempts += 1;
    const ok = timingSafeEqual(hash(otp), c.otpHash) && c.contextHash === hash(JSON.stringify(context)).toString('hex');
    if (ok || c.attempts >= MAX_ATTEMPTS) this.challenges.delete(challengeId);
    return ok ? c.customerId : undefined;
  }
}
