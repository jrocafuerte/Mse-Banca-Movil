import { Injectable } from '@nestjs/common';
import { createHash, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';

interface Session {
  sid: string;
  customerId: string;
  deviceId: string;
  refreshHash: Buffer;
  expiresAt: number;
  createdAt: number;
  active: boolean;
}

const sha256 = (v: string) => createHash('sha256').update(v).digest();

/**
 * Sesiones server-side con refresh tokens opacos y rotación obligatoria.
 * Si un refresh token ya usado vuelve a presentarse (robo), se revoca la
 * sesión completa (refresh token reuse detection - OAuth 2.0 BCP).
 * Producción: Redis/ElastiCache cifrado con TTL.
 */
@Injectable()
export class SessionStore {
  private readonly sessions = new Map<string, Session>();

  create(customerId: string, deviceId: string, ttlSeconds: number): { sid: string; refreshToken: string } {
    const sid = randomUUID();
    const refreshToken = `${sid}.${randomBytes(32).toString('base64url')}`;
    this.sessions.set(sid, {
      sid,
      customerId,
      deviceId,
      refreshHash: sha256(refreshToken),
      expiresAt: Date.now() + ttlSeconds * 1000,
      createdAt: Date.now(),
      active: true,
    });
    return { sid, refreshToken };
  }

  /** Rota el refresh token. Devuelve undefined (y revoca) si es inválido o reutilizado. */
  rotate(
    refreshToken: string,
    deviceId: string,
    ttlSeconds: number,
  ): { sid: string; customerId: string; refreshToken: string } | undefined {
    const sid = refreshToken.split('.')[0] ?? '';
    const s = this.sessions.get(sid);
    if (!s || !s.active || s.expiresAt < Date.now()) return undefined;
    const presented = sha256(refreshToken);
    if (!timingSafeEqual(presented, s.refreshHash) || s.deviceId !== deviceId) {
      s.active = false; // posible robo de token
      return undefined;
    }
    const next = `${sid}.${randomBytes(32).toString('base64url')}`;
    s.refreshHash = sha256(next);
    s.expiresAt = Date.now() + ttlSeconds * 1000;
    return { sid, customerId: s.customerId, refreshToken: next };
  }

  /** Milisegundos desde la autenticación con MFA (los refresh no reinician el contador). */
  ageMs(sid: string): number {
    const s = this.sessions.get(sid);
    return s ? Date.now() - s.createdAt : Number.POSITIVE_INFINITY;
  }

  isActive(sid: string): boolean {
    const s = this.sessions.get(sid);
    return !!s && s.active && s.expiresAt > Date.now();
  }

  revoke(sid: string): void {
    const s = this.sessions.get(sid);
    if (s) s.active = false;
  }
}
