import { Inject, Injectable, Logger, OnModuleInit, UnauthorizedException } from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import {
  type CryptoKey,
  type JWK,
  type JWTPayload,
  SignJWT,
  exportJWK,
  generateKeyPair,
  importJWK,
  importPKCS8,
  jwtVerify,
  calculateJwkThumbprint,
} from 'jose';
import { ENV, type Env } from '../config/env.js';

export const ALG = 'ES256';

export interface AccessClaims extends JWTPayload {
  sub: string;
  sid: string; // id de sesión (permite revocación)
  did: string; // id de dispositivo (device binding)
  scope: string;
}

/**
 * Firma/verifica JWT ES256. En producción la clave privada vive en un HSM/KMS
 * y se rota publicando el nuevo `kid` en el JWKS antes de usarla.
 */
@Injectable()
export class TokenService implements OnModuleInit {
  private readonly logger = new Logger(TokenService.name);
  private privateKey!: CryptoKey;
  private publicKey!: CryptoKey | Uint8Array;
  private publicJwk!: JWK;
  private kid!: string;

  constructor(@Inject(ENV) private readonly env: Env) {}

  async onModuleInit(): Promise<void> {
    if (this.env.TOKEN_PRIVATE_KEY_PEM) {
      this.privateKey = await importPKCS8(this.env.TOKEN_PRIVATE_KEY_PEM, ALG, { extractable: true });
    } else {
      // Solo desarrollo/test: clave efímera.
      this.logger.warn('TOKEN_PRIVATE_KEY_PEM no definido: usando clave efímera (solo dev/test)');
      const pair = await generateKeyPair(ALG, { extractable: true });
      this.privateKey = pair.privateKey;
    }
    const jwk = await exportJWK(this.privateKey);
    // Se publica únicamente la parte pública.
    const { d: _d, ...pub } = jwk;
    this.kid = await calculateJwkThumbprint(pub);
    this.publicJwk = { ...pub, kid: this.kid, alg: ALG, use: 'sig' };
    this.publicKey = await importJWK(pub, ALG);
  }

  jwks(): { keys: JWK[] } {
    return { keys: [this.publicJwk] };
  }

  async sign(
    claims: JWTPayload,
    opts: { audience: string; ttlSeconds: number; type?: string },
  ): Promise<{ token: string; jti: string; expiresIn: number }> {
    const jti = randomUUID();
    const token = await new SignJWT(claims)
      .setProtectedHeader({ alg: ALG, kid: this.kid, typ: opts.type ?? 'JWT' })
      .setIssuer(this.env.TOKEN_ISSUER)
      .setAudience(opts.audience)
      .setIssuedAt()
      .setNotBefore('0s')
      .setExpirationTime(`${opts.ttlSeconds}s`)
      .setJti(jti)
      .sign(this.privateKey);
    return { token, jti, expiresIn: opts.ttlSeconds };
  }

  async verify<T extends JWTPayload>(token: string, audience: string, type?: string): Promise<T> {
    try {
      const { payload } = await jwtVerify<T>(token, this.publicKey, {
        issuer: this.env.TOKEN_ISSUER,
        audience,
        algorithms: [ALG],
        typ: type,
        clockTolerance: 5,
      });
      return payload;
    } catch {
      throw new UnauthorizedException('Token inválido o expirado');
    }
  }
}
