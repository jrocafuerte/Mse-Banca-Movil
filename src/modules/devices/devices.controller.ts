import { Body, Controller, ForbiddenException, HttpCode, Logger, Post } from '@nestjs/common';
import { Throttle } from '@nestjs/throttler';
import { z } from 'zod';
import { CurrentUser } from '../../common/security/auth.guard.js';
import type { AccessClaims } from '../../crypto/token.service.js';
import { SessionStore } from '../auth/session.store.js';
import { DeviceKeysStore } from './device-keys.store.js';

/** Ventana tras el MFA en la que se permite registrar la clave del dispositivo. */
const ENROLL_WINDOW_MS = 5 * 60 * 1000;

const EnrollSchema = z.strictObject({ key: z.string().regex(/^[A-Za-z0-9_-]{43}$/, 'Clave de 32 bytes en base64url') });

@Controller('v1/devices')
@Throttle({ default: { limit: 5, ttl: 60_000 } })
export class DevicesController {
  private readonly logger = new Logger(DevicesController.name);

  constructor(
    private readonly keys: DeviceKeysStore,
    private readonly sessions: SessionStore,
  ) {}

  /**
   * Registro de la clave de firma. Solo en una sesión recién creada con
   * contraseña + OTP: un access token robado más tarde no puede sustituir la
   * clave del dispositivo legítimo.
   */
  @Post('signing-key')
  @HttpCode(204)
  enroll(@CurrentUser() user: AccessClaims, @Body({ schema: EnrollSchema }) body: z.infer<typeof EnrollSchema>): void {
    if (this.sessions.ageMs(user.sid) > ENROLL_WINDOW_MS) {
      throw new ForbiddenException('Vuelve a autenticarte para activar la biometría');
    }
    this.keys.register(user.sub, user.did, body.key);
    this.logger.log({ msg: 'device.signing_key.enrolled', sid: user.sid });
  }
}
