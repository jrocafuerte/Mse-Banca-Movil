import { Body, Controller, HttpCode, Inject, Post } from '@nestjs/common';
import { Throttle } from '@nestjs/throttler';
import { z } from 'zod';
import { ENV, type Env, requiresDeviceSignature } from '../../config/env.js';
import { CurrentUser } from '../../common/security/auth.guard.js';
import { TokenService, type AccessClaims } from '../../crypto/token.service.js';
import { DeviceKeysStore } from '../devices/device-keys.store.js';

export const HANDOFF_TYPE = 'handoff+jwt';
export const STEP_UP_TYPE = 'stepup+jwt';

const StepUpSchema = z.strictObject({
  /** sha256 (hex) del intent de pago calculado por mse-recaudos. */
  intentHash: z.string().regex(/^[a-f0-9]{64}$/),
  amount: z.number().positive().max(50_000),
  currency: z.enum(['USD', 'PEN', 'COP', 'MXN']),
  /** HMAC-SHA256 (base64url) del mensaje canónico con la clave del dispositivo protegida por biometría. */
  signature: z
    .string()
    .regex(/^[A-Za-z0-9_-]{43}$/)
    .optional(),
});
type StepUpDto = z.infer<typeof StepUpSchema>;

/**
 * Puente de identidad entre la app nativa y los micro frontends web.
 *
 * - handoff: token de un solo uso (60 s) que la app envía por POST al
 *   micro frontend; su BFF lo canjea por una cookie de sesión propia. La
 *   sesión principal (access/refresh) NUNCA se comparte con el WebView.
 * - step-up: verifica la firma HMAC hecha con la clave del dispositivo (que el
 *   SO solo libera tras biometría) y emite un token ligado a una transacción
 *   concreta (hash + monto), válido 120 s y de un solo uso.
 */
@Controller('v1/microfrontends/recaudos')
@Throttle({ default: { limit: 10, ttl: 60_000 } })
export class MicrofrontendsController {
  constructor(
    @Inject(ENV) private readonly env: Env,
    private readonly tokens: TokenService,
    private readonly deviceKeys: DeviceKeysStore,
  ) {}

  @Post('handoff')
  @HttpCode(200)
  async handoff(@CurrentUser() user: AccessClaims) {
    const { token, expiresIn } = await this.tokens.sign(
      { sub: user.sub, sid: user.sid, did: user.did, scope: 'recaudos' },
      { audience: this.env.RECAUDOS_AUDIENCE, ttlSeconds: 60, type: HANDOFF_TYPE },
    );
    return { handoffToken: token, expiresIn };
  }

  @Post('step-up')
  @HttpCode(200)
  async stepUp(@CurrentUser() user: AccessClaims, @Body({ schema: StepUpSchema }) dto: StepUpDto) {
    const signed = this.deviceKeys.authorize(
      {
        customerId: user.sub,
        deviceId: user.did,
        operationId: dto.intentHash,
        amount: dto.amount,
        currency: dto.currency,
        signature: dto.signature,
      },
      requiresDeviceSignature(this.env),
    );
    const { token, expiresIn } = await this.tokens.sign(
      {
        sub: user.sub,
        sid: user.sid,
        txn: dto.intentHash,
        amt: dto.amount,
        cur: dto.currency,
        // amr (RFC 8176): 'hwk' = prueba con clave ligada al hardware/biometría del dispositivo
        amr: signed ? ['pwd', 'otp', 'hwk', 'bio'] : ['pwd', 'otp'],
      },
      { audience: this.env.RECAUDOS_AUDIENCE, ttlSeconds: 120, type: STEP_UP_TYPE },
    );
    return { stepUpToken: token, expiresIn };
  }
}
