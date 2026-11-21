import { Body, Controller, Get, HttpCode, Post } from '@nestjs/common';
import { Throttle } from '@nestjs/throttler';
import type { AccessClaims } from '../../crypto/token.service.js';
import { TokenService } from '../../crypto/token.service.js';
import { CurrentUser, Public } from '../../common/security/auth.guard.js';
import {
  LoginSchema,
  RefreshSchema,
  VerifyMfaSchema,
  type LoginDto,
  type RefreshDto,
  type VerifyMfaDto,
} from './auth.schemas.js';
import { AuthService } from './auth.service.js';

@Controller()
export class AuthController {
  constructor(
    private readonly auth: AuthService,
    private readonly tokens: TokenService,
  ) {}

  /** Clave pública para que otros BFF (p. ej. mse-recaudos) validen tokens de handoff/step-up. */
  @Public()
  @Get('.well-known/jwks.json')
  jwks() {
    return this.tokens.jwks();
  }

  @Public()
  @Throttle({ default: { limit: 5, ttl: 60_000 } })
  @Post('v1/auth/login')
  @HttpCode(200)
  login(@Body({ schema: LoginSchema }) dto: LoginDto) {
    return this.auth.login(dto);
  }

  @Public()
  @Throttle({ default: { limit: 5, ttl: 60_000 } })
  @Post('v1/auth/mfa/verify')
  @HttpCode(200)
  verify(@Body({ schema: VerifyMfaSchema }) dto: VerifyMfaDto) {
    return this.auth.verifyMfa(dto);
  }

  @Public()
  @Throttle({ default: { limit: 10, ttl: 60_000 } })
  @Post('v1/auth/refresh')
  @HttpCode(200)
  refresh(@Body({ schema: RefreshSchema }) dto: RefreshDto) {
    return this.auth.refresh(dto);
  }

  @Post('v1/auth/logout')
  @HttpCode(204)
  logout(@CurrentUser() user: AccessClaims): void {
    this.auth.logout(user.sid);
  }
}
