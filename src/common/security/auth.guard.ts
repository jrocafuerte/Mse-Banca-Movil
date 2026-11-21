import {
  type CanActivate,
  type ExecutionContext,
  Injectable,
  SetMetadata,
  UnauthorizedException,
  createParamDecorator,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import type { Request } from 'express';
import { TokenService, type AccessClaims } from '../../crypto/token.service.js';
import { SessionStore } from '../../modules/auth/session.store.js';

export const ACCESS_AUDIENCE = 'mse-banca-movil';
export const ACCESS_TOKEN_TYPE = 'at+jwt';

const IS_PUBLIC = 'isPublic';
/** Marca un endpoint como público (sin token). Todo lo demás es privado por defecto. */
export const Public = () => SetMetadata(IS_PUBLIC, true);

export interface AuthenticatedRequest extends Request {
  user: AccessClaims;
}

export const CurrentUser = createParamDecorator(
  (_: unknown, ctx: ExecutionContext): AccessClaims => ctx.switchToHttp().getRequest<AuthenticatedRequest>().user,
);

/**
 * Guard global "deny by default": valida firma, issuer, audiencia, tipo,
 * expiración, sesión activa y que el token pertenezca al dispositivo que lo usa.
 */
@Injectable()
export class AuthGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    private readonly tokens: TokenService,
    private readonly sessions: SessionStore,
  ) {}

  async canActivate(ctx: ExecutionContext): Promise<boolean> {
    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC, [ctx.getHandler(), ctx.getClass()]);
    if (isPublic) return true;

    const req = ctx.switchToHttp().getRequest<AuthenticatedRequest>();
    const header = req.headers.authorization ?? '';
    const [scheme, token] = header.split(' ');
    if (scheme !== 'Bearer' || !token) throw new UnauthorizedException();

    const claims = await this.tokens.verify<AccessClaims>(token, ACCESS_AUDIENCE, ACCESS_TOKEN_TYPE);
    if (!this.sessions.isActive(claims.sid)) throw new UnauthorizedException('Sesión revocada');

    const deviceId = req.headers['x-device-id'];
    if (typeof deviceId !== 'string' || deviceId !== claims.did) {
      throw new UnauthorizedException('Dispositivo no coincide');
    }
    req.user = claims;
    return true;
  }
}
