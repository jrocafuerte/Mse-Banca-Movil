# mse-banca-movil

**BFF** (Backend for Frontend) de la app nativa de Banca Móvil — NestJS 12 (ESM), arquitectura hexagonal.

Arquitectura completa de la solución: [`spa-banca-movil/docs/ARCHITECTURE.md`](https://github.com/jrocafuerte/spa-banca-movil/blob/main/docs/ARCHITECTURE.md) · Seguridad: [`docs/SECURITY.md`](docs/SECURITY.md) · Contrato: [`openapi.yaml`](openapi.yaml)

## Estructura

```
src/
  main.ts                 # Helmet, no-store, body limit, validación global (Zod / Standard Schema)
  core.module.ts          # Config validada, TokenService (ES256/JWKS), puerto del core
  common/                 # AuthGuard deny-by-default, filtro RFC 9457, request-id, idempotencia, masking
  core-banking/           # Puerto CoreBankingPort + adaptador en memoria (dev/test)
  modules/
    auth/                 # login → OTP → tokens; refresh rotativo; logout
    position/             # posición consolidada + movimientos (BOLA)
    transfers/            # prepare/confirm, OTP por umbral, firma de dispositivo
    card-payments/        # pago mínimo/total/otro, monto resuelto en servidor
    devices/              # registro de clave de firma (≤ 5 min tras MFA) y verificación HMAC
    microfrontends/       # handoff y step-up para spa-recaudos / mse-recaudos
```

## Endpoints

| Método | Ruta | Auth |
|---|---|---|
| GET | `/health`, `/.well-known/jwks.json` | pública |
| POST | `/v1/auth/login`, `/v1/auth/mfa/verify`, `/v1/auth/refresh` | pública (rate limited) |
| POST | `/v1/auth/logout` | Bearer |
| GET | `/v1/position`, `/v1/accounts/:id/movements` | Bearer |
| POST | `/v1/transfers/prepare`, `/v1/transfers/:id/confirm`* | Bearer |
| POST | `/v1/card-payments`* | Bearer |
| POST | `/v1/devices/signing-key` | Bearer (sesión recién autenticada) |
| POST | `/v1/microfrontends/recaudos/handoff`, `/step-up` | Bearer |

\* requieren `Idempotency-Key`.

## Desarrollo

```bash
cp .env.example .env
npm ci
npm run start:dev           # http://localhost:3000
npm test                    # unitarios (Vitest)
npm run test:e2e            # e2e de contrato y controles de seguridad
npm run lint && npm run build
```

Usuario demo: documento `12345678`, clave `Demo#2026`, OTP `123456` (solo fuera de producción).
