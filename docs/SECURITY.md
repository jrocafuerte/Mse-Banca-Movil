# Seguridad — mse-banca-movil

Marco general, modelo de amenazas y pipeline: [`spa-banca-movil/docs/SECURITY.md`](https://github.com/jrocafuerte/spa-banca-movil/blob/main/docs/SECURITY.md).

## Controles de este BFF

| Control | Dónde | Prueba |
|---|---|---|
| Deny-by-default (todo privado salvo `@Public()`) | `common/security/auth.guard.ts` | e2e "deniega por defecto" |
| JWT ES256, `typ`/`aud`/`iss`/`exp`, algoritmos fijados | `crypto/token.service.ts` | e2e JWKS / login |
| Device binding (`did` = `X-Device-Id`) | `auth.guard.ts` | e2e "otro dispositivo" |
| MFA obligatorio, OTP ligado al contexto, 3 intentos | `modules/auth/otp.service.ts` | unit OtpService |
| Mensaje genérico + hash señuelo (anti enumeración / timing) | `modules/auth/auth.service.ts` | e2e credenciales inválidas |
| Bloqueo tras 5 fallos + rate limit 5/min | `auth.service.ts`, `@Throttle` | e2e fuerza bruta |
| Refresh rotativo con detección de reutilización | `modules/auth/session.store.ts` | e2e + unit |
| Validación estricta (anti mass-assignment) | Zod `strictObject` + `StandardSchemaValidationPipe` | e2e `role: admin` |
| BOLA | `position.controller.ts`, `transfers.service.ts`, `card-payments.controller.ts` | e2e cuentas ajenas |
| Idempotencia en operaciones monetarias | `common/idempotency` | e2e reintento |
| Montos resueltos en servidor | `card-payments.controller.ts`, `transfers.service.ts` | e2e pago mínimo |
| Firma de dispositivo (HMAC, clave liberada por biometría) | `modules/devices` | e2e step-up / tarjeta |
| Sin PAN completo en respuestas ni logs | `common/security/mask.ts` | e2e posición |
| Errores RFC 9457 sin detalles internos | `common/http/all-exceptions.filter.ts` | — |
| Helmet, HSTS, CSP `default-src 'none'`, `no-store`, body ≤ 16 KB | `main.ts` | e2e headers |

## Producción

- `TOKEN_PRIVATE_KEY_PEM` desde KMS/HSM (el proceso no arranca sin ella). Rotación por `kid`.
- `STEP_UP_REQUIRE_DEVICE_SIGNATURE` es `true` por defecto en producción.
- Sesiones, OTP, idempotencia y claves de dispositivo: Redis/DB cifrados (envelope encryption).
- El OTP fijo `123456` solo existe con `NODE_ENV != production`.
