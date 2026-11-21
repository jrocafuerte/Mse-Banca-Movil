import { z } from 'zod';

/**
 * Configuración validada al arranque (fail-fast). Ningún secreto tiene valor
 * por defecto en producción: si falta, el proceso no inicia.
 */
const EnvSchema = z
  .object({
    NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
    PORT: z.coerce.number().int().positive().default(3000),
    /** Emisor (iss) de los tokens que firma este BFF. */
    TOKEN_ISSUER: z.string().url().default('https://api.banco.example/mse-banca-movil'),
    /** Clave privada ES256 en formato PKCS#8 PEM (inyectada desde un vault / KMS). */
    TOKEN_PRIVATE_KEY_PEM: z.string().optional(),
    ACCESS_TOKEN_TTL_SECONDS: z.coerce.number().int().min(60).max(900).default(300),
    REFRESH_TOKEN_TTL_SECONDS: z.coerce.number().int().min(600).max(86_400).default(1_800),
    /** Audiencia de los micro frontends con los que se comparte sesión. */
    RECAUDOS_AUDIENCE: z.string().default('mse-recaudos'),
    /** Monto a partir del cual una transferencia requiere OTP (step-up). */
    STEP_UP_THRESHOLD: z.coerce.number().positive().default(500),
    CORS_ALLOWED_ORIGINS: z.string().default(''),
    /** Exigir firma del dispositivo (clave protegida por biometría) en el step-up. */
    STEP_UP_REQUIRE_DEVICE_SIGNATURE: z
      .enum(['true', 'false'])
      .optional()
      .transform((v) => (v === undefined ? undefined : v === 'true')),
  })
  .superRefine((env, ctx) => {
    if (env.NODE_ENV === 'production' && !env.TOKEN_PRIVATE_KEY_PEM) {
      ctx.addIssue({
        code: 'custom',
        path: ['TOKEN_PRIVATE_KEY_PEM'],
        message: 'Requerido en producción',
      });
    }
  });

export type Env = z.infer<typeof EnvSchema>;

/** Por defecto la firma de dispositivo es obligatoria en producción. */
export const requiresDeviceSignature = (env: Env): boolean =>
  env.STEP_UP_REQUIRE_DEVICE_SIGNATURE ?? env.NODE_ENV === 'production';

export function loadEnv(source: NodeJS.ProcessEnv = process.env): Env {
  const parsed = EnvSchema.safeParse(source);
  if (!parsed.success) {
    // Solo se listan las claves inválidas, nunca sus valores.
    const keys = parsed.error.issues.map((i) => i.path.join('.')).join(', ');
    throw new Error(`Configuración inválida: ${keys}`);
  }
  return parsed.data;
}

export const ENV = Symbol('ENV');
