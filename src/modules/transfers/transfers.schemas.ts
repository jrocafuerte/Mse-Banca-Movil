import { z } from 'zod';

export const Money = z
  .number()
  .positive()
  .max(50_000)
  .refine((n) => Math.abs(n * 100 - Math.round(n * 100)) < 1e-6, 'Máximo 2 decimales');

export const PrepareTransferSchema = z
  .strictObject({
    type: z.enum(['OWN', 'THIRD_PARTY', 'INTERBANK']),
    fromAccountId: z.string().regex(/^acc-\d{3,6}$/),
    toAccountNumber: z.string().regex(/^\d{10,20}$/),
    bankCode: z
      .string()
      .regex(/^\d{3,4}$/)
      .optional(),
    amount: Money,
    currency: z.enum(['USD', 'PEN', 'COP', 'MXN']),
    description: z
      .string()
      .max(60)
      .regex(/^[\p{L}\p{N} .,\-#]*$/u, 'Caracteres no permitidos')
      .default(''),
  })
  .refine((t) => t.type !== 'INTERBANK' || !!t.bankCode, { message: 'bankCode requerido', path: ['bankCode'] });

export const DeviceSignature = z
  .string()
  .regex(/^[A-Za-z0-9_-]{43}$/)
  .optional();

export const ConfirmTransferSchema = z.strictObject({
  otp: z
    .string()
    .regex(/^\d{6}$/)
    .optional(),
  /** HMAC de "transferId|monto|moneda" con la clave del dispositivo (biometría). */
  signature: DeviceSignature,
});

export type PrepareTransferDto = z.infer<typeof PrepareTransferSchema>;
export type ConfirmTransferDto = z.infer<typeof ConfirmTransferSchema>;
