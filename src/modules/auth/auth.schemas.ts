import { z } from 'zod';

export const DeviceId = z.string().regex(/^[A-Za-z0-9-]{16,64}$/, 'deviceId inválido');

export const LoginSchema = z.strictObject({
  documentId: z.string().regex(/^\d{8,12}$/),
  password: z.string().min(8).max(64),
  deviceId: DeviceId,
});

export const VerifyMfaSchema = z.strictObject({
  challengeId: z.uuid(),
  otp: z.string().regex(/^\d{6}$/),
  deviceId: DeviceId,
});

export const RefreshSchema = z.strictObject({
  refreshToken: z.string().min(40).max(200),
  deviceId: DeviceId,
});

export type LoginDto = z.infer<typeof LoginSchema>;
export type VerifyMfaDto = z.infer<typeof VerifyMfaSchema>;
export type RefreshDto = z.infer<typeof RefreshSchema>;
