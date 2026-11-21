import { maskAccount, maskDocument, maskPan } from '../../common/security/mask.js';
import { hashPassword, verifyPassword } from '../../core-banking/password.js';
import type { Env } from '../../config/env.js';
import { OtpService } from './otp.service.js';
import { SessionStore } from './session.store.js';

describe('SessionStore', () => {
  it('rota el refresh token y revoca ante reutilización', () => {
    const store = new SessionStore();
    const { sid, refreshToken } = store.create('cus-1', 'device-1', 600);
    const rotated = store.rotate(refreshToken, 'device-1', 600);
    expect(rotated?.refreshToken).not.toBe(refreshToken);
    expect(store.rotate(refreshToken, 'device-1', 600)).toBeUndefined();
    expect(store.isActive(sid)).toBe(false);
  });

  it('rechaza refresh desde otro dispositivo', () => {
    const store = new SessionStore();
    const { refreshToken } = store.create('cus-1', 'device-1', 600);
    expect(store.rotate(refreshToken, 'device-2', 600)).toBeUndefined();
  });
});

describe('OtpService', () => {
  const otp = new OtpService({ NODE_ENV: 'test' } as Env);

  it('el OTP queda ligado al contexto de la operación', () => {
    const { challengeId } = otp.issue('cus-1', 'transfer', { amount: 10 });
    expect(otp.verify(challengeId, '123456', 'transfer', { amount: 9999 })).toBeUndefined();
  });

  it('se consume tras un uso exitoso', () => {
    const { challengeId } = otp.issue('cus-1', 'login');
    expect(otp.verify(challengeId, '123456', 'login')).toBe('cus-1');
    expect(otp.verify(challengeId, '123456', 'login')).toBeUndefined();
  });

  it('se invalida tras 3 intentos fallidos', () => {
    const { challengeId } = otp.issue('cus-1', 'login');
    ['000000', '111111', '222222'].forEach((c) => otp.verify(challengeId, c, 'login'));
    expect(otp.verify(challengeId, '123456', 'login')).toBeUndefined();
  });
});

describe('password & masking', () => {
  it('verifica hashes scrypt', async () => {
    const h = await hashPassword('S3gura!2026');
    expect(await verifyPassword('S3gura!2026', h)).toBe(true);
    expect(await verifyPassword('otra', h)).toBe(false);
  });

  it('enmascara PAN, cuenta y documento', () => {
    expect(maskPan('4111111111111111')).toBe('•••• 1111');
    expect(maskAccount('0011002233445566')).toBe('•••5566');
    expect(maskDocument('12345678')).toBe('12****78');
  });
});
