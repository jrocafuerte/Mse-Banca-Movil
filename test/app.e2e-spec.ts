import { Test } from '@nestjs/testing';
import type { NestExpressApplication } from '@nestjs/platform-express';
import { createHmac, randomBytes, randomUUID } from 'node:crypto';
import { decodeJwt } from 'jose';
import request from 'supertest';
import { AppModule } from '../src/app.module.js';
import { configureApp } from '../src/main.js';

const DEVICE = 'device-0123456789abcdef';

describe('mse-banca-movil (e2e)', () => {
  let app: NestExpressApplication;
  let http: ReturnType<NestExpressApplication['getHttpServer']>;
  let session: { accessToken: string; refreshToken: string };

  async function login() {
    const l = await request(http)
      .post('/v1/auth/login')
      .send({ documentId: '12345678', password: 'Demo#2026', deviceId: DEVICE })
      .expect(200);
    const v = await request(http)
      .post('/v1/auth/mfa/verify')
      .send({ challengeId: l.body.challengeId, otp: '123456', deviceId: DEVICE })
      .expect(200);
    return v.body as { accessToken: string; refreshToken: string };
  }
  const auth = (t: string) => ({ Authorization: `Bearer ${t}`, 'X-Device-Id': DEVICE });

  beforeAll(async () => {
    const mod = await Test.createTestingModule({ imports: [AppModule] }).compile();
    app = mod.createNestApplication<NestExpressApplication>({ bodyParser: false });
    await configureApp(app);
    await app.init();
    http = app.getHttpServer();
    session = await login();
  });
  afterAll(() => app.close());

  it('expone JWKS sin clave privada', async () => {
    const res = await request(http).get('/.well-known/jwks.json').expect(200);
    expect(res.body.keys[0]).toMatchObject({ kty: 'EC', alg: 'ES256' });
    expect(res.body.keys[0].d).toBeUndefined();
  });

  it('deniega por defecto sin token y aplica headers de seguridad', async () => {
    const res = await request(http).get('/v1/position').expect(401);
    expect(res.headers['cache-control']).toBe('no-store');
    expect(res.headers['x-powered-by']).toBeUndefined();
    expect(res.headers['strict-transport-security']).toContain('max-age');
  });

  it('rechaza credenciales inválidas con mensaje genérico', async () => {
    const res = await request(http)
      .post('/v1/auth/login')
      .send({ documentId: '99999999', password: 'whatever123', deviceId: DEVICE })
      .expect(401);
    expect(res.body.detail).toBe('Credenciales inválidas');
  });

  it('rechaza campos no esperados (mass assignment)', async () => {
    await request(http)
      .post('/v1/auth/login')
      .send({ documentId: '12345678', password: 'Demo#2026', deviceId: DEVICE, role: 'admin' })
      .expect(400);
  });

  it('login + MFA + posición consolidada enmascarada', async () => {
    const { accessToken } = session;
    const res = await request(http).get('/v1/position').set(auth(accessToken)).expect(200);
    expect(res.body.accounts).toHaveLength(2);
    expect(res.body.cards[0].panMasked).toBe('•••• 1111');
    expect(JSON.stringify(res.body)).not.toContain('4111111111111111');
  });

  it('impide usar el token desde otro dispositivo', async () => {
    const { accessToken } = session;
    await request(http)
      .get('/v1/position')
      .set({ Authorization: `Bearer ${accessToken}`, 'X-Device-Id': 'other-device-000000000' })
      .expect(401);
  });

  it('BOLA: no permite ver movimientos de cuentas ajenas', async () => {
    const { accessToken } = session;
    await request(http).get('/v1/accounts/acc-900/movements').set(auth(accessToken)).expect(404);
    await request(http).get('/v1/accounts/acc-001/movements').set(auth(accessToken)).expect(200);
  });

  it('transferencia a tercero con OTP e idempotencia', async () => {
    const { accessToken } = session;
    const prep = await request(http)
      .post('/v1/transfers/prepare')
      .set(auth(accessToken))
      .send({
        type: 'THIRD_PARTY',
        fromAccountId: 'acc-001',
        toAccountNumber: '0011007777777777',
        amount: 600,
        currency: 'USD',
        description: 'Alquiler',
      })
      .expect(200);
    expect(prep.body.otpRequired).toBe(true);

    const key = randomUUID();
    await request(http)
      .post(`/v1/transfers/${prep.body.transferId}/confirm`)
      .set(auth(accessToken))
      .send({ otp: '123456' })
      .expect(400);
    const first = await request(http)
      .post(`/v1/transfers/${prep.body.transferId}/confirm`)
      .set({ ...auth(accessToken), 'Idempotency-Key': key })
      .send({ otp: '123456' })
      .expect(200);
    const retry = await request(http)
      .post(`/v1/transfers/${prep.body.transferId}/confirm`)
      .set({ ...auth(accessToken), 'Idempotency-Key': key })
      .send({ otp: '123456' })
      .expect(200);
    expect(retry.body.operationId).toBe(first.body.operationId);
  });

  it('pago de tarjeta con monto mínimo resuelto en servidor', async () => {
    const { accessToken } = session;
    const res = await request(http)
      .post('/v1/card-payments')
      .set({ ...auth(accessToken), 'Idempotency-Key': randomUUID() })
      .send({ cardId: 'card-001', fromAccountId: 'acc-002', amountType: 'MINIMUM' })
      .expect(201);
    expect(res.body.amount).toBe(45);
  });

  it('refresh rota el token y detecta reutilización', async () => {
    const { refreshToken } = await login();
    const r1 = await request(http).post('/v1/auth/refresh').send({ refreshToken, deviceId: DEVICE }).expect(200);
    await request(http).post('/v1/auth/refresh').send({ refreshToken, deviceId: DEVICE }).expect(401);
    // Tras la reutilización la sesión completa queda revocada
    await request(http)
      .post('/v1/auth/refresh')
      .send({ refreshToken: r1.body.refreshToken, deviceId: DEVICE })
      .expect(401);
  });

  it('emite handoff token para el micro frontend de recaudos', async () => {
    const { accessToken } = session;
    const res = await request(http).post('/v1/microfrontends/recaudos/handoff').set(auth(accessToken)).expect(200);
    expect(res.body.expiresIn).toBe(60);
  });

  it('step-up ligado a la firma del dispositivo (clave protegida por biometría)', async () => {
    const { accessToken } = session;
    const key = randomBytes(32);
    await request(http)
      .post('/v1/devices/signing-key')
      .set(auth(accessToken))
      .send({ key: key.toString('base64url') })
      .expect(204);

    const intentHash = 'b'.repeat(64);
    const sign = (amount: number) =>
      createHmac('sha256', key)
        .update(`${intentHash}|${amount.toFixed(2)}|USD`)
        .digest('base64url');

    const ok = await request(http)
      .post('/v1/microfrontends/recaudos/step-up')
      .set(auth(accessToken))
      .send({ intentHash, amount: 76, currency: 'USD', signature: sign(76) })
      .expect(200);
    expect(decodeJwt(ok.body.stepUpToken)).toMatchObject({
      txn: intentHash,
      amt: 76,
      amr: expect.arrayContaining(['hwk']),
    });

    // Firma hecha para otro monto ⇒ rechazada
    await request(http)
      .post('/v1/microfrontends/recaudos/step-up')
      .set(auth(accessToken))
      .send({ intentHash, amount: 76, currency: 'USD', signature: sign(1) })
      .expect(403);
  });

  it('pago de tarjeta con firma de dispositivo inválida es rechazado', async () => {
    await request(http)
      .post('/v1/card-payments')
      .set({ ...auth(session.accessToken), 'Idempotency-Key': randomUUID() })
      .send({
        cardId: 'card-001',
        fromAccountId: 'acc-002',
        amountType: 'OTHER',
        amount: 10,
        signature: 'A'.repeat(43),
      })
      .expect(403);
  });

  it('limita intentos de login por minuto (fuerza bruta)', async () => {
    let last = 0;
    for (let i = 0; i < 3; i++) {
      last = (
        await request(http)
          .post('/v1/auth/login')
          .send({ documentId: '12345678', password: 'bad-password', deviceId: DEVICE })
      ).status;
    }
    expect(last).toBe(429);
  });
});
