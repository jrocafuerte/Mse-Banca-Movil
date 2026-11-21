import { StandardSchemaValidationPipe } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import type { NestExpressApplication } from '@nestjs/platform-express';
import helmet from 'helmet';
import { AppModule } from './app.module.js';

export async function configureApp(app: NestExpressApplication): Promise<void> {
  app.disable('x-powered-by');
  app.set('trust proxy', 1); // detrás del API Gateway / WAF
  app.use(
    helmet({
      contentSecurityPolicy: { directives: { defaultSrc: ["'none'"], frameAncestors: ["'none'"] } },
      strictTransportSecurity: { maxAge: 31_536_000, includeSubDomains: true, preload: true },
      referrerPolicy: { policy: 'no-referrer' },
    }),
  );
  app.use((_req: unknown, res: { setHeader(k: string, v: string): void }, next: () => void) => {
    res.setHeader('Cache-Control', 'no-store'); // respuestas con datos financieros nunca se cachean
    next();
  });
  app.useBodyParser('json', { limit: '16kb' });
  // Validación estricta con Zod (Standard Schema) en todos los @Body/@Param/@Query con schema.
  app.useGlobalPipes(new StandardSchemaValidationPipe());
  // La app móvil no usa CORS; solo se habilitan orígenes explícitos (herramientas internas).
  const origins = (process.env.CORS_ALLOWED_ORIGINS ?? '').split(',').filter(Boolean);
  if (origins.length) app.enableCors({ origin: origins, credentials: false });
  app.enableShutdownHooks();
}

async function bootstrap(): Promise<void> {
  const app = await NestFactory.create<NestExpressApplication>(AppModule, { bodyParser: false });
  await configureApp(app);
  await app.listen(process.env.PORT ?? 3000);
}

if (process.env.NODE_ENV !== 'test') await bootstrap();
