import { type MiddlewareConsumer, Module, type NestModule } from '@nestjs/common';
import { APP_FILTER, APP_GUARD } from '@nestjs/core';
import { ThrottlerGuard, ThrottlerModule } from '@nestjs/throttler';
import { AllExceptionsFilter } from './common/http/all-exceptions.filter.js';
import { RequestIdMiddleware } from './common/http/request-id.middleware.js';
import { AuthGuard } from './common/security/auth.guard.js';
import { CoreModule } from './core.module.js';
import { AuthModule } from './modules/auth/auth.module.js';
import { CardPaymentsController } from './modules/card-payments/card-payments.controller.js';
import { DevicesController } from './modules/devices/devices.controller.js';
import { DeviceKeysStore } from './modules/devices/device-keys.store.js';
import { HealthController } from './modules/health/health.controller.js';
import { MicrofrontendsController } from './modules/microfrontends/microfrontends.controller.js';
import { PositionController } from './modules/position/position.controller.js';
import { TransfersController } from './modules/transfers/transfers.controller.js';
import { TransfersService } from './modules/transfers/transfers.service.js';

@Module({
  imports: [
    CoreModule,
    // Rate limiting global (OWASP API4). Endpoints sensibles definen límites más estrictos.
    ThrottlerModule.forRoot([{ ttl: 60_000, limit: 120 }]),
    AuthModule,
  ],
  controllers: [
    HealthController,
    PositionController,
    TransfersController,
    CardPaymentsController,
    MicrofrontendsController,
    DevicesController,
  ],
  providers: [
    TransfersService,
    DeviceKeysStore,
    { provide: APP_GUARD, useClass: ThrottlerGuard },
    { provide: APP_GUARD, useClass: AuthGuard }, // deny-by-default
    { provide: APP_FILTER, useClass: AllExceptionsFilter },
  ],
})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer): void {
    consumer.apply(RequestIdMiddleware).forRoutes('*path');
  }
}
