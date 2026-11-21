import { Global, Module } from '@nestjs/common';
import { ENV, loadEnv } from './config/env.js';
import { CoreBankingPort } from './core-banking/core-banking.port.js';
import { InMemoryCoreBanking } from './core-banking/in-memory-core-banking.js';
import { TokenService } from './crypto/token.service.js';

/** Infraestructura compartida (config, criptografía, adaptadores al core). */
@Global()
@Module({
  providers: [
    { provide: ENV, useFactory: () => loadEnv() },
    TokenService,
    // Adaptador del core: se reemplaza por el adaptador HTTP/mTLS en producción.
    { provide: CoreBankingPort, useClass: InMemoryCoreBanking },
  ],
  exports: [ENV, TokenService, CoreBankingPort],
})
export class CoreModule {}
