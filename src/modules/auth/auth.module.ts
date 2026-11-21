import { Global, Module } from '@nestjs/common';
import { AuthController } from './auth.controller.js';
import { AuthService } from './auth.service.js';
import { OtpService } from './otp.service.js';
import { SessionStore } from './session.store.js';

@Global()
@Module({
  controllers: [AuthController],
  providers: [AuthService, OtpService, SessionStore],
  exports: [OtpService, SessionStore],
})
export class AuthModule {}
