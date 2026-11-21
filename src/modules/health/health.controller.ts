import { Controller, Get } from '@nestjs/common';
import { SkipThrottle } from '@nestjs/throttler';
import { Public } from '../../common/security/auth.guard.js';

@Controller('health')
@SkipThrottle()
export class HealthController {
  @Public()
  @Get()
  health() {
    return { status: 'ok' }; // sin versión ni detalles del stack (information disclosure)
  }
}
