import { Body, Controller, HttpCode, Param, Post, UseInterceptors } from '@nestjs/common';
import { Throttle } from '@nestjs/throttler';
import { z } from 'zod';
import { IdempotencyInterceptor } from '../../common/idempotency/idempotency.interceptor.js';
import { CurrentUser } from '../../common/security/auth.guard.js';
import type { AccessClaims } from '../../crypto/token.service.js';
import {
  ConfirmTransferSchema,
  PrepareTransferSchema,
  type ConfirmTransferDto,
  type PrepareTransferDto,
} from './transfers.schemas.js';
import { TransfersService } from './transfers.service.js';

@Controller('v1/transfers')
@Throttle({ default: { limit: 20, ttl: 60_000 } })
export class TransfersController {
  constructor(private readonly transfers: TransfersService) {}

  @Post('prepare')
  @HttpCode(200)
  prepare(@CurrentUser() user: AccessClaims, @Body({ schema: PrepareTransferSchema }) dto: PrepareTransferDto) {
    return this.transfers.prepare(user.sub, dto);
  }

  @Post(':id/confirm')
  @HttpCode(200)
  @UseInterceptors(IdempotencyInterceptor)
  confirm(
    @CurrentUser() user: AccessClaims,
    @Param('id', { schema: z.uuid() }) id: string,
    @Body({ schema: ConfirmTransferSchema }) dto: ConfirmTransferDto,
  ) {
    return this.transfers.confirm(user.sub, user.did, id, dto);
  }
}
