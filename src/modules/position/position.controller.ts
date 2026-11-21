import { Controller, Get, NotFoundException, Param, Query } from '@nestjs/common';
import { z } from 'zod';
import { CurrentUser } from '../../common/security/auth.guard.js';
import { maskAccount, maskPan } from '../../common/security/mask.js';
import { CoreBankingPort } from '../../core-banking/core-banking.port.js';
import type { AccessClaims } from '../../crypto/token.service.js';

const IdSchema = z.string().regex(/^[a-z]+-[0-9]{3,6}$/);
const LimitSchema = z.coerce.number().int().min(1).max(50).default(20);

/**
 * Posición consolidada: agrega cuentas, tarjetas y préstamos del cliente
 * en una sola llamada optimizada para la pantalla principal (patrón BFF).
 */
@Controller('v1')
export class PositionController {
  constructor(private readonly core: CoreBankingPort) {}

  @Get('position')
  async position(@CurrentUser() user: AccessClaims) {
    const [accounts, cards, loans] = await Promise.all([
      this.core.listAccounts(user.sub),
      this.core.listCards(user.sub),
      this.core.listLoans(user.sub),
    ]);
    const totals = accounts.reduce<Record<string, number>>((acc, a) => {
      acc[a.currency] = Math.round(((acc[a.currency] ?? 0) + a.availableBalance) * 100) / 100;
      return acc;
    }, {});
    return {
      totals,
      accounts: accounts.map((a) => ({
        id: a.id,
        type: a.type,
        currency: a.currency,
        numberMasked: maskAccount(a.number),
        availableBalance: a.availableBalance,
        ledgerBalance: a.ledgerBalance,
      })),
      cards: cards.map((c) => ({
        id: c.id,
        brand: c.brand,
        panMasked: maskPan(c.pan), // el PAN completo nunca sale del BFF
        currency: c.currency,
        creditLimit: c.creditLimit,
        availableCredit: c.availableCredit,
        statementBalance: c.statementBalance,
        minimumPayment: c.minimumPayment,
        dueDate: c.dueDate,
      })),
      loans: loans.map(({ ownerId: _o, ...l }) => l),
    };
  }

  @Get('accounts/:id/movements')
  async movements(
    @CurrentUser() user: AccessClaims,
    @Param('id', { schema: IdSchema }) id: string,
    @Query('limit', { schema: LimitSchema }) limit: number,
  ) {
    // Control de autorización a nivel de objeto (OWASP API1: BOLA).
    const owned = await this.core.listAccounts(user.sub);
    if (!owned.some((a) => a.id === id)) throw new NotFoundException();
    return { items: await this.core.listMovements(id, limit) };
  }
}
