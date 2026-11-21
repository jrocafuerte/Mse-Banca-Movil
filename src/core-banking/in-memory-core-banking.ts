import { Injectable, type OnModuleInit, UnprocessableEntityException } from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import {
  type Account,
  type Card,
  CoreBankingPort,
  type Customer,
  type DebitCreditParams,
  type LedgerResult,
  type Loan,
  type Movement,
} from './core-banking.port.js';
import { hashPassword } from './password.js';

/**
 * Adaptador en memoria SOLO para desarrollo y pruebas. Datos ficticios.
 * Usuario demo: documento 12345678 / clave Demo#2026
 */
@Injectable()
export class InMemoryCoreBanking extends CoreBankingPort implements OnModuleInit {
  private customers: Customer[] = [];
  private accounts: Account[] = [];
  private cards: Card[] = [];
  private loans: Loan[] = [];
  private movements: Movement[] = [];

  async onModuleInit(): Promise<void> {
    const id = 'cus-0001';
    this.customers = [
      {
        id,
        documentId: '12345678',
        fullName: 'Ana Torres',
        passwordHash: await hashPassword('Demo#2026'),
        phoneMasked: '*** *** 789',
      },
    ];
    this.accounts = [
      {
        id: 'acc-001',
        number: '0011002233445566',
        type: 'SAVINGS',
        currency: 'USD',
        availableBalance: 5420.35,
        ledgerBalance: 5420.35,
        ownerId: id,
      },
      {
        id: 'acc-002',
        number: '0011009988776655',
        type: 'CHECKING',
        currency: 'USD',
        availableBalance: 1250,
        ledgerBalance: 1300,
        ownerId: id,
      },
      {
        id: 'acc-900',
        number: '0011007777777777',
        type: 'SAVINGS',
        currency: 'USD',
        availableBalance: 100,
        ledgerBalance: 100,
        ownerId: 'cus-0002',
      },
    ];
    this.cards = [
      {
        id: 'card-001',
        pan: '4111111111111111',
        brand: 'VISA',
        type: 'CREDIT',
        currency: 'USD',
        creditLimit: 3000,
        availableCredit: 2150.4,
        statementBalance: 849.6,
        minimumPayment: 45,
        dueDate: '2026-12-05',
        ownerId: id,
      },
    ];
    this.loans = [
      {
        id: 'loan-001',
        product: 'Préstamo personal',
        currency: 'USD',
        outstandingPrincipal: 7800,
        nextInstallment: 310.5,
        nextDueDate: '2026-12-15',
        ownerId: id,
      },
    ];
    this.movements = Array.from({ length: 8 }, (_, i) => ({
      id: `mov-${i}`,
      accountId: i % 2 ? 'acc-002' : 'acc-001',
      date: new Date(Date.UTC(2026, 10, 20 - i)).toISOString(),
      description: i % 3 ? 'Compra POS' : 'Depósito nómina',
      amount: i % 3 ? -(20 + i * 3.5) : 1500,
      currency: 'USD' as const,
    }));
  }

  async findCustomerByDocument(documentId: string) {
    return this.customers.find((c) => c.documentId === documentId);
  }
  async findCustomer(id: string) {
    return this.customers.find((c) => c.id === id);
  }
  async listAccounts(customerId: string) {
    return this.accounts.filter((a) => a.ownerId === customerId);
  }
  async listCards(customerId: string) {
    return this.cards.filter((c) => c.ownerId === customerId);
  }
  async listLoans(customerId: string) {
    return this.loans.filter((l) => l.ownerId === customerId);
  }
  async listMovements(accountId: string, limit: number) {
    return this.movements.filter((m) => m.accountId === accountId).slice(0, limit);
  }
  async findAccountByNumber(number: string) {
    return this.accounts.find((a) => a.number === number);
  }

  async debitCredit(p: DebitCreditParams): Promise<LedgerResult> {
    const from = this.accounts.find((a) => a.id === p.fromAccountId);
    if (!from || from.availableBalance < p.amount) throw new UnprocessableEntityException('Fondos insuficientes');
    from.availableBalance = round(from.availableBalance - p.amount);
    from.ledgerBalance = round(from.ledgerBalance - p.amount);
    if (p.toAccountId) {
      const to = this.accounts.find((a) => a.id === p.toAccountId);
      if (to) {
        to.availableBalance = round(to.availableBalance + p.amount);
        to.ledgerBalance = round(to.ledgerBalance + p.amount);
      }
    }
    return { operationId: randomUUID(), executedAt: new Date().toISOString() };
  }

  async payCard(p: { fromAccountId: string; cardId: string; amount: number }): Promise<LedgerResult> {
    const card = this.cards.find((c) => c.id === p.cardId);
    if (!card) throw new UnprocessableEntityException('Tarjeta no encontrada');
    const res = await this.debitCredit({
      fromAccountId: p.fromAccountId,
      amount: p.amount,
      currency: card.currency,
      description: 'Pago TC',
    });
    card.statementBalance = Math.max(0, round(card.statementBalance - p.amount));
    card.availableCredit = Math.min(card.creditLimit, round(card.availableCredit + p.amount));
    card.minimumPayment = Math.max(0, round(card.minimumPayment - p.amount));
    return res;
  }
}

/** Montos con 2 decimales. En producción usar enteros (céntimos) o un tipo decimal. */
const round = (n: number) => Math.round(n * 100) / 100;
