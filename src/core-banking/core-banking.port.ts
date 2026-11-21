/**
 * Puerto (arquitectura hexagonal) hacia los sistemas core del banco.
 * El BFF no contiene reglas de negocio contables: orquesta y adapta.
 * Implementaciones: InMemoryCoreBanking (dev/test) y un adaptador HTTP/mTLS
 * hacia el ESB / API Gateway interno en producción.
 */
export interface Customer {
  id: string;
  documentId: string;
  fullName: string;
  passwordHash: string; // scrypt$N$salt$hash (en prod la credencial vive en el IdP)
  phoneMasked: string;
}

export type Currency = 'USD' | 'PEN' | 'COP' | 'MXN';

export interface Account {
  id: string;
  number: string;
  type: 'SAVINGS' | 'CHECKING';
  currency: Currency;
  availableBalance: number;
  ledgerBalance: number;
  ownerId: string;
}

export interface Card {
  id: string;
  pan: string;
  brand: 'VISA' | 'MASTERCARD';
  type: 'CREDIT';
  currency: Currency;
  creditLimit: number;
  availableCredit: number;
  statementBalance: number;
  minimumPayment: number;
  dueDate: string;
  ownerId: string;
}

export interface Loan {
  id: string;
  product: string;
  currency: Currency;
  outstandingPrincipal: number;
  nextInstallment: number;
  nextDueDate: string;
  ownerId: string;
}

export interface Movement {
  id: string;
  accountId: string;
  date: string;
  description: string;
  amount: number;
  currency: Currency;
}

export interface LedgerResult {
  operationId: string;
  executedAt: string;
}

export interface DebitCreditParams {
  fromAccountId: string;
  toAccountId?: string;
  toExternal?: { bankCode: string; account: string };
  amount: number;
  currency: Currency;
  description: string;
}

export abstract class CoreBankingPort {
  abstract findCustomerByDocument(documentId: string): Promise<Customer | undefined>;
  abstract findCustomer(id: string): Promise<Customer | undefined>;
  abstract listAccounts(customerId: string): Promise<Account[]>;
  abstract listCards(customerId: string): Promise<Card[]>;
  abstract listLoans(customerId: string): Promise<Loan[]>;
  abstract listMovements(accountId: string, limit: number): Promise<Movement[]>;
  abstract findAccountByNumber(number: string): Promise<Account | undefined>;
  abstract debitCredit(params: DebitCreditParams): Promise<LedgerResult>;
  abstract payCard(params: { fromAccountId: string; cardId: string; amount: number }): Promise<LedgerResult>;
}
