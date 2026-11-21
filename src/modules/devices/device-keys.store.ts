import { ForbiddenException, Injectable } from '@nestjs/common';
import { createHmac, timingSafeEqual } from 'node:crypto';

/** Mensaje canónico firmado por la app (debe ser idéntico a `transactionMessage` en spa-banca-movil). */
export const transactionMessage = (intentHash: string, amount: number, currency: string) =>
  `${intentHash}|${amount.toFixed(2)}|${currency}`;

/**
 * Claves de firma de transacciones por (cliente, dispositivo).
 * Producción: cifradas con una KEK del HSM/KMS (envelope encryption) en base
 * de datos; nunca en logs. Evolución: claves asimétricas (solo pública en servidor).
 */
@Injectable()
export class DeviceKeysStore {
  private readonly keys = new Map<string, Buffer>();

  register(customerId: string, deviceId: string, keyB64Url: string): void {
    this.keys.set(`${customerId}:${deviceId}`, Buffer.from(keyB64Url, 'base64url'));
  }

  has(customerId: string, deviceId: string): boolean {
    return this.keys.has(`${customerId}:${deviceId}`);
  }

  revoke(customerId: string, deviceId: string): void {
    this.keys.delete(`${customerId}:${deviceId}`);
  }

  verify(customerId: string, deviceId: string, message: string, signatureB64Url: string): boolean {
    const key = this.keys.get(`${customerId}:${deviceId}`);
    if (!key) return false;
    const expected = createHmac('sha256', key).update(message).digest();
    const given = Buffer.from(signatureB64Url, 'base64url');
    return given.length === expected.length && timingSafeEqual(given, expected);
  }

  /**
   * Autoriza una operación monetaria con la firma del dispositivo.
   * Lanza 403 si la firma es inválida, o si falta y la política la exige.
   * Devuelve true si la operación quedó firmada criptográficamente.
   */
  authorize(
    p: {
      customerId: string;
      deviceId: string;
      operationId: string;
      amount: number;
      currency: string;
      signature?: string;
    },
    required: boolean,
  ): boolean {
    if (!p.signature) {
      if (required) throw new ForbiddenException('Se requiere confirmación biométrica del dispositivo');
      return false;
    }
    const message = transactionMessage(p.operationId, p.amount, p.currency);
    if (!this.verify(p.customerId, p.deviceId, message, p.signature)) {
      throw new ForbiddenException('Firma de dispositivo inválida');
    }
    return true;
  }
}
