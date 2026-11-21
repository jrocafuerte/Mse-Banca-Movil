/** Enmascara datos sensibles antes de exponerlos o registrarlos (PCI DSS 3.4). */
export const maskPan = (pan: string): string => `•••• ${pan.slice(-4)}`;
export const maskAccount = (acc: string): string => `•••${acc.slice(-4)}`;
export const maskDocument = (doc: string): string =>
  `${doc.slice(0, 2)}${'*'.repeat(Math.max(doc.length - 4, 0))}${doc.slice(-2)}`;
