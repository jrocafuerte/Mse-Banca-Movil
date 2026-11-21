import { randomBytes, scrypt as scryptCb, timingSafeEqual } from 'node:crypto';

const N = 2 ** 15;
const OPTS = { N, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };

function scrypt(pwd: string, salt: Buffer, keylen: number): Promise<Buffer> {
  return new Promise((resolve, reject) =>
    scryptCb(pwd, salt, keylen, OPTS, (err, key) => (err ? reject(err) : resolve(key))),
  );
}

export async function hashPassword(password: string): Promise<string> {
  const salt = randomBytes(16);
  const hash = await scrypt(password, salt, 32);
  return `scrypt$${N}$${salt.toString('base64')}$${hash.toString('base64')}`;
}

/** Comparación en tiempo constante (evita timing attacks). */
export async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const [alg, , saltB64, hashB64] = stored.split('$');
  if (alg !== 'scrypt' || !saltB64 || !hashB64) return false;
  const expected = Buffer.from(hashB64, 'base64');
  const actual = await scrypt(password, Buffer.from(saltB64, 'base64'), expected.length);
  return timingSafeEqual(expected, actual);
}
