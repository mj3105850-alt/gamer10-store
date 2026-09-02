import crypto from 'crypto';
import jwt from 'jsonwebtoken';

const SECRET_KEY = process.env.SECRET_KEY || 'dev-secret-key';
const JWT_SECRET = process.env.JWT_SECRET || 'dev-jwt-secret';

// ========== HASH DE SENHAS ==========
export function hashPassword(password: string): string {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto
    .pbkdf2Sync(password, salt, 1000, 64, 'sha512')
    .toString('hex');
  return `${salt}:${hash}`;
}

export function verifyPassword(password: string, hash: string): boolean {
  const [salt, storedHash] = hash.split(':');
  const computedHash = crypto
    .pbkdf2Sync(password, salt, 1000, 64, 'sha512')
    .toString('hex');
  return computedHash === storedHash;
}

// ========== TOKENS JWT ==========
export function generateJWT(payload: any, expiresIn: string = '24h'): string {
  return jwt.sign(payload, JWT_SECRET, { expiresIn });
}

export function verifyJWT(token: string): any {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch (error) {
    return null;
  }
}

// ========== TOKEN DE DOWNLOAD ==========
export function generateDownloadToken(): string {
  return crypto.randomBytes(32).toString('hex');
}

// ========== ID ÚNICO ==========
export function generateId(): string {
  return crypto.randomUUID();
}

// ========== SLUG ==========
export function generateSlug(text: string): string {
  return text
    .toLowerCase()
    .trim()
    .replace(/[^\w\s-]/g, '')
    .replace(/\s+/g, '-')
    .replace(/-+/g, '-');
}

// ========== VALIDAÇÃO DE WEBHOOK ==========
export function validateWebhookSignature(
  payload: string,
  signature: string,
  secret: string
): boolean {
  const expectedSignature = crypto
    .createHmac('sha256', secret)
    .update(payload)
    .digest('hex');
  
  return crypto.timingSafeEqual(
    Buffer.from(signature),
    Buffer.from(expectedSignature)
  );
}

// ========== CRIPTOGRAFIA SIMPLES ==========
export function encrypt(text: string): string {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(
    'aes-256-cbc',
    Buffer.from(SECRET_KEY.padEnd(32, '0').slice(0, 32)),
    iv
  );
  
  let encrypted = cipher.update(text, 'utf-8', 'hex');
  encrypted += cipher.final('hex');
  
  return iv.toString('hex') + ':' + encrypted;
}

export function decrypt(encryptedText: string): string {
  const [iv, encrypted] = encryptedText.split(':');
  const decipher = crypto.createDecipheriv(
    'aes-256-cbc',
    Buffer.from(SECRET_KEY.padEnd(32, '0').slice(0, 32)),
    Buffer.from(iv, 'hex')
  );
  
  let decrypted = decipher.update(encrypted, 'hex', 'utf-8');
  decrypted += decipher.final('utf-8');
  
  return decrypted;
}
