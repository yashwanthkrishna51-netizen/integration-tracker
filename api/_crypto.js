const crypto = require('crypto');

// Derive a 32-byte AES-256 key from any string secret of any length.
function deriveKey(secret) {
  return crypto.createHash('sha256').update(String(secret)).digest();
}

// Encrypts a UTF-8 string. Output format (base64): iv(12 bytes) + authTag(16 bytes) + ciphertext
function encryptString(plaintext, secret) {
  const key = deriveKey(secret);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(Buffer.from(plaintext, 'utf8')), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return Buffer.concat([iv, authTag, ciphertext]).toString('base64');
}

// Reverses encryptString. Throws if the auth tag doesn't validate (wrong key or tampered data).
function decryptString(encryptedB64, secret) {
  const key = deriveKey(secret);
  const payload = Buffer.from(encryptedB64, 'base64');
  const iv = payload.slice(0, 12);
  const authTag = payload.slice(12, 28);
  const ciphertext = payload.slice(28);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(authTag);
  const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return plaintext.toString('utf8');
}

module.exports = { encryptString, decryptString, deriveKey };
