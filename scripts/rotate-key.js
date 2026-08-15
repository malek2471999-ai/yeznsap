'use strict';

require('dotenv').config({ quiet: true });
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

function parseKey(value) {
  if (typeof value !== 'string') return null;
  const raw = Buffer.from(value.trim(), 'base64');
  return raw.length === 32 ? raw : null;
}

function deriveStoreKey(masterKey) {
  return Buffer.from(crypto.hkdfSync('sha256', masterKey, Buffer.from('yeznsap-v4-store-salt'), Buffer.from('store-encryption'), 32));
}

function decryptEnvelope(envelope, masterKey) {
  if (!envelope || envelope.alg !== 'AES-256-GCM') throw new Error('Unsupported encrypted store format');
  const iv = Buffer.from(envelope.iv, 'base64');
  const tag = Buffer.from(envelope.tag, 'base64');
  const ciphertext = Buffer.from(envelope.ct, 'base64');
  if (iv.length !== 12 || tag.length !== 16) throw new Error('Invalid encrypted store metadata');
  const legacy = envelope.v === 1;
  if (!legacy && envelope.v !== 2) throw new Error('Unsupported encrypted store version');
  const key = legacy ? masterKey : deriveStoreKey(masterKey);
  const aad = legacy ? 'yeznsap-store-v3' : 'yeznsap-store-v4';
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv, { authTagLength: 16 });
  decipher.setAAD(Buffer.from(aad));
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

function encryptEnvelope(plaintext, masterKey) {
  const iv = crypto.randomBytes(12);
  const key = deriveStoreKey(masterKey);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv, { authTagLength: 16 });
  cipher.setAAD(Buffer.from('yeznsap-store-v4'));
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return {
    v: 2,
    alg: 'AES-256-GCM',
    kdf: 'HKDF-SHA256',
    iv: iv.toString('base64'),
    tag: cipher.getAuthTag().toString('base64'),
    ct: ciphertext.toString('base64')
  };
}

const oldKey = parseKey(process.env.DATA_ENCRYPTION_KEY);
if (!oldKey) {
  console.error('DATA_ENCRYPTION_KEY is missing or invalid.');
  process.exit(1);
}
const indexKey = parseKey(process.env.DATA_INDEX_KEY);
if (!indexKey) {
  console.error('DATA_INDEX_KEY must be set before key rotation. For a legacy v3 deployment, set it to the CURRENT/OLD DATA_ENCRYPTION_KEY first so backup-code hashes and audit pseudonyms remain stable.');
  process.exit(1);
}

const dataDir = process.env.DATA_DIR ? path.resolve(process.env.DATA_DIR) : path.join(__dirname, '..', 'data');
const storeFile = path.join(dataDir, 'store.enc');
if (!fs.existsSync(storeFile)) {
  console.error(`No encrypted store found at ${storeFile}`);
  process.exit(1);
}

const originalText = fs.readFileSync(storeFile, 'utf8');
const originalEnvelope = JSON.parse(originalText);
const plaintext = decryptEnvelope(originalEnvelope, oldKey);
// Validate JSON before rotating so a corrupt plaintext payload is never re-encrypted.
JSON.parse(plaintext.toString('utf8'));

const newKey = crypto.randomBytes(32);
const nextEnvelope = encryptEnvelope(plaintext, newKey);
const stamp = new Date().toISOString().replace(/[:.]/g, '-');
const backup = `${storeFile}.bak-${stamp}`;
const tmp = `${storeFile}.${process.pid}.rotate.tmp`;

fs.copyFileSync(storeFile, backup, fs.constants.COPYFILE_EXCL);
try { fs.chmodSync(backup, 0o600); } catch { /* best effort */ }
const fd = fs.openSync(tmp, 'wx', 0o600);
try {
  fs.writeFileSync(fd, JSON.stringify(nextEnvelope), 'utf8');
  fs.fsyncSync(fd);
} finally {
  fs.closeSync(fd);
}
fs.renameSync(tmp, storeFile);
try { fs.chmodSync(storeFile, 0o600); } catch { /* best effort */ }

console.log('Key rotation completed for the encrypted data file.');
console.log(`Backup encrypted with OLD key: ${backup}`);
console.log('Update DATA_ENCRYPTION_KEY in your secret manager BEFORE restarting the app:');
console.log(`NEW_DATA_ENCRYPTION_KEY=${newKey.toString('base64')}`);
console.log('After verifying startup and data, securely remove the old-key backup when your retention policy allows.');
