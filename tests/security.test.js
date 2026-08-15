'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');

const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'yeznsap-v4-test-'));
process.env.NODE_ENV = 'test';
process.env.DATA_DIR = tempDir;
process.env.DATA_ENCRYPTION_KEY = crypto.randomBytes(32).toString('base64');
process.env.DATA_INDEX_KEY = crypto.randomBytes(32).toString('base64');
process.env.AUTH_PEPPER = crypto.randomBytes(32).toString('base64url');
process.env.TRUST_PROXY = '0';

const { __test } = require('../server');

test.after(() => {
  fs.rmSync(tempDir, { recursive: true, force: true });
});

test('new recovery keys contain 16 words and 128 bits of selection entropy', () => {
  const phrase = __test.generatePhrase();
  const words = phrase.split(' ');
  assert.equal(words.length, 16);
  for (const word of words) assert.ok(__test.WORDS.includes(word));
  assert.equal(__test.WORDS.length, 256);
  assert.equal(Math.log2(256) * words.length, 128);
});

test('v4.5 recovery-key parser accepts 16 words only', () => {
  const legacy = Array(12).fill('amber').join(' ');
  const current = Array(16).fill('anchor').join(' ');
  assert.equal(__test.normalizePhrase(legacy), null);
  assert.equal(__test.normalizePhrase(current).split(' ').length, 16);
  assert.equal(__test.normalizePhrase(Array(15).fill('apple').join(' ')), null);
});

test('client-derived authentication secret is exactly 32 bytes base64url', () => {
  const good = crypto.randomBytes(32).toString('base64url');
  assert.equal(__test.normalizeAuthSecret(good), good);
  assert.equal(__test.normalizeAuthSecret('short'), null);
  assert.equal(__test.normalizeAuthSecret(`${good}x`), null);
});

test('E2EE identity bundle requires RSA 3072 public key and bounded private-key wrapper', () => {
  const { publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 3072, publicExponent: 0x10001 });
  const { publicKey: signingPublicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const spki = publicKey.export({ format: 'der', type: 'spki' }).toString('base64url');
  const signingSpki = signingPublicKey.export({ format: 'der', type: 'spki' }).toString('base64url');
  const bundle = {
    v: 1,
    alg: 'RSA-OAEP-3072-SHA256+ECDSA-P256-SHA256',
    publicKeySpki: spki,
    signingPublicKeySpki: signingSpki,
    privateKeyWrap: {
      v: 1,
      alg: 'AES-256-GCM',
      kdf: 'PBKDF2-SHA256',
      iterations: 600000,
      salt: crypto.randomBytes(16).toString('base64url'),
      iv: crypto.randomBytes(12).toString('base64url'),
      ct: crypto.randomBytes(1800).toString('base64url')
    }
  };
  const normalized = __test.normalizeE2eeBundle(bundle);
  assert.ok(normalized);
  assert.match(normalized.fingerprint, /^[A-F0-9]{64}$/);
  assert.equal(__test.normalizeKeyEnvelope(crypto.randomBytes(384).toString('base64url')).length > 0, true);
  assert.equal(__test.normalizeKeyEnvelope(crypto.randomBytes(32).toString('base64url')), null);
});

test('confirmation positions are unique and in range', () => {
  const positions = __test.confirmationPositions(16, 4);
  assert.equal(positions.length, 4);
  assert.equal(new Set(positions).size, 4);
  for (const pos of positions) assert.ok(pos >= 1 && pos <= 16);
});

test('AES-256-GCM store envelope round-trips and rejects tampering', () => {
  const plaintext = Buffer.from('sensitive yeznsap test data');
  const envelope = __test.encryptEnvelope(plaintext);
  assert.equal(envelope.alg, 'AES-256-GCM');
  assert.equal(envelope.kdf, 'HKDF-SHA256');
  assert.deepEqual(__test.decryptEnvelope(envelope), plaintext);

  const tampered = { ...envelope };
  const ct = Buffer.from(tampered.ct, 'base64');
  ct[0] ^= 1;
  tampered.ct = ct.toString('base64');
  assert.throws(() => __test.decryptEnvelope(tampered));
});

test('TOTP code cannot be accepted twice after successful validation', () => {
  const secret = 'JBSWY3DPEHPK3PXP';
  const code = __test.totpCode(secret, Date.now());
  const first = __test.verifyTotpCode(secret, code, null);
  assert.ok(first && Number.isInteger(first.counter));
  const replay = __test.verifyTotpCode(secret, code, first.counter);
  assert.equal(replay, null);
});

test('username validation rejects dangerous/ambiguous forms', () => {
  assert.equal(__test.normalizeUsername('good_user.1'), 'good_user.1');
  assert.equal(__test.normalizeUsername('../admin'), null);
  assert.equal(__test.normalizeUsername('A'), null);
  assert.equal(__test.normalizeUsername('bad space'), null);
});
