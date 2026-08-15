'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { webcrypto } = require('node:crypto');

const { subtle } = webcrypto;
const encoder = new TextEncoder();
const decoder = new TextDecoder();
const randomBytes = (n) => webcrypto.getRandomValues(new Uint8Array(n));
const b64 = (value) => Buffer.from(value).toString('base64url');

async function generateIdentity() {
  const [encryption, signing] = await Promise.all([
    subtle.generateKey(
      { name: 'RSA-OAEP', modulusLength: 3072, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
      true,
      ['encrypt', 'decrypt']
    ),
    subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
  ]);
  return { encryption, signing };
}

async function wrapChatKey(raw, publicKey) {
  return subtle.encrypt({ name: 'RSA-OAEP' }, publicKey, raw);
}

function agreementStatement(agreement, participants) {
  return JSON.stringify({
    v: 1,
    keyId: agreement.keyId,
    participants: [...participants].sort(),
    keyHash: agreement.keyHash,
    creator: agreement.creator
  });
}

test('signed key establishment lets two identities exchange AES-GCM ciphertext and detects tampering', async () => {
  const alice = await generateIdentity();
  const bob = await generateIdentity();
  const chatKey = randomBytes(32);
  const participants = ['alice', 'bob'];
  const keyHash = b64(await subtle.digest('SHA-256', chatKey));
  const agreement = { v: 1, keyId: b64(randomBytes(16)), keyHash, creator: 'alice' };
  const signature = await subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    alice.signing.privateKey,
    encoder.encode(agreementStatement(agreement, participants))
  );
  assert.equal(new Uint8Array(signature).length, 64);
  assert.equal(
    await subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      alice.signing.publicKey,
      signature,
      encoder.encode(agreementStatement(agreement, participants))
    ),
    true
  );

  const aliceEnvelope = await wrapChatKey(chatKey, alice.encryption.publicKey);
  const bobEnvelope = await wrapChatKey(chatKey, bob.encryption.publicKey);
  assert.equal(new Uint8Array(aliceEnvelope).length, 384);
  assert.equal(new Uint8Array(bobEnvelope).length, 384);

  const aliceRaw = new Uint8Array(await subtle.decrypt({ name: 'RSA-OAEP' }, alice.encryption.privateKey, aliceEnvelope));
  const bobRaw = new Uint8Array(await subtle.decrypt({ name: 'RSA-OAEP' }, bob.encryption.privateKey, bobEnvelope));
  assert.deepEqual(aliceRaw, bobRaw);
  assert.equal(b64(await subtle.digest('SHA-256', bobRaw)), agreement.keyHash);

  const aliceAes = await subtle.importKey('raw', aliceRaw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
  const bobAes = await subtle.importKey('raw', bobRaw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
  const iv = randomBytes(12);
  const aad = encoder.encode('yeznsap-message-v1|chat123|msg123|alice');
  const ciphertext = await subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad }, aliceAes, encoder.encode('مرحبا من Yeznsap'));
  const plaintext = await subtle.decrypt({ name: 'AES-GCM', iv, additionalData: aad }, bobAes, ciphertext);
  assert.equal(decoder.decode(plaintext), 'مرحبا من Yeznsap');

  await assert.rejects(
    subtle.decrypt({ name: 'AES-GCM', iv, additionalData: encoder.encode('tampered-aad') }, bobAes, ciphertext)
  );
  const tamperedAgreement = { ...agreement, keyHash: b64(randomBytes(32)) };
  assert.equal(
    await subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      alice.signing.publicKey,
      signature,
      encoder.encode(agreementStatement(tamperedAgreement, participants))
    ),
    false
  );
});
