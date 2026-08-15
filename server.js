require('dotenv').config({ quiet: true });

const express = require('express');
const cookieParser = require('cookie-parser');
const { rateLimit } = require('express-rate-limit');
const helmet = require('helmet');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { promisify } = require('util');

const scryptAsync = promisify(crypto.scrypt);
const app = express();
app.disable('x-powered-by');
app.disable('etag');
if (process.env.TRUST_PROXY === '1') app.set('trust proxy', 1);

const IS_PROD = process.env.NODE_ENV === 'production';
const PORT = Number(process.env.PORT || 3000);
const MAX_DEVICES = clampInt(process.env.MAX_DEVICES, 1, 20, 5);
const SESSION_IDLE_MINUTES = clampInt(process.env.SESSION_IDLE_MINUTES, 5, 1440, 30);
const SESSION_ABSOLUTE_DAYS = clampInt(process.env.SESSION_ABSOLUTE_DAYS, 1, 30, 7);
const SESSION_TOUCH_SECONDS = clampInt(process.env.SESSION_TOUCH_SECONDS, 15, 300, 60);
const MAX_KDF_CONCURRENCY = clampInt(process.env.MAX_KDF_CONCURRENCY, 1, 8, 2);
const MAX_KDF_QUEUE = clampInt(process.env.MAX_KDF_QUEUE, 10, 500, 50);
const MAX_EPHEMERAL_CHALLENGES = clampInt(process.env.MAX_EPHEMERAL_CHALLENGES, 100, 50000, 5000);
const NEW_RECOVERY_WORD_COUNT = 16; // 256-word list × 16 words = 128 bits of entropy. v4.5 authentication accepts 16-word recovery keys only.
const AUTH_KDF_VERSION = 1;
const AUTH_PEPPER = process.env.AUTH_PEPPER || '';
const AUTH_PEPPER_PREVIOUS = process.env.AUTH_PEPPER_PREVIOUS || '';
const APP_ORIGIN = normalizeConfiguredOrigin(process.env.APP_ORIGIN);
const ALLOWED_ORIGINS = new Set(
  String(process.env.ALLOWED_ORIGINS || '')
    .split(',')
    .map(normalizeConfiguredOrigin)
    .filter(Boolean)
);

const DATA_KEY = parseDataKey(process.env.DATA_ENCRYPTION_KEY);
if (!DATA_KEY) {
  console.error('Missing/invalid DATA_ENCRYPTION_KEY. Generate one with: npm run keygen');
  process.exit(1);
}
const CONFIGURED_INDEX_KEY = parseDataKey(process.env.DATA_INDEX_KEY);
if (IS_PROD && !CONFIGURED_INDEX_KEY) {
  console.error('DATA_INDEX_KEY must be a separate 32-byte Base64 secret in production.');
  process.exit(1);
}
// Development/legacy fallback only. New setups always generate DATA_INDEX_KEY independently.
const INDEX_HMAC_KEY = CONFIGURED_INDEX_KEY || DATA_KEY;
if (!CONFIGURED_INDEX_KEY && !IS_PROD) {
  console.warn('DATA_INDEX_KEY is not set; using DATA_ENCRYPTION_KEY for keyed hashes (legacy/development only).');
}
if (IS_PROD && AUTH_PEPPER.length < 32) {
  console.error('AUTH_PEPPER must be at least 32 characters in production.');
  process.exit(1);
}
if (IS_PROD && !APP_ORIGIN.startsWith('https://')) {
  console.error('APP_ORIGIN must be set to the canonical https:// origin in production (scheme + host only, no path/query/hash).');
  process.exit(1);
}

// Derive independent subkeys so encryption and keyed hashing never reuse the raw master key directly.
const STORE_KEY = Buffer.from(crypto.hkdfSync('sha256', DATA_KEY, Buffer.from('yeznsap-v4-store-salt'), Buffer.from('store-encryption'), 32));

const cspDirectives = {
  defaultSrc: ["'self'"],
  baseUri: ["'self'"],
  fontSrc: ["'self'"],
  formAction: ["'self'"],
  frameAncestors: ["'none'"],
  imgSrc: ["'self'", 'data:'],
  objectSrc: ["'none'"],
  scriptSrc: ["'self'"],
  scriptSrcAttr: ["'none'"],
  styleSrc: ["'self'"],
  connectSrc: ["'self'"]
};
if (IS_PROD) cspDirectives.upgradeInsecureRequests = [];

app.use(helmet({
  contentSecurityPolicy: { directives: cspDirectives },
  crossOriginEmbedderPolicy: true,
  crossOriginOpenerPolicy: { policy: 'same-origin' },
  crossOriginResourcePolicy: { policy: 'same-origin' },
  hsts: IS_PROD ? { maxAge: 31536000, includeSubDomains: true, preload: true } : false,
  referrerPolicy: { policy: 'no-referrer' }
}));
app.use((_req, res, next) => {
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=(), usb=()');
  next();
});
app.use(express.json({ limit: '32kb', strict: true, type: 'application/json' }));
app.use(cookieParser());
app.use('/api', (req, res, next) => {
  res.setHeader('Cache-Control', 'no-store, max-age=0');
  res.setHeader('Pragma', 'no-cache');
  const unsafe = !['GET', 'HEAD', 'OPTIONS'].includes(req.method);
  if (unsafe && req.get('content-type') && !req.is('application/json')) {
    return res.status(415).json({ success: false, message: 'نوع المحتوى غير مدعوم' });
  }
  const fetchSite = String(req.get('sec-fetch-site') || '').toLowerCase();
  if (unsafe && fetchSite && !['same-origin', 'same-site', 'none'].includes(fetchSite)) {
    return res.status(403).json({ success: false, message: 'تم رفض طلب من مصدر خارجي' });
  }
  const origin = String(req.get('origin') || '').trim();
  if (unsafe && origin) {
    const expected = APP_ORIGIN || `${req.protocol}://${req.get('host')}`;
    if (origin !== expected && !ALLOWED_ORIGINS.has(origin)) {
      return res.status(403).json({ success: false, message: 'المصدر غير مسموح' });
    }
  }
  next();
});

const SESSION_COOKIE = IS_PROD ? '__Host-id' : 'id';
const DEVICE_COOKIE = IS_PROD ? '__Host-did' : 'did';
const BASE_COOKIE = {
  httpOnly: true,
  secure: IS_PROD,
  sameSite: 'strict',
  path: '/'
};

const DATA_DIR = process.env.DATA_DIR ? path.resolve(process.env.DATA_DIR) : path.join(__dirname, 'data');
const STORE_FILE = path.join(DATA_DIR, 'store.enc');
const LEGACY_USERS_FILE = path.join(DATA_DIR, 'users.json');
const registrationChallenges = new Map();
const twoFactorLoginChallenges = new Map();

// Yeznsap-specific list. Not BIP39 and never intended for cryptocurrency wallets.
const WORDS = [
  'amber','anchor','apple','arrow','artist','atlas','aurora','autumn','bamboo','beacon','berry','bicycle','blossom','bridge','breeze','brook',
  'cactus','candle','canyon','cedar','cherry','circle','cloud','cobalt','comet','coral','cotton','crystal','dawn','delta','desert','dolphin',
  'dream','drift','eagle','earth','echo','ember','emerald','falcon','feather','field','firefly','forest','fossil','frost','galaxy','garden',
  'glacier','gold','harbor','hazel','honey','horizon','island','ivory','jasmine','jungle','kettle','lagoon','lantern','lavender','leaf','lemon',
  'lilac','lotus','lunar','maple','marble','meadow','meteor','mint','mirror','mist','moon','moss','mountain','nebula','nectar','night',
  'oasis','ocean','olive','opal','orchid','palm','peach','pearl','pebble','pepper','pine','planet','plum','pond','prairie','quartz',
  'rain','raven','reef','river','rose','ruby','saffron','sage','sand','scarlet','shadow','shell','silver','sky','snow','solar',
  'sparrow','spring','star','stone','storm','sunset','surf','teal','thunder','tiger','timber','topaz','trail','tulip','valley','velvet',
  'violet','water','willow','wind','winter','wood','acorn','alpine','apricot','badger','bay','birch','bluebird','bramble','bronze','butterfly',
  'cascade','chestnut','clover','copper','crane','daisy','dune','elm','fern','finch','flame','fox','granite','grape','grove','hawk',
  'heather','heron','indigo','iris','jade','juniper','kiwi','lake','lark','lime','magnolia','mango','marigold','mercury','mesa','midnight',
  'mulberry','north','oak','onyx','orange','otter','papaya','petal','phoenix','poppy','rainbow','redwood','robin','sapphire','savanna','sequoia',
  'shore','spruce','sunrise','swift','tangerine','terra','thorn','tide','umber','wave','wren','yucca','zephyr','acacia','aster','azalea',
  'basil','bluejay','carnation','citron','cypress','dahlia','egret','fig','fir','ginger','irisfield','kelp','laurel','lichen','mimosa','myrtle',
  'nutmeg','pansy','pinecone','primrose','reed','rosemary','seashell','sorrel','sumac','thyme','truffle','walnut','waterfall','wildflower','yarrow','zinnia',
  'aviary','brookside','capri','citrine','cosmos','evergreen','harvest','haven','marina','monsoon','mosaic','orchard','paradise','peony','ripple','solstice'
];
if (new Set(WORDS).size !== 256) {
  console.error('Internal word list must contain exactly 256 unique words.');
  process.exit(1);
}

function normalizeConfiguredOrigin(value) {
  const raw = String(value || '').trim();
  if (!raw) return '';
  try {
    const url = new URL(raw);
    if (!['http:', 'https:'].includes(url.protocol)) return '';
    if (url.username || url.password || url.pathname !== '/' || url.search || url.hash) return '';
    return url.origin;
  } catch {
    return '';
  }
}

function clampInt(value, min, max, fallback) {
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(max, Math.max(min, parsed));
}

function parseDataKey(value) {
  if (typeof value !== 'string' || !value.trim()) return null;
  try {
    const raw = Buffer.from(value.trim(), 'base64');
    return raw.length === 32 ? raw : null;
  } catch {
    return null;
  }
}

function ensureDataDir() {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  if (fs.existsSync(LEGACY_USERS_FILE)) {
    console.error('Refusing to start while legacy plaintext data/users.json exists. Move/delete it after migrating accounts.');
    process.exit(1);
  }
}

function encryptEnvelope(plaintextBuffer, aad = 'yeznsap-store-v4') {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', STORE_KEY, iv, { authTagLength: 16 });
  cipher.setAAD(Buffer.from(aad, 'utf8'));
  const ciphertext = Buffer.concat([cipher.update(plaintextBuffer), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    v: 2,
    alg: 'AES-256-GCM',
    kdf: 'HKDF-SHA256',
    iv: iv.toString('base64'),
    tag: tag.toString('base64'),
    ct: ciphertext.toString('base64')
  };
}

function decryptEnvelope(envelope) {
  if (!envelope || envelope.alg !== 'AES-256-GCM') throw new Error('Unsupported encrypted store format');
  const iv = Buffer.from(envelope.iv, 'base64');
  const tag = Buffer.from(envelope.tag, 'base64');
  const ciphertext = Buffer.from(envelope.ct, 'base64');
  if (iv.length !== 12 || tag.length !== 16) throw new Error('Invalid encrypted store metadata');

  // v1 is the v3 format and is supported only for one-way migration.
  const legacy = envelope.v === 1;
  if (!legacy && envelope.v !== 2) throw new Error('Unsupported encrypted store version');
  const key = legacy ? DATA_KEY : STORE_KEY;
  const aad = legacy ? 'yeznsap-store-v3' : 'yeznsap-store-v4';
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv, { authTagLength: 16 });
  decipher.setAAD(Buffer.from(aad, 'utf8'));
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

function blankStore() {
  return { version: 4, users: {}, sessions: {}, audit: [], chats: {}, messages: {} };
}

function loadStore() {
  ensureDataDir();
  if (!fs.existsSync(STORE_FILE)) return blankStore();
  try {
    const envelope = JSON.parse(fs.readFileSync(STORE_FILE, 'utf8'));
    const plaintext = decryptEnvelope(envelope).toString('utf8');
    const parsed = JSON.parse(plaintext);
    if (!parsed || ![3, 4].includes(parsed.version) || typeof parsed.users !== 'object' || typeof parsed.sessions !== 'object') {
      throw new Error('Unexpected store structure');
    }
    if (!Array.isArray(parsed.audit)) parsed.audit = [];
    if (!parsed.chats || typeof parsed.chats !== 'object' || Array.isArray(parsed.chats)) parsed.chats = {};
    if (!parsed.messages || typeof parsed.messages !== 'object' || Array.isArray(parsed.messages)) parsed.messages = {};
    if (parsed.version === 3) {
      parsed.version = 4;
      for (const user of Object.values(parsed.users)) {
        if (!user.phraseWordCount) user.phraseWordCount = 12;
        if (!user.phraseKdfVersion) user.phraseKdfVersion = AUTH_KDF_VERSION;
        user.totp = user.totp || { enabled: false, secret: null, pendingSecret: null, backupCodeHashes: [] };
        if (user.totp.lastAcceptedCounter === undefined) user.totp.lastAcceptedCounter = null;
        user.lockedUntil = null;
        user.nextLoginAt = null;
        user.lastFailedLoginAt = null;
      }
    }
    return parsed;
  } catch (error) {
    console.error('Encrypted data store could not be decrypted. Check DATA_ENCRYPTION_KEY. Refusing to start.', error.message);
    process.exit(1);
  }
}

let store = loadStore();

function saveStore() {
  ensureDataDir();
  const serialized = Buffer.from(JSON.stringify(store), 'utf8');
  const envelope = encryptEnvelope(serialized);
  const tmp = `${STORE_FILE}.${process.pid}.${Date.now()}.tmp`;
  const fd = fs.openSync(tmp, 'wx', 0o600);
  try {
    fs.writeFileSync(fd, JSON.stringify(envelope), 'utf8');
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  fs.renameSync(tmp, STORE_FILE);
  try { fs.chmodSync(STORE_FILE, 0o600); } catch { /* best effort */ }
  // Persist the directory rename on filesystems that support directory fsync.
  try {
    const dirFd = fs.openSync(DATA_DIR, 'r');
    try { fs.fsyncSync(dirFd); } finally { fs.closeSync(dirFd); }
  } catch { /* best effort */ }
}

function sanitizeString(value, maxLen = 500) {
  if (typeof value !== 'string') return '';
  return value.trim().slice(0, maxLen);
}

function normalizeUsername(value) {
  const username = sanitizeString(value, 24).toLowerCase();
  if (!/^[a-z0-9](?:[a-z0-9._]{1,22}[a-z0-9])?$/.test(username)) return null;
  return username;
}

function normalizePhrase(value, allowedCounts = [NEW_RECOVERY_WORD_COUNT]) {
  if (typeof value !== 'string' || value.length > 600) return null;
  const words = value.toLowerCase().trim().split(/\s+/).filter(Boolean);
  if (!allowedCounts.includes(words.length)) return null;
  if (!words.every((word) => /^[a-z]+$/.test(word))) return null;
  return words.join(' ');
}

function normalizeAuthSecret(value) {
  const secret = sanitizeString(value, 100);
  return /^[A-Za-z0-9_-]{43}$/.test(secret) ? secret : null;
}

function normalizeB64Url(value, minBytes, maxBytes) {
  const text = sanitizeString(value, Math.ceil(maxBytes * 4 / 3) + 16);
  if (!text || !/^[A-Za-z0-9_-]+$/.test(text)) return null;
  try {
    const raw = Buffer.from(text, 'base64url');
    if (raw.length < minBytes || raw.length > maxBytes) return null;
    return { text, raw };
  } catch {
    return null;
  }
}

function normalizeE2eeBundle(value) {
  if (!value || value.v !== 1 || value.alg !== 'RSA-OAEP-3072-SHA256+ECDSA-P256-SHA256') return null;
  const publicKey = normalizeB64Url(value.publicKeySpki, 300, 1024);
  const signingKey = normalizeB64Url(value.signingPublicKeySpki, 80, 256);
  const wrap = value.privateKeyWrap;
  if (!publicKey || !signingKey || !wrap || wrap.v !== 1 || wrap.alg !== 'AES-256-GCM' || wrap.kdf !== 'PBKDF2-SHA256') return null;
  const iterations = Number(wrap.iterations);
  if (!Number.isInteger(iterations) || iterations < 300000 || iterations > 1200000) return null;
  const salt = normalizeB64Url(wrap.salt, 16, 64);
  const iv = normalizeB64Url(wrap.iv, 12, 12);
  const ct = normalizeB64Url(wrap.ct, 1800, 8192);
  if (!salt || !iv || !ct) return null;
  try {
    const encryptionPublic = crypto.createPublicKey({ key: publicKey.raw, format: 'der', type: 'spki' });
    if (encryptionPublic.asymmetricKeyType !== 'rsa' || Number(encryptionPublic.asymmetricKeyDetails?.modulusLength || 0) < 3072) return null;
    const signingPublic = crypto.createPublicKey({ key: signingKey.raw, format: 'der', type: 'spki' });
    if (signingPublic.asymmetricKeyType !== 'ec' || signingPublic.asymmetricKeyDetails?.namedCurve !== 'prime256v1') return null;
  } catch {
    return null;
  }
  const fingerprint = crypto.createHash('sha256')
    .update(Buffer.from('yeznsap-e2ee-identity-v1\0'))
    .update(publicKey.raw)
    .update(Buffer.from('\0signing\0'))
    .update(signingKey.raw)
    .digest('hex')
    .toUpperCase();
  return {
    v: 1,
    alg: 'RSA-OAEP-3072-SHA256+ECDSA-P256-SHA256',
    publicKeySpki: publicKey.text,
    signingPublicKeySpki: signingKey.text,
    fingerprint,
    privateKeyWrap: {
      v: 1,
      alg: 'AES-256-GCM',
      kdf: 'PBKDF2-SHA256',
      iterations,
      salt: salt.text,
      iv: iv.text,
      ct: ct.text
    }
  };
}

function normalizeKeyEnvelope(value) {
  const decoded = normalizeB64Url(value, 384, 384);
  return decoded ? decoded.text : null;
}

function keyAgreementStatement(agreement, participants) {
  return JSON.stringify({
    v: 1,
    keyId: agreement.keyId,
    participants: [...participants].sort(),
    keyHash: agreement.keyHash,
    creator: agreement.creator
  });
}

function normalizeKeyAgreement(value, participants, expectedCreator) {
  if (!value || value.v !== 1 || value.creator !== expectedCreator) return null;
  const keyId = normalizeB64Url(value.keyId, 16, 16);
  const keyHash = normalizeB64Url(value.keyHash, 32, 32);
  const signature = normalizeB64Url(value.signature, 64, 64);
  if (!keyId || !keyHash || !signature) return null;
  const creatorUser = store.users[expectedCreator];
  const signingSpki = creatorUser?.e2ee?.signingPublicKeySpki;
  if (!signingSpki) return null;
  try {
    const signingPublic = crypto.createPublicKey({ key: Buffer.from(signingSpki, 'base64url'), format: 'der', type: 'spki' });
    const normalized = { v: 1, keyId: keyId.text, keyHash: keyHash.text, creator: expectedCreator, signature: signature.text };
    const statement = Buffer.from(keyAgreementStatement(normalized, participants), 'utf8');
    const ok = crypto.verify('sha256', statement, { key: signingPublic, dsaEncoding: 'ieee-p1363' }, signature.raw);
    return ok ? normalized : null;
  } catch {
    return null;
  }
}

async function verifyUserAuthSecret(user, value) {
  const authSecret = normalizeAuthSecret(value);
  if (!authSecret || user?.authScheme !== 'client-hash-v1' || !user.authSalt || !user.authHash) return false;
  return verifySecret(authSecret, user.authSalt, user.authHash, user.authKdfVersion || AUTH_KDF_VERSION);
}

function hashText(value) {
  return crypto.createHash('sha256').update(value).digest('base64url');
}

function keyedHash(value, purpose = 'generic') {
  const key = crypto.createHmac('sha256', INDEX_HMAC_KEY).update(`yeznsap:${purpose}`).digest();
  return crypto.createHmac('sha256', key).update(String(value || '')).digest('base64url');
}

function requestMeta(req) {
  const ip = req.ip || req.socket?.remoteAddress || '';
  const ua = sanitizeString(req.get('user-agent'), 300);
  return { ipHash: keyedHash(ip, 'ip'), uaHash: keyedHash(ua, 'ua'), ua };
}

function audit(req, action, username, outcome = 'ok', extra = {}) {
  const meta = requestMeta(req);
  store.audit.push({
    ts: new Date().toISOString(),
    action,
    usernameHash: username ? keyedHash(username, 'username') : null,
    ipHash: meta.ipHash,
    uaHash: meta.uaHash,
    outcome,
    ...extra
  });
  if (store.audit.length > 2000) store.audit.splice(0, store.audit.length - 2000);
}

function generatePhrase(wordCount = NEW_RECOVERY_WORD_COUNT) {
  const words = [];
  for (let i = 0; i < wordCount; i += 1) words.push(WORDS[crypto.randomInt(0, WORDS.length)]);
  return words.join(' ');
}

function confirmationPositions(wordCount = NEW_RECOVERY_WORD_COUNT, count = 4) {
  const positions = new Set();
  while (positions.size < Math.min(count, wordCount)) positions.add(crypto.randomInt(1, wordCount + 1));
  return [...positions].sort((a, b) => a - b);
}

function phraseDigest(phrase) {
  return hashText(`registration:${phrase}`);
}

const SCRYPT_PARAMS = { N: 131072, r: 8, p: 1, maxmem: 192 * 1024 * 1024 };
let kdfActive = 0;
const kdfWaiters = [];

async function withKdfSlot(task) {
  if (kdfActive >= MAX_KDF_CONCURRENCY) {
    if (kdfWaiters.length >= MAX_KDF_QUEUE) {
      const error = new Error('Authentication service is busy');
      error.code = 'KDF_BUSY';
      throw error;
    }
    await new Promise((resolve) => kdfWaiters.push(resolve));
  }
  kdfActive += 1;
  try {
    return await task();
  } finally {
    kdfActive -= 1;
    const next = kdfWaiters.shift();
    if (next) next();
  }
}

async function deriveSecret(secret, salt, length = 64, pepper = AUTH_PEPPER) {
  return withKdfSlot(async () => Buffer.from(await scryptAsync(`${secret}${pepper}`, salt, length, SCRYPT_PARAMS)));
}

async function hashSecret(secret) {
  const salt = crypto.randomBytes(16);
  const derived = await deriveSecret(secret, salt, 64);
  return { salt: salt.toString('base64'), hash: derived.toString('base64'), kdfVersion: AUTH_KDF_VERSION };
}

async function verifySecretDetailed(secret, saltB64, hashB64, kdfVersion = AUTH_KDF_VERSION) {
  try {
    if (kdfVersion !== AUTH_KDF_VERSION) return { ok: false, usedPreviousPepper: false };
    const salt = Buffer.from(saltB64, 'base64');
    const expected = Buffer.from(hashB64, 'base64');
    const current = await deriveSecret(secret, salt, expected.length, AUTH_PEPPER);
    if (expected.length === current.length && crypto.timingSafeEqual(expected, current)) {
      return { ok: true, usedPreviousPepper: false };
    }
    if (AUTH_PEPPER_PREVIOUS && AUTH_PEPPER_PREVIOUS !== AUTH_PEPPER) {
      const previous = await deriveSecret(secret, salt, expected.length, AUTH_PEPPER_PREVIOUS);
      if (expected.length === previous.length && crypto.timingSafeEqual(expected, previous)) {
        return { ok: true, usedPreviousPepper: true };
      }
    }
    return { ok: false, usedPreviousPepper: false };
  } catch (error) {
    if (error?.code === 'KDF_BUSY') throw error;
    return { ok: false, usedPreviousPepper: false };
  }
}

async function verifySecret(secret, saltB64, hashB64, kdfVersion = AUTH_KDF_VERSION) {
  return (await verifySecretDetailed(secret, saltB64, hashB64, kdfVersion)).ok;
}

async function consumeDummyScrypt(secret) {
  try {
    const salt = Buffer.alloc(16, 0x5a);
    await deriveSecret(secret || 'invalid', salt, 64, AUTH_PEPPER);
    if (AUTH_PEPPER_PREVIOUS && AUTH_PEPPER_PREVIOUS !== AUTH_PEPPER) {
      await deriveSecret(secret || 'invalid', salt, 64, AUTH_PEPPER_PREVIOUS);
    }
  } catch { /* timing equalization best effort */ }
}

function safeUser(user) {
  return {
    username: user.username,
    displayName: user.displayName || null,
    avatarUrl: user.avatarUrl || null,
    bio: user.bio || null,
    createdAt: user.createdAt,
    lastSeen: user.lastSeen,
    isOnline: Boolean(activeSessionsFor(user.username).length),
    security: {
      twoFactorEnabled: Boolean(user.totp?.enabled),
      pinEnabled: Boolean(user.pin?.hash),
      maxDevices: MAX_DEVICES,
      sessionIdleMinutes: SESSION_IDLE_MINUTES
    },
    privacy: normalizePrivacy(user.privacy),
    autoDeleteInactiveDays: normalizeAutoDeleteDays(user.autoDeleteInactiveDays),
    e2eeReady: Boolean(user.e2ee?.publicKeySpki && user.e2ee?.privateKeyWrap),
    e2eeFingerprint: user.e2ee?.fingerprint || null
  };
}


function safeDirectoryUser(user) {
  if (!user) return null;
  return {
    username: user.username,
    displayName: user.displayName || null,
    avatarUrl: user.avatarUrl || null,
    isOnline: Boolean(activeSessionsFor(user.username).length),
    e2ee: user.e2ee?.publicKeySpki ? {
      v: 1,
      alg: user.e2ee.alg,
      publicKeySpki: user.e2ee.publicKeySpki,
      signingPublicKeySpki: user.e2ee.signingPublicKeySpki,
      fingerprint: user.e2ee.fingerprint
    } : null
  };
}

function ensureMessagingStore() {
  if (!store.chats || typeof store.chats !== 'object' || Array.isArray(store.chats)) store.chats = {};
  if (!store.messages || typeof store.messages !== 'object' || Array.isArray(store.messages)) store.messages = {};
}

function userCanAccessChat(chat, username) {
  return Boolean(chat && Array.isArray(chat.participants) && chat.participants.includes(username));
}

function directChatBetween(a, b) {
  ensureMessagingStore();
  return Object.values(store.chats).find((chat) =>
    chat?.type === 'direct' && Array.isArray(chat.participants) && chat.participants.length === 2 &&
    chat.participants.includes(a) && chat.participants.includes(b)
  ) || null;
}

function chatSummary(chat, username) {
  const otherUsername = chat.participants.find((p) => p !== username) || username;
  const other = safeDirectoryUser(store.users[otherUsername]);
  const list = Array.isArray(store.messages[chat.id]) ? store.messages[chat.id] : [];
  const last = list.length ? list[list.length - 1] : null;
  return {
    id: chat.id,
    type: chat.type,
    other,
    createdAt: chat.createdAt,
    updatedAt: chat.updatedAt,
    e2ee: Boolean(chat.e2ee?.v === 1),
    e2eeStartedAt: chat.e2ee?.startedAt || null,
    legacyMessageCount: Number(chat.e2ee?.legacyMessageCount || 0),
    lastMessage: last ? {
      id: last.id,
      sender: last.sender,
      createdAt: last.createdAt,
      encrypted: Boolean(last.v === 1 && last.ct && last.iv),
      legacyText: last.v === 1 ? null : (last.text || null)
    } : null
  };
}

function chatForClient(chat, username) {
  const summary = chatSummary(chat, username);
  if (!chat.e2ee?.keyEnvelopes) return summary;
  return {
    ...summary,
    e2eeInfo: {
      v: 1,
      keyEnvelope: chat.e2ee.keyEnvelopes[username] || null,
      agreement: chat.e2ee.agreement || null,
      peerFingerprint: summary.other?.e2ee?.fingerprint || null,
      peerPublicKeySpki: summary.other?.e2ee?.publicKeySpki || null,
      peerSigningPublicKeySpki: summary.other?.e2ee?.signingPublicKeySpki || null,
      creatorSigningPublicKeySpki: store.users[chat.e2ee?.agreement?.creator]?.e2ee?.signingPublicKeySpki || null
    }
  };
}

function removeUserMessagingData(username) {
  ensureMessagingStore();
  for (const [chatId, chat] of Object.entries(store.chats)) {
    if (Array.isArray(chat?.participants) && chat.participants.includes(username)) {
      delete store.chats[chatId];
      delete store.messages[chatId];
    }
  }
}

function normalizePrivacy(value = {}) {
  const allowedVisibility = new Set(['everyone', 'contacts', 'nobody']);
  return {
    lastSeen: allowedVisibility.has(value.lastSeen) ? value.lastSeen : 'contacts',
    readReceipts: value.readReceipts !== false,
    statusVisibility: allowedVisibility.has(value.statusVisibility) ? value.statusVisibility : 'contacts',
    profilePhoto: allowedVisibility.has(value.profilePhoto) ? value.profilePhoto : 'contacts'
  };
}

function normalizeAutoDeleteDays(value) {
  if (value === null || value === undefined || value === 0 || value === 'never') return null;
  const days = Number(value);
  return [30, 90, 180, 365].includes(days) ? days : null;
}

function nowMs() { return Date.now(); }
function randomToken(bytes = 32) { return crypto.randomBytes(bytes).toString('base64url'); }
function sessionHash(raw) { return hashText(`session:${raw}`); }
function deviceHash(raw) { return hashText(`device:${raw}`); }
function csrfHash(raw) { return hashText(`csrf:${raw}`); }

function getOrCreateDeviceId(req, res) {
  let raw = req.cookies[DEVICE_COOKIE];
  if (typeof raw !== 'string' || raw.length < 32 || raw.length > 200) {
    raw = randomToken(32);
    res.cookie(DEVICE_COOKIE, raw, {
      ...BASE_COOKIE,
      maxAge: 365 * 24 * 60 * 60 * 1000
    });
  }
  return raw;
}

function userAgentLabel(ua) {
  const s = String(ua || 'Unknown device');
  let browser = 'Browser';
  if (/Edg\//i.test(s)) browser = 'Edge';
  else if (/Firefox\//i.test(s)) browser = 'Firefox';
  else if (/Chrome\//i.test(s)) browser = 'Chrome';
  else if (/Safari\//i.test(s)) browser = 'Safari';
  let platform = 'Desktop';
  if (/Android/i.test(s)) platform = 'Android';
  else if (/iPhone|iPad|iPod/i.test(s)) platform = 'iOS';
  else if (/Windows/i.test(s)) platform = 'Windows';
  else if (/Macintosh|Mac OS X/i.test(s)) platform = 'macOS';
  else if (/Linux/i.test(s)) platform = 'Linux';
  return `${browser} · ${platform}`;
}

function activeSessionsFor(username) {
  const now = nowMs();
  return Object.entries(store.sessions)
    .filter(([, s]) => s.username === username && !s.revokedAt && s.absoluteExpiresAt > now && (now - s.lastSeenAt) <= SESSION_IDLE_MINUTES * 60 * 1000)
    .map(([tokenHash, s]) => ({ tokenHash, ...s }));
}

function pruneSessions() {
  const now = nowMs();
  let changed = false;
  for (const [tokenHash, s] of Object.entries(store.sessions)) {
    const idleExpired = now - s.lastSeenAt > SESSION_IDLE_MINUTES * 60 * 1000;
    const oldRevoked = s.revokedAt && now - s.revokedAt > 7 * 24 * 60 * 60 * 1000;
    if (s.absoluteExpiresAt <= now || idleExpired || oldRevoked) {
      delete store.sessions[tokenHash];
      changed = true;
    }
  }
  return changed;
}

function createSession(req, res, username) {
  pruneSessions();
  const existing = activeSessionsFor(username).sort((a, b) => a.createdAt - b.createdAt);
  while (existing.length >= MAX_DEVICES) {
    const oldest = existing.shift();
    if (oldest) delete store.sessions[oldest.tokenHash];
  }

  const rawSession = randomToken(32);
  const rawDevice = getOrCreateDeviceId(req, res);
  const rawCsrf = randomToken(24);
  const tokenHash = sessionHash(rawSession);
  const meta = requestMeta(req);
  const now = nowMs();
  const publicId = randomToken(12);
  store.sessions[tokenHash] = {
    id: publicId,
    username,
    deviceHash: deviceHash(rawDevice),
    label: userAgentLabel(meta.ua),
    uaHash: meta.uaHash,
    ipHash: meta.ipHash,
    csrfHash: csrfHash(rawCsrf),
    createdAt: now,
    lastSeenAt: now,
    absoluteExpiresAt: now + SESSION_ABSOLUTE_DAYS * 24 * 60 * 60 * 1000,
    revokedAt: null,
    locked: false,
    pinFailedCount: 0,
    pinNextAttemptAt: null
  };

  // Session cookie is intentionally non-persistent: closing the browser ends the client-side session.
  res.cookie(SESSION_COOKIE, rawSession, BASE_COOKIE);
  return { csrfToken: rawCsrf, sessionId: publicId };
}

function clearSessionCookies(res) {
  res.clearCookie(SESSION_COOKIE, BASE_COOKIE);
  // Keep device cookie so the same browser retains a stable device binding identity.
}

function requireAuth(req, res, next) {
  const rawSession = req.cookies[SESSION_COOKIE];
  const rawDevice = req.cookies[DEVICE_COOKIE];
  if (typeof rawSession !== 'string' || typeof rawDevice !== 'string') {
    return res.status(401).json({ success: false, message: 'يجب تسجيل الدخول' });
  }
  const tokenHash = sessionHash(rawSession);
  const session = store.sessions[tokenHash];
  if (!session || session.revokedAt) {
    clearSessionCookies(res);
    return res.status(401).json({ success: false, message: 'الجلسة غير صالحة' });
  }
  const now = nowMs();
  const idleExpired = now - session.lastSeenAt > SESSION_IDLE_MINUTES * 60 * 1000;
  if (session.absoluteExpiresAt <= now || idleExpired) {
    delete store.sessions[tokenHash];
    saveStore();
    clearSessionCookies(res);
    return res.status(401).json({ success: false, message: 'انتهت الجلسة، سجّل الدخول من جديد' });
  }
  if (session.deviceHash !== deviceHash(rawDevice)) {
    delete store.sessions[tokenHash];
    audit(req, 'session_device_mismatch', session.username, 'blocked');
    saveStore();
    clearSessionCookies(res);
    return res.status(401).json({ success: false, message: 'تم رفض الجلسة بسبب اختلاف الجهاز' });
  }
  if (session.locked && !req.originalUrl.startsWith('/api/security/unlock') && !req.originalUrl.startsWith('/api/auth/logout')) {
    return res.status(423).json({ success: false, locked: true, message: 'التطبيق مقفل بالـPIN' });
  }
  const user = store.users[session.username];
  const shouldPersistTouch = now - session.lastSeenAt >= SESSION_TOUCH_SECONDS * 1000;
  session.lastSeenAt = now;
  if (user) user.lastSeen = new Date(now).toISOString();
  req.auth = { tokenHash, session, user };
  if (shouldPersistTouch) saveStore();
  next();
}

function requireCsrf(req, res, next) {
  const supplied = sanitizeString(req.get('x-csrf-token'), 200);
  const expected = req.auth?.session?.csrfHash;
  const suppliedHash = supplied ? Buffer.from(csrfHash(supplied)) : null;
  const expectedHash = expected ? Buffer.from(expected) : null;
  const valid = suppliedHash && expectedHash && suppliedHash.length === expectedHash.length && crypto.timingSafeEqual(suppliedHash, expectedHash);
  if (!valid) {
    audit(req, 'csrf_rejected', req.auth?.session?.username || null, 'blocked');
    saveStore();
    return res.status(403).json({ success: false, message: 'فشل التحقق الأمني للطلب' });
  }
  next();
}

function issueCsrf(req) {
  const raw = randomToken(24);
  req.auth.session.csrfHash = csrfHash(raw);
  return raw;
}

function genericAuthFailure(res) {
  return res.status(401).json({ success: false, message: 'اسم المستخدم أو مفتاح الدخول غير صحيح' });
}

function recordFailedLogin(req, user) {
  if (!user) return;
  const now = nowMs();
  if (!user.lastFailedLoginAt || now - user.lastFailedLoginAt > 15 * 60 * 1000) user.failedLoginCount = 0;
  user.failedLoginCount = Number(user.failedLoginCount || 0) + 1;
  user.lastFailedLoginAt = now;
  // Do not lock the whole account: account-wide lockouts let an attacker deny service to a known username.
  // Brute-force pressure is handled by source-based rate limiting; the recovery key itself has 128 bits of entropy.
  user.nextLoginAt = null;
  user.lockedUntil = null; // legacy fields intentionally retired.
  audit(req, 'login_failed', user.username, 'blocked', { recentFailures: user.failedLoginCount });
}

function resetFailedLogin(user) {
  user.failedLoginCount = 0;
  user.lastFailedLoginAt = null;
  user.nextLoginAt = null;
  user.lockedUntil = null;
}

// TOTP (RFC 6238 style) helpers. SHA-1 is retained here because it is the interoperable TOTP default.
const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
function base32Encode(buffer) {
  let bits = 0;
  let value = 0;
  let output = '';
  for (const byte of buffer) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  return output;
}

function base32Decode(input) {
  const clean = String(input || '').toUpperCase().replace(/=+$/g, '').replace(/[^A-Z2-7]/g, '');
  let bits = 0;
  let value = 0;
  const out = [];
  for (const ch of clean) {
    const idx = BASE32_ALPHABET.indexOf(ch);
    if (idx < 0) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

function totpCode(secretBase32, timestamp = Date.now(), stepSeconds = 30) {
  const secret = base32Decode(secretBase32);
  const counter = Math.floor(timestamp / 1000 / stepSeconds);
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));
  const hmac = crypto.createHmac('sha1', secret).update(msg).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const binary = ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);
  return String(binary % 1_000_000).padStart(6, '0');
}

function verifyTotpCode(secretBase32, code, lastAcceptedCounter = null) {
  const clean = String(code || '').replace(/\s+/g, '');
  if (!/^\d{6}$/.test(clean)) return null;
  const now = Date.now();
  for (const offset of [-30_000, 0, 30_000]) {
    const timestamp = now + offset;
    const counter = Math.floor(timestamp / 1000 / 30);
    const expected = totpCode(secretBase32, timestamp);
    if (crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(clean))) {
      if (Number.isFinite(lastAcceptedCounter) && counter <= lastAcceptedCounter) return null;
      return { counter };
    }
  }
  return null;
}

function backupCodeHash(code) {
  return keyedHash(String(code || '').toUpperCase().replace(/[^A-Z0-9]/g, ''), 'backup-code');
}

function generateBackupCodes() {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const codes = [];
  for (let i = 0; i < 8; i += 1) {
    let code = '';
    for (let j = 0; j < 12; j += 1) code += alphabet[crypto.randomInt(0, alphabet.length)];
    codes.push(`${code.slice(0, 6)}-${code.slice(6)}`);
  }
  return codes;
}

function consumeBackupCode(user, code) {
  const hash = backupCodeHash(code);
  const list = user.totp?.backupCodeHashes || [];
  const idx = list.findIndex((x) => x === hash);
  if (idx < 0) return false;
  list.splice(idx, 1);
  return true;
}

function cleanupEphemeralChallenges() {
  const now = nowMs();
  for (const [key, value] of registrationChallenges) if (value.expiresAt <= now) registrationChallenges.delete(key);
  for (const [key, value] of twoFactorLoginChallenges) if (value.expiresAt <= now) twoFactorLoginChallenges.delete(key);
}

function keepMapUnderLimit(map, limit = MAX_EPHEMERAL_CHALLENGES) {
  while (map.size >= limit) {
    const oldestKey = map.keys().next().value;
    if (oldestKey === undefined) break;
    map.delete(oldestKey);
  }
}

function cleanupInactiveAccounts() {
  const now = nowMs();
  let changed = false;
  for (const [username, user] of Object.entries(store.users)) {
    const days = normalizeAutoDeleteDays(user.autoDeleteInactiveDays);
    if (!days) continue;
    const last = Date.parse(user.lastSeen || user.createdAt || 0);
    if (Number.isFinite(last) && now - last > days * 24 * 60 * 60 * 1000) {
      delete store.users[username];
      for (const [tokenHash, s] of Object.entries(store.sessions)) if (s.username === username) delete store.sessions[tokenHash];
      removeUserMessagingData(username);
      store.audit.push({ ts: new Date().toISOString(), action: 'account_auto_deleted', usernameHash: keyedHash(username, 'username'), outcome: 'ok' });
      changed = true;
    }
  }
  if (pruneSessions()) changed = true;
  if (changed) saveStore();
}

const phraseLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  identifier: 'recovery-key-generation',
  message: { success: false, message: 'طلبات كثيرة، حاول لاحقًا' }
});
const registerLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 8,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  identifier: 'registration',
  message: { success: false, message: 'محاولات تسجيل كثيرة، حاول لاحقًا' }
});
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 15,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  identifier: 'login',
  message: { success: false, message: 'محاولات دخول كثيرة، حاول لاحقًا' }
});
const sensitiveLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  limit: 30,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  identifier: 'sensitive-security-actions',
  message: { success: false, message: 'طلبات أمنية كثيرة، حاول لاحقًا' }
});
const messageLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 60,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  identifier: 'messaging-send',
  message: { success: false, message: 'إرسال سريع جدًا، انتظر قليلًا ثم حاول من جديد' }
});
const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 180,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  identifier: 'api-global',
  message: { success: false, message: 'طلبات كثيرة جدًا، حاول بعد قليل' }
});
app.use('/api', apiLimiter);

app.use(express.static(path.join(__dirname, 'public'), {
  etag: true,
  maxAge: IS_PROD ? '1h' : 0,
  setHeaders(res, filePath) {
    if (filePath.endsWith('.html')) res.setHeader('Cache-Control', 'no-store, max-age=0');
  }
}));

app.post('/api/auth/new-phrase', phraseLimiter, (_req, res) => {
  // Recovery keys are generated with Web Crypto in the browser so the server never receives them.
  return res.status(410).json({ success: false, message: 'مفتاح الاسترداد يُنشأ محليًا على جهازك في هذا الإصدار' });
});

app.post('/api/auth/register', registerLimiter, async (req, res) => {
  const username = normalizeUsername(req.body?.username);
  const authSecret = normalizeAuthSecret(req.body?.authSecret);
  const e2ee = normalizeE2eeBundle(req.body?.e2ee);
  const ageConfirmed = req.body?.ageConfirmed === true;
  const recoveryConfirmed = req.body?.recoveryConfirmed === true;

  if (!username) return res.status(400).json({ success: false, message: 'اسم المستخدم يجب أن يكون من 3 إلى 24 حرفًا ويحتوي فقط على a-z و0-9 والنقطة و_' });
  if (!authSecret) return res.status(400).json({ success: false, message: 'مفتاح المصادقة المحلي غير صالح' });
  if (!e2ee) return res.status(400).json({ success: false, message: 'تعذر إنشاء هوية التشفير الطرفي' });
  if (!recoveryConfirmed) return res.status(400).json({ success: false, message: 'يجب تأكيد حفظ كلمات الاسترداد' });
  if (!ageConfirmed) return res.status(400).json({ success: false, message: 'يجب تأكيد استيفاء الحد الأدنى للعمر المطلوب في بلدك' });
  if (store.users[username]) return res.status(409).json({ success: false, message: 'اسم المستخدم مستخدم بالفعل' });

  try {
    const authRecord = await hashSecret(authSecret);
    if (store.users[username]) return res.status(409).json({ success: false, message: 'اسم المستخدم مستخدم بالفعل' });
    const now = new Date().toISOString();
    store.users[username] = {
      username,
      authScheme: 'client-hash-v1',
      authSalt: authRecord.salt,
      authHash: authRecord.hash,
      authKdfVersion: authRecord.kdfVersion,
      recoveryWordCount: NEW_RECOVERY_WORD_COUNT,
      e2ee,
      displayName: null,
      avatarUrl: null,
      bio: null,
      createdAt: now,
      lastSeen: now,
      ageConfirmedAt: now,
      failedLoginCount: 0,
      lockedUntil: null,
      nextLoginAt: null,
      lastFailedLoginAt: null,
      totp: { enabled: false, secret: null, pendingSecret: null, backupCodeHashes: [], lastAcceptedCounter: null },
      pin: null,
      privacy: normalizePrivacy(),
      autoDeleteInactiveDays: null
    };
    const session = createSession(req, res, username);
    audit(req, 'account_registered_e2ee', username, 'ok');
    saveStore();
    return res.status(201).json({ success: true, message: 'تم إنشاء الحساب', user: safeUser(store.users[username]), csrfToken: session.csrfToken });
  } catch (error) {
    if (error?.code === 'KDF_BUSY') throw error;
    console.error('[Register Error]', error.message);
    return res.status(500).json({ success: false, message: 'تعذر إنشاء الحساب، حاول مرة أخرى' });
  }
});

app.post('/api/auth/login', loginLimiter, async (req, res) => {
  cleanupEphemeralChallenges();
  const username = normalizeUsername(req.body?.username);
  const authSecret = normalizeAuthSecret(req.body?.authSecret);
  if (!username || !authSecret) return genericAuthFailure(res);

  const user = store.users[username];
  if (!user) {
    await consumeDummyScrypt(authSecret);
    audit(req, 'login_failed_unknown_user', null, 'blocked');
    saveStore();
    return genericAuthFailure(res);
  }
  if (user.authScheme !== 'client-hash-v1') {
    audit(req, 'legacy_account_login_blocked', username, 'blocked');
    saveStore();
    return res.status(409).json({ success: false, legacyAccount: true, message: 'هذا الحساب أُنشئ بإصدار قديم لا يوفر E2EE server-blind. أنشئ حسابًا جديدًا في v4.5.' });
  }

  const authVerification = await verifySecretDetailed(authSecret, user.authSalt, user.authHash, user.authKdfVersion || AUTH_KDF_VERSION);
  if (!authVerification.ok) {
    recordFailedLogin(req, user);
    saveStore();
    return genericAuthFailure(res);
  }

  if (authVerification.usedPreviousPepper) {
    const upgraded = await hashSecret(authSecret);
    user.authSalt = upgraded.salt;
    user.authHash = upgraded.hash;
    user.authKdfVersion = upgraded.kdfVersion;
    audit(req, 'auth_pepper_rehashed', username, 'ok');
  }
  resetFailedLogin(user);
  if (user.totp?.enabled && user.totp.secret) {
    keepMapUnderLimit(twoFactorLoginChallenges);
    const rawLoginToken = randomToken(32);
    twoFactorLoginChallenges.set(hashText(rawLoginToken), {
      username,
      expiresAt: nowMs() + 5 * 60 * 1000,
      ipHash: requestMeta(req).ipHash,
      attempts: 0
    });
    audit(req, 'login_primary_ok_2fa_required', username, 'pending');
    saveStore();
    return res.json({ success: true, requires2fa: true, loginToken: rawLoginToken, expiresInSeconds: 300 });
  }

  const session = createSession(req, res, username);
  user.lastSeen = new Date().toISOString();
  audit(req, 'login_success', username, 'ok');
  saveStore();
  return res.json({ success: true, message: 'تم تسجيل الدخول', user: safeUser(user), csrfToken: session.csrfToken });
});

app.post('/api/auth/2fa', loginLimiter, (req, res) => {
  cleanupEphemeralChallenges();
  const loginToken = sanitizeString(req.body?.loginToken, 200);
  const code = sanitizeString(req.body?.code, 40).toUpperCase();
  if (!loginToken || !code) return res.status(400).json({ success: false, message: 'أدخل رمز التحقق' });
  const key = hashText(loginToken);
  const challenge = twoFactorLoginChallenges.get(key);
  if (!challenge || challenge.expiresAt <= nowMs()) {
    twoFactorLoginChallenges.delete(key);
    return res.status(401).json({ success: false, message: 'انتهت محاولة الدخول. سجّل الدخول من جديد.' });
  }
  if (challenge.ipHash !== requestMeta(req).ipHash) {
    twoFactorLoginChallenges.delete(key);
    return res.status(401).json({ success: false, message: 'انتهت محاولة الدخول. سجّل الدخول من جديد.' });
  }
  const user = store.users[challenge.username];
  if (!user?.totp?.enabled || !user.totp.secret) {
    twoFactorLoginChallenges.delete(key);
    return res.status(401).json({ success: false, message: 'تعذر التحقق' });
  }
  const totpResult = verifyTotpCode(user.totp.secret, code, user.totp.lastAcceptedCounter);
  const validBackup = totpResult ? false : consumeBackupCode(user, code);
  if (!totpResult && !validBackup) {
    challenge.attempts = Number(challenge.attempts || 0) + 1;
    audit(req, 'login_2fa_failed', user.username, 'blocked', { attempts: challenge.attempts });
    saveStore();
    if (challenge.attempts >= 8) twoFactorLoginChallenges.delete(key);
    return res.status(401).json({ success: false, message: challenge.attempts >= 8 ? 'انتهت محاولة التحقق. سجّل الدخول من جديد.' : 'رمز التحقق غير صحيح' });
  }
  twoFactorLoginChallenges.delete(key);
  if (totpResult) user.totp.lastAcceptedCounter = totpResult.counter;
  const session = createSession(req, res, user.username);
  user.lastSeen = new Date().toISOString();
  audit(req, validBackup ? 'login_backup_code_success' : 'login_2fa_success', user.username, 'ok');
  saveStore();
  return res.json({ success: true, message: 'تم تسجيل الدخول', user: safeUser(user), csrfToken: session.csrfToken });
});

app.post('/api/auth/logout', requireAuth, (req, res) => {
  delete store.sessions[req.auth.tokenHash];
  audit(req, 'logout', req.auth.session.username, 'ok');
  saveStore();
  clearSessionCookies(res);
  res.setHeader('Clear-Site-Data', '"cache"');
  return res.json({ success: true, message: 'تم تسجيل الخروج' });
});

app.get('/api/me', requireAuth, (req, res) => {
  if (!req.auth.user) return res.status(404).json({ success: false, message: 'المستخدم غير موجود' });
  const token = issueCsrf(req);
  saveStore();
  return res.json({ success: true, user: safeUser(req.auth.user), csrfToken: token });
});

app.patch('/api/me', requireAuth, requireCsrf, (req, res) => {
  const user = req.auth.user;
  if (!user) return res.status(404).json({ success: false, message: 'المستخدم غير موجود' });
  if (req.body?.displayName !== undefined) user.displayName = sanitizeString(req.body.displayName, 50) || null;
  if (req.body?.bio !== undefined) user.bio = sanitizeString(req.body.bio, 160) || null;
  user.lastSeen = new Date().toISOString();
  audit(req, 'profile_updated', user.username, 'ok');
  saveStore();
  return res.json({ success: true, user: safeUser(user) });
});


// ===================== End-to-end encrypted Messaging =====================
// The server stores ciphertext and RSA-wrapped per-chat AES keys. It never receives
// recovery phrases or plaintext for new v4.5 messages.
app.get('/api/e2ee/me', requireAuth, (req, res) => {
  const e2ee = req.auth.user.e2ee;
  if (!e2ee?.publicKeySpki || !e2ee?.privateKeyWrap) return res.status(409).json({ success: false, message: 'هوية E2EE غير موجودة لهذا الحساب' });
  return res.json({
    success: true,
    e2ee: {
      v: 1,
      alg: e2ee.alg,
      publicKeySpki: e2ee.publicKeySpki,
      signingPublicKeySpki: e2ee.signingPublicKeySpki,
      fingerprint: e2ee.fingerprint,
      privateKeyWrap: e2ee.privateKeyWrap
    }
  });
});

app.get('/api/users/:username/e2ee-public', requireAuth, (req, res) => {
  const username = normalizeUsername(req.params.username);
  const user = username ? store.users[username] : null;
  if (!user?.e2ee?.publicKeySpki) return res.status(404).json({ success: false, message: 'المستخدم أو مفتاح E2EE غير موجود' });
  return res.json({ success: true, user: safeDirectoryUser(user) });
});

app.get('/api/users/search', requireAuth, (req, res) => {
  const q = sanitizeString(req.query?.q, 24).toLowerCase();
  if (q.length < 2) return res.json({ success: true, users: [] });
  const users = Object.values(store.users)
    .filter((user) => user.username !== req.auth.user.username && user.e2ee?.publicKeySpki)
    .filter((user) => user.username.includes(q) || String(user.displayName || '').toLowerCase().includes(q))
    .slice(0, 20)
    .map(safeDirectoryUser);
  return res.json({ success: true, users });
});

app.get('/api/chats', requireAuth, (req, res) => {
  ensureMessagingStore();
  const chats = Object.values(store.chats)
    .filter((chat) => userCanAccessChat(chat, req.auth.user.username))
    .map((chat) => chatSummary(chat, req.auth.user.username))
    .sort((a, b) => Date.parse(b.updatedAt || b.createdAt) - Date.parse(a.updatedAt || a.createdAt));
  return res.json({ success: true, chats });
});

app.post('/api/chats/direct', requireAuth, requireCsrf, sensitiveLimiter, (req, res) => {
  const target = normalizeUsername(req.body?.username);
  if (!target || target === req.auth.user.username) return res.status(400).json({ success: false, message: 'اختر مستخدمًا آخر' });
  if (!store.users[target]?.e2ee?.publicKeySpki) return res.status(404).json({ success: false, message: 'المستخدم غير موجود أو E2EE غير مفعّل لديه' });
  if (!req.auth.user.e2ee?.publicKeySpki) return res.status(409).json({ success: false, message: 'هوية E2EE لحسابك غير جاهزة' });
  ensureMessagingStore();

  const participants = [req.auth.user.username, target].sort();
  const incoming = req.body?.keyEnvelopes || {};
  const normalizedEnvelopes = {};
  for (const username of participants) {
    const envelope = normalizeKeyEnvelope(incoming[username]);
    if (!envelope) return res.status(400).json({ success: false, message: 'مفاتيح المحادثة المشفرة غير صالحة' });
    normalizedEnvelopes[username] = envelope;
  }
  const agreement = normalizeKeyAgreement(req.body?.keyAgreement, participants, req.auth.user.username);
  if (!agreement) return res.status(400).json({ success: false, message: 'توقيع تأسيس مفتاح المحادثة غير صالح' });

  let chat = directChatBetween(req.auth.user.username, target);
  if (!chat) {
    const now = new Date().toISOString();
    const id = randomToken(18);
    chat = {
      id,
      type: 'direct',
      participants,
      createdAt: now,
      updatedAt: now,
      e2ee: { v: 1, startedAt: now, legacyMessageCount: 0, keyEnvelopes: normalizedEnvelopes, agreement }
    };
    store.chats[id] = chat;
    store.messages[id] = [];
    audit(req, 'direct_e2ee_chat_created', req.auth.user.username, 'ok');
    saveStore();
  } else if (!chat.e2ee?.keyEnvelopes) {
    const now = new Date().toISOString();
    const legacyMessageCount = Array.isArray(store.messages[chat.id]) ? store.messages[chat.id].filter((m) => m?.text).length : 0;
    chat.e2ee = { v: 1, startedAt: now, legacyMessageCount, keyEnvelopes: normalizedEnvelopes, agreement };
    chat.updatedAt = now;
    audit(req, 'direct_chat_upgraded_to_e2ee', req.auth.user.username, 'ok', { legacyMessageCount });
    saveStore();
  }
  return res.status(201).json({ success: true, chat: chatForClient(chat, req.auth.user.username) });
});

app.get('/api/chats/:id/messages', requireAuth, (req, res) => {
  ensureMessagingStore();
  const chatId = sanitizeString(req.params.id, 100);
  const chat = store.chats[chatId];
  if (!userCanAccessChat(chat, req.auth.user.username)) return res.status(404).json({ success: false, message: 'المحادثة غير موجودة' });
  const limit = clampInt(req.query?.limit, 1, 200, 100);
  const list = Array.isArray(store.messages[chatId]) ? store.messages[chatId] : [];
  const messages = list.slice(-limit).map((m) => {
    if (m?.v === 1 && m?.ct && m?.iv) {
      return { id: m.id, v: 1, alg: 'AES-256-GCM', sender: m.sender, iv: m.iv, ct: m.ct, createdAt: m.createdAt };
    }
    // Compatibility only for messages created before the E2EE upgrade.
    return { id: m.id, v: 0, legacy: true, sender: m.sender, text: m.text || '', createdAt: m.createdAt };
  });
  return res.json({ success: true, chat: chatForClient(chat, req.auth.user.username), messages });
});

app.post('/api/chats/:id/messages', requireAuth, requireCsrf, messageLimiter, (req, res) => {
  ensureMessagingStore();
  const chatId = sanitizeString(req.params.id, 100);
  const chat = store.chats[chatId];
  if (!userCanAccessChat(chat, req.auth.user.username)) return res.status(404).json({ success: false, message: 'المحادثة غير موجودة' });
  if (!chat.e2ee?.keyEnvelopes?.[req.auth.user.username]) return res.status(409).json({ success: false, message: 'المحادثة غير جاهزة للتشفير الطرفي' });

  const id = sanitizeString(req.body?.id, 64);
  const iv = normalizeB64Url(req.body?.iv, 12, 12);
  const ct = normalizeB64Url(req.body?.ct, 17, 20000);
  if (!/^[A-Za-z0-9_-]{20,40}$/.test(id) || !iv || !ct || req.body?.v !== 1 || req.body?.alg !== 'AES-256-GCM') {
    return res.status(400).json({ success: false, message: 'صيغة الرسالة المشفرة غير صالحة' });
  }
  if (!Array.isArray(store.messages[chatId])) store.messages[chatId] = [];
  if (store.messages[chatId].some((m) => m.id === id)) return res.status(409).json({ success: false, message: 'معرّف الرسالة مستخدم بالفعل' });

  const message = {
    id,
    v: 1,
    alg: 'AES-256-GCM',
    sender: req.auth.user.username,
    iv: iv.text,
    ct: ct.text,
    createdAt: new Date().toISOString()
  };
  store.messages[chatId].push(message);
  if (store.messages[chatId].length > 5000) store.messages[chatId].splice(0, store.messages[chatId].length - 5000);
  chat.updatedAt = message.createdAt;
  saveStore();
  return res.status(201).json({ success: true, message: { id: message.id, v: 1, sender: message.sender, createdAt: message.createdAt } });
});

app.get('/api/security/sessions', requireAuth, sensitiveLimiter, (req, res) => {
  const list = activeSessionsFor(req.auth.session.username)
    .sort((a, b) => b.lastSeenAt - a.lastSeenAt)
    .map((s) => ({
      id: s.id,
      label: s.label,
      createdAt: new Date(s.createdAt).toISOString(),
      lastSeenAt: new Date(s.lastSeenAt).toISOString(),
      current: s.tokenHash === req.auth.tokenHash,
      locked: Boolean(s.locked)
    }));
  return res.json({ success: true, sessions: list, maxDevices: MAX_DEVICES });
});

app.delete('/api/security/sessions/:id', requireAuth, requireCsrf, sensitiveLimiter, (req, res) => {
  const targetId = sanitizeString(req.params.id, 100);
  let removedCurrent = false;
  let found = false;
  for (const [tokenHash, s] of Object.entries(store.sessions)) {
    if (s.username === req.auth.session.username && s.id === targetId) {
      removedCurrent = tokenHash === req.auth.tokenHash;
      delete store.sessions[tokenHash];
      found = true;
      break;
    }
  }
  if (!found) return res.status(404).json({ success: false, message: 'الجهاز غير موجود' });
  audit(req, 'session_revoked', req.auth.session.username, 'ok', { self: removedCurrent });
  saveStore();
  if (removedCurrent) clearSessionCookies(res);
  return res.json({ success: true, loggedOut: removedCurrent });
});

app.post('/api/security/sessions/revoke-others', requireAuth, requireCsrf, sensitiveLimiter, (req, res) => {
  let count = 0;
  for (const [tokenHash, s] of Object.entries(store.sessions)) {
    if (s.username === req.auth.session.username && tokenHash !== req.auth.tokenHash) {
      delete store.sessions[tokenHash];
      count += 1;
    }
  }
  audit(req, 'other_sessions_revoked', req.auth.session.username, 'ok', { count });
  saveStore();
  return res.json({ success: true, revoked: count });
});

app.post('/api/security/totp/setup', requireAuth, requireCsrf, sensitiveLimiter, async (req, res) => {
  const authSecret = normalizeAuthSecret(req.body?.authSecret);
  const user = req.auth.user;
  if (!(await verifyUserAuthSecret(user, authSecret))) {
    return res.status(401).json({ success: false, message: 'مفتاح الاسترداد غير صحيح' });
  }
  const secret = base32Encode(crypto.randomBytes(20));
  user.totp = user.totp || {};
  user.totp.pendingSecret = secret;
  const issuer = encodeURIComponent('Yeznsap');
  const label = encodeURIComponent(`Yeznsap:${user.username}`);
  const otpauthUri = `otpauth://totp/${label}?secret=${secret}&issuer=${issuer}&algorithm=SHA1&digits=6&period=30`;
  audit(req, 'totp_setup_started', user.username, 'ok');
  saveStore();
  return res.json({ success: true, secret, otpauthUri });
});

app.post('/api/security/totp/confirm', requireAuth, requireCsrf, sensitiveLimiter, (req, res) => {
  const code = sanitizeString(req.body?.code, 20);
  const user = req.auth.user;
  const secret = user.totp?.pendingSecret;
  const totpResult = secret ? verifyTotpCode(secret, code, null) : null;
  if (!secret || !totpResult) return res.status(400).json({ success: false, message: 'رمز TOTP غير صحيح' });
  const backupCodes = generateBackupCodes();
  user.totp.enabled = true;
  user.totp.secret = secret;
  user.totp.pendingSecret = null;
  user.totp.backupCodeHashes = backupCodes.map(backupCodeHash);
  user.totp.lastAcceptedCounter = totpResult.counter;
  audit(req, 'totp_enabled', user.username, 'ok');
  saveStore();
  return res.json({ success: true, backupCodes });
});

app.post('/api/security/totp/disable', requireAuth, requireCsrf, sensitiveLimiter, async (req, res) => {
  const authSecret = normalizeAuthSecret(req.body?.authSecret);
  const code = sanitizeString(req.body?.code, 40).toUpperCase();
  const user = req.auth.user;
  if (!(await verifyUserAuthSecret(user, authSecret))) return res.status(401).json({ success: false, message: 'مفتاح الاسترداد غير صحيح' });
  const totpResult = user.totp?.secret ? verifyTotpCode(user.totp.secret, code, user.totp.lastAcceptedCounter) : null;
  const validBackup = totpResult ? false : consumeBackupCode(user, code);
  if (!totpResult && !validBackup) return res.status(401).json({ success: false, message: 'رمز التحقق غير صحيح' });
  user.totp = { enabled: false, secret: null, pendingSecret: null, backupCodeHashes: [], lastAcceptedCounter: null };
  audit(req, 'totp_disabled', user.username, 'ok');
  saveStore();
  return res.json({ success: true });
});

app.post('/api/security/pin', requireAuth, requireCsrf, sensitiveLimiter, async (req, res) => {
  const authSecret = normalizeAuthSecret(req.body?.authSecret);
  const pin = sanitizeString(req.body?.pin, 12);
  const user = req.auth.user;
  if (!/^\d{6,10}$/.test(pin)) return res.status(400).json({ success: false, message: 'الـPIN يجب أن يكون 6 إلى 10 أرقام' });
  if (!(await verifyUserAuthSecret(user, authSecret))) return res.status(401).json({ success: false, message: 'مفتاح الاسترداد غير صحيح' });
  user.pin = await hashSecret(`pin:${pin}`);
  audit(req, 'pin_enabled', user.username, 'ok');
  saveStore();
  return res.json({ success: true });
});

app.delete('/api/security/pin', requireAuth, requireCsrf, sensitiveLimiter, async (req, res) => {
  const authSecret = normalizeAuthSecret(req.body?.authSecret);
  const user = req.auth.user;
  if (!(await verifyUserAuthSecret(user, authSecret))) return res.status(401).json({ success: false, message: 'مفتاح الاسترداد غير صحيح' });
  user.pin = null;
  req.auth.session.locked = false;
  audit(req, 'pin_disabled', user.username, 'ok');
  saveStore();
  return res.json({ success: true });
});

app.post('/api/security/lock', requireAuth, requireCsrf, sensitiveLimiter, (req, res) => {
  if (!req.auth.user.pin?.hash) return res.status(400).json({ success: false, message: 'فعّل PIN أولًا' });
  req.auth.session.locked = true;
  audit(req, 'session_locked', req.auth.user.username, 'ok');
  saveStore();
  return res.json({ success: true, locked: true });
});

app.post('/api/security/unlock', requireAuth, sensitiveLimiter, async (req, res) => {
  const pin = sanitizeString(req.body?.pin, 12);
  const user = req.auth.user;
  const session = req.auth.session;
  if (!user.pin?.hash) return res.status(400).json({ success: false, message: 'PIN غير مفعّل' });
  if (session.pinNextAttemptAt && session.pinNextAttemptAt > nowMs()) {
    const retryAfter = Math.max(1, Math.ceil((session.pinNextAttemptAt - nowMs()) / 1000));
    res.setHeader('Retry-After', String(retryAfter));
    return res.status(429).json({ success: false, message: 'محاولات PIN كثيرة. حاول بعد قليل.' });
  }
  const pinVerification = await verifySecretDetailed(`pin:${pin}`, user.pin.salt, user.pin.hash, user.pin.kdfVersion || AUTH_KDF_VERSION);
  if (!pinVerification.ok) {
    session.pinFailedCount = Number(session.pinFailedCount || 0) + 1;
    const seconds = session.pinFailedCount < 4 ? 0 : Math.min(60, 2 ** Math.min(6, session.pinFailedCount - 4));
    session.pinNextAttemptAt = seconds ? nowMs() + seconds * 1000 : null;
    audit(req, 'pin_unlock_failed', user.username, 'blocked', { attempts: session.pinFailedCount, backoffSeconds: seconds });
    if (session.pinFailedCount >= 10) {
      delete store.sessions[req.auth.tokenHash];
      saveStore();
      clearSessionCookies(res);
      return res.status(401).json({ success: false, message: 'تم إنهاء هذه الجلسة بعد محاولات PIN فاشلة كثيرة.' });
    }
    saveStore();
    return res.status(401).json({ success: false, message: 'PIN غير صحيح' });
  }
  if (pinVerification.usedPreviousPepper) {
    user.pin = await hashSecret(`pin:${pin}`);
    audit(req, 'pin_pepper_rehashed', user.username, 'ok');
  }
  session.pinFailedCount = 0;
  session.pinNextAttemptAt = null;
  session.locked = false;
  const token = issueCsrf(req);
  audit(req, 'session_unlocked', user.username, 'ok');
  saveStore();
  return res.json({ success: true, csrfToken: token });
});

app.patch('/api/security/privacy', requireAuth, requireCsrf, sensitiveLimiter, (req, res) => {
  const current = normalizePrivacy(req.auth.user.privacy);
  const allowed = new Set(['everyone', 'contacts', 'nobody']);
  const next = { ...current };
  for (const field of ['lastSeen', 'statusVisibility', 'profilePhoto']) {
    if (req.body?.[field] !== undefined) {
      if (!allowed.has(req.body[field])) return res.status(400).json({ success: false, message: `قيمة ${field} غير صالحة` });
      next[field] = req.body[field];
    }
  }
  if (req.body?.readReceipts !== undefined) next.readReceipts = Boolean(req.body.readReceipts);
  req.auth.user.privacy = next;
  if (req.body?.autoDeleteInactiveDays !== undefined) {
    const raw = req.body.autoDeleteInactiveDays;
    const normalized = normalizeAutoDeleteDays(raw);
    if (!(raw === null || raw === 'never' || raw === 0 || [30, 90, 180, 365].includes(Number(raw)))) {
      return res.status(400).json({ success: false, message: 'مدة حذف الحساب غير صالحة' });
    }
    req.auth.user.autoDeleteInactiveDays = normalized;
  }
  audit(req, 'privacy_updated', req.auth.user.username, 'ok');
  saveStore();
  return res.json({ success: true, user: safeUser(req.auth.user) });
});

app.get('/api/security/audit', requireAuth, sensitiveLimiter, (req, res) => {
  const usernameHash = keyedHash(req.auth.user.username, 'username');
  const events = store.audit
    .filter((e) => e.usernameHash === usernameHash)
    .slice(-50)
    .reverse()
    .map((e) => ({ ts: e.ts, action: e.action, outcome: e.outcome }));
  return res.json({ success: true, events });
});

function accountExport(user) {
  ensureMessagingStore();
  const usernameHash = keyedHash(user.username, 'username');
  const devices = activeSessionsFor(user.username).map((s) => ({
    id: s.id,
    label: s.label,
    createdAt: new Date(s.createdAt).toISOString(),
    lastSeenAt: new Date(s.lastSeenAt).toISOString(),
    locked: Boolean(s.locked)
  }));
  const securityEvents = store.audit
    .filter((event) => event.usernameHash === usernameHash)
    .slice(-100)
    .map((event) => ({ ts: event.ts, action: event.action, outcome: event.outcome }));
  const chats = Object.values(store.chats)
    .filter((chat) => userCanAccessChat(chat, user.username))
    .map((chat) => ({
      id: chat.id,
      type: chat.type,
      participants: chat.participants,
      createdAt: chat.createdAt,
      updatedAt: chat.updatedAt,
      messages: (store.messages[chat.id] || []).map((m) => ({ id: m.id, sender: m.sender, text: m.text, createdAt: m.createdAt }))
    }));
  return {
    exportedAt: new Date().toISOString(),
    service: 'Yeznsap',
    exportType: 'encrypted-data-export-not-account-recovery',
    account: {
      username: user.username,
      displayName: user.displayName || null,
      bio: user.bio || null,
      createdAt: user.createdAt,
      lastSeen: user.lastSeen,
      privacy: normalizePrivacy(user.privacy),
      autoDeleteInactiveDays: normalizeAutoDeleteDays(user.autoDeleteInactiveDays),
      twoFactorEnabled: Boolean(user.totp?.enabled),
      pinEnabled: Boolean(user.pin?.hash),
      recoveryWordCount: user.recoveryWordCount || user.phraseWordCount || 16,
      e2eeFingerprint: user.e2ee?.fingerprint || null
    },
    devices,
    securityEvents,
    chats
  };
}

app.get('/api/account/export', requireAuth, sensitiveLimiter, (req, res) => {
  audit(req, 'account_export_plain', req.auth.user.username, 'ok');
  saveStore();
  return res.json({ success: true, data: accountExport(req.auth.user) });
});

app.post('/api/account/export-encrypted', requireAuth, requireCsrf, sensitiveLimiter, async (req, res) => {
  const password = sanitizeString(req.body?.password, 200);
  if (password.length < 16) return res.status(400).json({ success: false, message: 'استخدم كلمة مرور تصدير بطول 16 حرفًا على الأقل' });
  const salt = crypto.randomBytes(16);
  const exportKey = await withKdfSlot(async () => Buffer.from(await scryptAsync(password, salt, 32, { N: 131072, r: 8, p: 1, maxmem: 192 * 1024 * 1024 })));
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', exportKey, iv, { authTagLength: 16 });
  cipher.setAAD(Buffer.from('yeznsap-account-export-v1'));
  const plaintext = Buffer.from(JSON.stringify(accountExport(req.auth.user)), 'utf8');
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  exportKey.fill(0);
  audit(req, 'account_export_encrypted', req.auth.user.username, 'ok');
  saveStore();
  return res.json({
    success: true,
    backup: {
      v: 1,
      kdf: 'scrypt-N131072-r8-p1',
      alg: 'AES-256-GCM',
      salt: salt.toString('base64'),
      iv: iv.toString('base64'),
      tag: tag.toString('base64'),
      ct: ct.toString('base64')
    }
  });
});

app.delete('/api/account', requireAuth, requireCsrf, sensitiveLimiter, async (req, res) => {
  const authSecret = normalizeAuthSecret(req.body?.authSecret);
  const user = req.auth.user;
  if (!(await verifyUserAuthSecret(user, authSecret))) return res.status(401).json({ success: false, message: 'مفتاح الاسترداد غير صحيح' });
  const username = user.username;
  const deletedUserHash = keyedHash(username, 'username');
  delete store.users[username];
  for (const [tokenHash, s] of Object.entries(store.sessions)) if (s.username === username) delete store.sessions[tokenHash];
  removeUserMessagingData(username);
  // Right-to-deletion: remove prior user-correlated audit events instead of retaining a stable pseudonymous identifier.
  store.audit = store.audit.filter((event) => event.usernameHash !== deletedUserHash);
  store.audit.push({ ts: new Date().toISOString(), action: 'account_deleted', usernameHash: null, outcome: 'ok' });
  saveStore();
  clearSessionCookies(res);
  res.setHeader('Clear-Site-Data', '"cache", "cookies", "storage"');
  return res.json({ success: true, message: 'تم حذف الحساب نهائيًا' });
});

app.get('/api/health', (_req, res) => {
  if (IS_PROD) return res.json({ status: 'ok' });
  return res.json({
    status: 'ok',
    service: 'Yeznsap E2EE Messenger v4.5',
    atRestEncryption: 'AES-256-GCM',
    sessionModel: 'opaque-server-side-device-bound',
    messaging: 'direct-e2ee-text-messaging-enabled',
    e2ee: 'AES-256-GCM messages + RSA-OAEP-3072 wrapped chat keys',
    time: new Date().toISOString()
  });
});

app.use((err, req, res, _next) => {
  if (err?.code === 'KDF_BUSY') {
    res.setHeader('Retry-After', '2');
    return res.status(503).json({ success: false, message: 'خدمة المصادقة مشغولة مؤقتًا. حاول بعد ثوانٍ قليلة.' });
  }
  console.error('[Unhandled Error]', err?.message || err);
  audit(req, 'unhandled_error', req.auth?.user?.username || null, 'error');
  try { saveStore(); } catch { /* ignore secondary failure */ }
  res.status(500).json({ success: false, message: 'حدث خطأ داخلي' });
});

saveStore();
cleanupInactiveAccounts();
setInterval(() => {
  cleanupEphemeralChallenges();
  cleanupInactiveAccounts();
}, 6 * 60 * 60 * 1000).unref();

if (require.main === module) {
  const server = app.listen(PORT, () => {
    console.log(`Yeznsap secure server running on http://localhost:${PORT}`);
    if (!IS_PROD) console.log('Development mode: use HTTPS in production.');
  });

  let shuttingDown = false;
  const gracefulShutdown = (signal) => {
    if (shuttingDown) return;
    shuttingDown = true;
    console.log(`${signal} received; finishing active requests.`);
    server.close(() => {
      try { saveStore(); } catch (error) { console.error('Final store save failed:', error.message); }
      try { DATA_KEY.fill(0); } catch { /* best effort */ }
      try { STORE_KEY.fill(0); } catch { /* best effort */ }
      if (INDEX_HMAC_KEY !== DATA_KEY) { try { INDEX_HMAC_KEY.fill(0); } catch { /* best effort */ } }
      process.exit(0);
    });
    setTimeout(() => process.exit(1), 10_000).unref();
  };
  process.once('SIGTERM', () => gracefulShutdown('SIGTERM'));
  process.once('SIGINT', () => gracefulShutdown('SIGINT'));
}

module.exports = {
  app,
  __test: {
    normalizeUsername,
    normalizePhrase,
    normalizeAuthSecret,
    normalizeE2eeBundle,
    normalizeKeyEnvelope,
    normalizeKeyAgreement,
    keyAgreementStatement,
    generatePhrase,
    confirmationPositions,
    encryptEnvelope,
    decryptEnvelope,
    verifyTotpCode,
    totpCode,
    blankStore,
    NEW_RECOVERY_WORD_COUNT,
    WORDS
  }
};
