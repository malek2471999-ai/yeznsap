// =====================================================
// Yeznsap Frontend — Secure Username + Recovery Key
// =====================================================

const API_BASE = '';
let generatedPhrase = '';
let registrationConfirmPositions = [];
let pendingLoginPhrase = '';
let localIdentity = null;
let activeChatInfo = null;
const chatKeyCache = new Map();
let twoFactorLoginToken = '';
let csrfToken = '';
let currentUser = null;
let lastBackupCodes = [];
let activeChatId = null;
let activeChatOther = null;
let cachedChats = [];
let messagingPollId = null;
let chatSearchTimer = null;

const screens = {
  login: document.getElementById('login-screen'),
  twofa: document.getElementById('twofa-screen'),
  register: document.getElementById('register-screen'),
  main: document.getElementById('main-screen')
};

const els = {
  loginUsername: document.getElementById('login-username'),
  loginPhrase: document.getElementById('login-phrase'),
  btnToggleLoginPhrase: document.getElementById('btn-toggle-login-phrase'),
  btnLogin: document.getElementById('btn-login'),
  loginError: document.getElementById('login-error'),
  btnOpenRegister: document.getElementById('btn-open-register'),

  twofaCode: document.getElementById('twofa-code'),
  twofaError: document.getElementById('twofa-error'),
  btnTwofaVerify: document.getElementById('btn-twofa-verify'),
  btnTwofaCancel: document.getElementById('btn-twofa-cancel'),

  registerUsername: document.getElementById('register-username'),
  btnGeneratePhrase: document.getElementById('btn-generate-phrase'),
  btnRegeneratePhrase: document.getElementById('btn-regenerate-phrase'),
  phrasePanel: document.getElementById('phrase-panel'),
  phraseGrid: document.getElementById('phrase-grid'),
  btnCopyPhrase: document.getElementById('btn-copy-phrase'),
  phraseSaved: document.getElementById('phrase-saved'),
  phraseConfirmBox: document.getElementById('phrase-confirm-box'),
  phraseConfirmInputs: document.getElementById('phrase-confirm-inputs'),
  ageConfirmed: document.getElementById('age-confirmed'),
  btnRegister: document.getElementById('btn-register'),
  registerError: document.getElementById('register-error'),
  btnBackLogin: document.getElementById('btn-back-login'),

  btnLogout: document.getElementById('btn-logout'),
  sidebarAvatarText: document.getElementById('sidebar-avatar-text'),
  toastContainer: document.getElementById('toast-container'),
  chatSearch: document.getElementById('chat-search'),
  conversationsList: document.getElementById('conversations-list'),
  emptyConversations: document.getElementById('empty-conversations'),
  btnStartChat: document.getElementById('btn-start-chat'),
  btnNewChatSidebar: document.getElementById('btn-new-chat-sidebar'),
  btnNewChatHeader: document.getElementById('btn-new-chat-header'),
  btnFocusChatSearch: document.getElementById('btn-focus-chat-search'),
  chatWindow: document.getElementById('chat-window'),

  btnSecuritySettings: document.getElementById('btn-security-settings'),
  securityModal: document.getElementById('security-modal'),
  securityBackdrop: document.getElementById('security-backdrop'),
  btnCloseSecurity: document.getElementById('btn-close-security'),
  sessionsList: document.getElementById('sessions-list'),
  btnRevokeOthers: document.getElementById('btn-revoke-others'),
  status2fa: document.getElementById('status-2fa'),

  totpDisabledBox: document.getElementById('totp-disabled-box'),
  totpSetupBox: document.getElementById('totp-setup-box'),
  totpEnabledBox: document.getElementById('totp-enabled-box'),
  totpPhrase: document.getElementById('totp-phrase'),
  btnTotpSetup: document.getElementById('btn-totp-setup'),
  totpSecret: document.getElementById('totp-secret'),
  totpConfirmCode: document.getElementById('totp-confirm-code'),
  btnTotpConfirm: document.getElementById('btn-totp-confirm'),
  totpDisablePhrase: document.getElementById('totp-disable-phrase'),
  totpDisableCode: document.getElementById('totp-disable-code'),
  btnTotpDisable: document.getElementById('btn-totp-disable'),
  backupCodesBox: document.getElementById('backup-codes-box'),
  backupCodes: document.getElementById('backup-codes'),
  btnCopyBackupCodes: document.getElementById('btn-copy-backup-codes'),

  pinPhrase: document.getElementById('pin-phrase'),
  pinValue: document.getElementById('pin-value'),
  btnSetPin: document.getElementById('btn-set-pin'),
  btnLockNow: document.getElementById('btn-lock-now'),
  btnRemovePin: document.getElementById('btn-remove-pin'),
  pinLockOverlay: document.getElementById('pin-lock-overlay'),
  unlockPin: document.getElementById('unlock-pin'),
  btnUnlockPin: document.getElementById('btn-unlock-pin'),
  btnLockLogout: document.getElementById('btn-lock-logout'),

  privacyLastSeen: document.getElementById('privacy-last-seen'),
  privacyProfilePhoto: document.getElementById('privacy-profile-photo'),
  privacyStatus: document.getElementById('privacy-status'),
  privacyAutoDelete: document.getElementById('privacy-auto-delete'),
  privacyReadReceipts: document.getElementById('privacy-read-receipts'),
  btnSavePrivacy: document.getElementById('btn-save-privacy'),

  exportPassword: document.getElementById('export-password'),
  btnExportEncrypted: document.getElementById('btn-export-encrypted'),
  deletePhrase: document.getElementById('delete-phrase'),
  btnDeleteAccount: document.getElementById('btn-delete-account')
};

function showScreen(name) {
  Object.values(screens).forEach((screen) => screen?.classList.remove('active'));
  screens[name]?.classList.add('active');
}

function showToast(message, type = 'info') {
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.textContent = message;
  els.toastContainer.appendChild(toast);
  setTimeout(() => {
    toast.classList.add('toast-hide');
    setTimeout(() => toast.remove(), 300);
  }, 4200);
}

function setLoading(button, loading) {
  if (!button) return;
  const text = button.querySelector('.btn-text');
  const loader = button.querySelector('.btn-loader');
  if (loading) {
    text?.classList.add('hidden');
    loader?.classList.remove('hidden');
    button.disabled = true;
  } else {
    text?.classList.remove('hidden');
    loader?.classList.add('hidden');
  }
}

function showError(element, message) {
  if (!element) return;
  element.textContent = message;
  element.classList.remove('hidden');
}

function hideError(element) {
  if (!element) return;
  element.classList.add('hidden');
  element.textContent = '';
}

function normalizeUsername(value) {
  return (value || '').trim().toLowerCase();
}

function validUsername(value) {
  const username = normalizeUsername(value);
  return /^[a-z0-9](?:[a-z0-9._]{1,22}[a-z0-9])?$/.test(username);
}

function normalizePhrase(value) {
  return (value || '').toLowerCase().trim().split(/\s+/).filter(Boolean).join(' ');
}

function validPhrase(value) {
  const words = normalizePhrase(value).split(' ').filter(Boolean);
  return words.length === 16 && words.every((word) => /^[a-z]+$/.test(word));
}

function validNewPhrase(value) {
  const words = normalizePhrase(value).split(' ').filter(Boolean);
  return words.length === 16 && words.every((word) => /^[a-z]+$/.test(word));
}

const RECOVERY_WORDS = Object.freeze([
  'amber',
  'anchor',
  'apple',
  'arrow',
  'artist',
  'atlas',
  'aurora',
  'autumn',
  'bamboo',
  'beacon',
  'berry',
  'bicycle',
  'blossom',
  'bridge',
  'breeze',
  'brook',
  'cactus',
  'candle',
  'canyon',
  'cedar',
  'cherry',
  'circle',
  'cloud',
  'cobalt',
  'comet',
  'coral',
  'cotton',
  'crystal',
  'dawn',
  'delta',
  'desert',
  'dolphin',
  'dream',
  'drift',
  'eagle',
  'earth',
  'echo',
  'ember',
  'emerald',
  'falcon',
  'feather',
  'field',
  'firefly',
  'forest',
  'fossil',
  'frost',
  'galaxy',
  'garden',
  'glacier',
  'gold',
  'harbor',
  'hazel',
  'honey',
  'horizon',
  'island',
  'ivory',
  'jasmine',
  'jungle',
  'kettle',
  'lagoon',
  'lantern',
  'lavender',
  'leaf',
  'lemon',
  'lilac',
  'lotus',
  'lunar',
  'maple',
  'marble',
  'meadow',
  'meteor',
  'mint',
  'mirror',
  'mist',
  'moon',
  'moss',
  'mountain',
  'nebula',
  'nectar',
  'night',
  'oasis',
  'ocean',
  'olive',
  'opal',
  'orchid',
  'palm',
  'peach',
  'pearl',
  'pebble',
  'pepper',
  'pine',
  'planet',
  'plum',
  'pond',
  'prairie',
  'quartz',
  'rain',
  'raven',
  'reef',
  'river',
  'rose',
  'ruby',
  'saffron',
  'sage',
  'sand',
  'scarlet',
  'shadow',
  'shell',
  'silver',
  'sky',
  'snow',
  'solar',
  'sparrow',
  'spring',
  'star',
  'stone',
  'storm',
  'sunset',
  'surf',
  'teal',
  'thunder',
  'tiger',
  'timber',
  'topaz',
  'trail',
  'tulip',
  'valley',
  'velvet',
  'violet',
  'water',
  'willow',
  'wind',
  'winter',
  'wood',
  'acorn',
  'alpine',
  'apricot',
  'badger',
  'bay',
  'birch',
  'bluebird',
  'bramble',
  'bronze',
  'butterfly',
  'cascade',
  'chestnut',
  'clover',
  'copper',
  'crane',
  'daisy',
  'dune',
  'elm',
  'fern',
  'finch',
  'flame',
  'fox',
  'granite',
  'grape',
  'grove',
  'hawk',
  'heather',
  'heron',
  'indigo',
  'iris',
  'jade',
  'juniper',
  'kiwi',
  'lake',
  'lark',
  'lime',
  'magnolia',
  'mango',
  'marigold',
  'mercury',
  'mesa',
  'midnight',
  'mulberry',
  'north',
  'oak',
  'onyx',
  'orange',
  'otter',
  'papaya',
  'petal',
  'phoenix',
  'poppy',
  'rainbow',
  'redwood',
  'robin',
  'sapphire',
  'savanna',
  'sequoia',
  'shore',
  'spruce',
  'sunrise',
  'swift',
  'tangerine',
  'terra',
  'thorn',
  'tide',
  'umber',
  'wave',
  'wren',
  'yucca',
  'zephyr',
  'acacia',
  'aster',
  'azalea',
  'basil',
  'bluejay',
  'carnation',
  'citron',
  'cypress',
  'dahlia',
  'egret',
  'fig',
  'fir',
  'ginger',
  'irisfield',
  'kelp',
  'laurel',
  'lichen',
  'mimosa',
  'myrtle',
  'nutmeg',
  'pansy',
  'pinecone',
  'primrose',
  'reed',
  'rosemary',
  'seashell',
  'sorrel',
  'sumac',
  'thyme',
  'truffle',
  'walnut',
  'waterfall',
  'wildflower',
  'yarrow',
  'zinnia',
  'aviary',
  'brookside',
  'capri',
  'citrine',
  'cosmos',
  'evergreen',
  'harvest',
  'haven',
  'marina',
  'monsoon',
  'mosaic',
  'orchard',
  'paradise',
  'peony',
  'ripple',
  'solstice'
]);
const E2EE_WRAP_ITERATIONS = 600000;
const encoder = new TextEncoder();
const decoder = new TextDecoder();

function randomBytes(length) {
  const out = new Uint8Array(length);
  crypto.getRandomValues(out);
  return out;
}

function bytesToB64Url(value) {
  const bytes = value instanceof Uint8Array ? value : new Uint8Array(value);
  let binary = '';
  for (let i = 0; i < bytes.length; i += 0x8000) binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function b64UrlToBytes(value) {
  const text = String(value || '').replace(/-/g, '+').replace(/_/g, '/');
  const padded = text + '='.repeat((4 - (text.length % 4)) % 4);
  const binary = atob(padded);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) out[i] = binary.charCodeAt(i);
  return out;
}

async function sha256Bytes(value) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', value));
}

async function deriveAuthSecret(phrase) {
  const normalized = normalizePhrase(phrase);
  const digest = await sha256Bytes(encoder.encode(`Yeznsap Authentication v1\0${normalized}`));
  return bytesToB64Url(digest);
}

function concatBytes(...parts) {
  const arrays = parts.map((part) => part instanceof Uint8Array ? part : new Uint8Array(part));
  const total = arrays.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of arrays) { out.set(part, offset); offset += part.length; }
  return out;
}

async function fingerprintIdentity(publicKeySpki, signingPublicKeySpki) {
  const material = concatBytes(
    encoder.encode('yeznsap-e2ee-identity-v1\0'),
    b64UrlToBytes(publicKeySpki),
    encoder.encode('\0signing\0'),
    b64UrlToBytes(signingPublicKeySpki)
  );
  const digest = await sha256Bytes(material);
  return [...digest].map((b) => b.toString(16).padStart(2, '0')).join('').toUpperCase();
}

function formatFingerprint(value) {
  const clean = String(value || '').replace(/[^A-Fa-f0-9]/g, '').toUpperCase();
  return clean.match(/.{1,4}/g)?.join(' ') || clean;
}

async function derivePrivateWrapKey(phrase, salt, iterations = E2EE_WRAP_ITERATIONS) {
  const material = await crypto.subtle.importKey(
    'raw',
    encoder.encode(`Yeznsap E2EE private-key wrap v1\0${normalizePhrase(phrase)}`),
    'PBKDF2',
    false,
    ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function createE2eeIdentityBundle(phrase) {
  const [encryptionPair, signingPair] = await Promise.all([
    crypto.subtle.generateKey(
      { name: 'RSA-OAEP', modulusLength: 3072, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
      true,
      ['encrypt', 'decrypt']
    ),
    crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify']
    )
  ]);
  const [spki, pkcs8, signingSpki, signingPkcs8] = await Promise.all([
    crypto.subtle.exportKey('spki', encryptionPair.publicKey),
    crypto.subtle.exportKey('pkcs8', encryptionPair.privateKey),
    crypto.subtle.exportKey('spki', signingPair.publicKey),
    crypto.subtle.exportKey('pkcs8', signingPair.privateKey)
  ]);
  const privatePayload = encoder.encode(JSON.stringify({
    rsaPkcs8: bytesToB64Url(new Uint8Array(pkcs8)),
    signingPkcs8: bytesToB64Url(new Uint8Array(signingPkcs8))
  }));
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const wrapKey = await derivePrivateWrapKey(phrase, salt);
  const aad = encoder.encode('yeznsap-e2ee-private-v1');
  const wrapped = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad }, wrapKey, privatePayload));
  privatePayload.fill(0);

  const privateKey = await crypto.subtle.importKey('pkcs8', pkcs8, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['decrypt']);
  const signingPrivateKey = await crypto.subtle.importKey('pkcs8', signingPkcs8, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  const publicKeySpki = bytesToB64Url(new Uint8Array(spki));
  const signingPublicKeySpki = bytesToB64Url(new Uint8Array(signingSpki));
  const fingerprint = await fingerprintIdentity(publicKeySpki, signingPublicKeySpki);
  return {
    identity: { privateKey, signingPrivateKey, publicKeySpki, signingPublicKeySpki, fingerprint },
    bundle: {
      v: 1,
      alg: 'RSA-OAEP-3072-SHA256+ECDSA-P256-SHA256',
      publicKeySpki,
      signingPublicKeySpki,
      privateKeyWrap: {
        v: 1,
        alg: 'AES-256-GCM',
        kdf: 'PBKDF2-SHA256',
        iterations: E2EE_WRAP_ITERATIONS,
        salt: bytesToB64Url(salt),
        iv: bytesToB64Url(iv),
        ct: bytesToB64Url(wrapped)
      }
    }
  };
}

async function unlockE2eeIdentity(phrase, bundle) {
  if (!bundle?.publicKeySpki || !bundle?.signingPublicKeySpki || !bundle?.privateKeyWrap) throw new Error('E2EE identity bundle missing');
  const wrap = bundle.privateKeyWrap;
  const wrapKey = await derivePrivateWrapKey(phrase, b64UrlToBytes(wrap.salt), Number(wrap.iterations));
  const aad = encoder.encode('yeznsap-e2ee-private-v1');
  const privatePayloadBytes = new Uint8Array(await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: b64UrlToBytes(wrap.iv), additionalData: aad },
    wrapKey,
    b64UrlToBytes(wrap.ct)
  ));
  let privatePayload;
  try { privatePayload = JSON.parse(decoder.decode(privatePayloadBytes)); }
  finally { privatePayloadBytes.fill(0); }
  if (!privatePayload?.rsaPkcs8 || !privatePayload?.signingPkcs8) throw new Error('E2EE private key payload invalid');
  const rsaPkcs8 = b64UrlToBytes(privatePayload.rsaPkcs8);
  const signingPkcs8 = b64UrlToBytes(privatePayload.signingPkcs8);
  const privateKey = await crypto.subtle.importKey('pkcs8', rsaPkcs8, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['decrypt']);
  const signingPrivateKey = await crypto.subtle.importKey('pkcs8', signingPkcs8, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  rsaPkcs8.fill(0);
  signingPkcs8.fill(0);

  const publicKey = await crypto.subtle.importKey('spki', b64UrlToBytes(bundle.publicKeySpki), { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt']);
  const signingPublicKey = await crypto.subtle.importKey('spki', b64UrlToBytes(bundle.signingPublicKeySpki), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
  const test = randomBytes(32);
  const cipher = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, publicKey, test);
  const plain = new Uint8Array(await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, privateKey, cipher));
  if (plain.length !== test.length || plain.some((b, i) => b !== test[i])) throw new Error('E2EE encryption key pair mismatch');
  const signTest = encoder.encode('yeznsap-signing-key-test-v1');
  const signature = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, signingPrivateKey, signTest);
  if (!(await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, signingPublicKey, signature, signTest))) throw new Error('E2EE signing key pair mismatch');
  const fingerprint = await fingerprintIdentity(bundle.publicKeySpki, bundle.signingPublicKeySpki);
  if (bundle.fingerprint && fingerprint !== String(bundle.fingerprint).toUpperCase()) throw new Error('E2EE fingerprint mismatch');
  return { privateKey, signingPrivateKey, publicKeySpki: bundle.publicKeySpki, signingPublicKeySpki: bundle.signingPublicKeySpki, fingerprint };
}

const CRYPTO_DB_NAME = 'yeznsap-e2ee-v1';
function openCryptoDb() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(CRYPTO_DB_NAME, 1);
    request.onupgradeneeded = () => {
      if (!request.result.objectStoreNames.contains('kv')) request.result.createObjectStore('kv');
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error || new Error('IndexedDB failed'));
  });
}

async function cryptoDbGet(key) {
  const db = await openCryptoDb();
  try {
    return await new Promise((resolve, reject) => {
      const request = db.transaction('kv', 'readonly').objectStore('kv').get(key);
      request.onsuccess = () => resolve(request.result ?? null);
      request.onerror = () => reject(request.error);
    });
  } finally { db.close(); }
}

async function cryptoDbPut(key, value) {
  const db = await openCryptoDb();
  try {
    await new Promise((resolve, reject) => {
      const tx = db.transaction('kv', 'readwrite');
      tx.objectStore('kv').put(value, key);
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  } finally { db.close(); }
}

async function cryptoDbDelete(key) {
  const db = await openCryptoDb();
  try {
    await new Promise((resolve, reject) => {
      const tx = db.transaction('kv', 'readwrite');
      tx.objectStore('kv').delete(key);
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  } finally { db.close(); }
}

async function saveLocalIdentity(username, identity) {
  localIdentity = identity;
  await cryptoDbPut(`identity:${username}`, identity);
}

async function loadLocalIdentity(username) {
  const value = await cryptoDbGet(`identity:${username}`);
  localIdentity = value || null;
  return localIdentity;
}

async function clearLocalIdentity(username) {
  localIdentity = null;
  chatKeyCache.clear();
  activeChatInfo = null;
  if (username) await cryptoDbDelete(`identity:${username}`);
}

async function pinPeerIdentity(username, publicKeySpki, signingPublicKeySpki, claimedFingerprint) {
  const actual = await fingerprintIdentity(publicKeySpki, signingPublicKeySpki);
  if (claimedFingerprint && actual !== String(claimedFingerprint).toUpperCase()) throw new Error('بصمة مفتاح المستخدم غير متطابقة');
  const key = `trust:${currentUser?.username || 'unknown'}:${username}`;
  const pinned = await cryptoDbGet(key);
  if (pinned && pinned !== actual) throw new Error('تغيّر مفتاح التشفير لهذا المستخدم. أوقف الإرسال وتحقق من البصمة معه خارج Yeznsap.');
  if (!pinned) await cryptoDbPut(key, actual);
  return actual;
}

async function importRsaPublic(publicKeySpki) {
  return crypto.subtle.importKey('spki', b64UrlToBytes(publicKeySpki), { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt']);
}

async function wrapChatKey(rawKey, publicKeySpki) {
  const publicKey = await importRsaPublic(publicKeySpki);
  return bytesToB64Url(new Uint8Array(await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, publicKey, rawKey)));
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

async function createKeyAgreement(rawChatKey, participants) {
  if (!localIdentity?.signingPrivateKey) throw new Error('مفتاح توقيع E2EE المحلي غير جاهز');
  const agreement = {
    v: 1,
    keyId: bytesToB64Url(randomBytes(16)),
    participants: [...participants].sort(),
    keyHash: bytesToB64Url(await sha256Bytes(rawChatKey)),
    creator: currentUser.username
  };
  const signature = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    localIdentity.signingPrivateKey,
    encoder.encode(keyAgreementStatement(agreement, agreement.participants))
  );
  return { v: 1, keyId: agreement.keyId, keyHash: agreement.keyHash, creator: agreement.creator, signature: bytesToB64Url(new Uint8Array(signature)) };
}

async function verifyKeyAgreement(chat, rawChatKey) {
  const info = chat?.e2eeInfo;
  const agreement = info?.agreement;
  if (!agreement?.keyId || !agreement?.keyHash || !agreement?.signature || !agreement?.creator) throw new Error('بيانات تأسيس مفتاح المحادثة ناقصة');
  const actualHash = bytesToB64Url(await sha256Bytes(rawChatKey));
  if (actualHash !== agreement.keyHash) throw new Error('تم رفض مفتاح محادثة تم تغييره من الخادم');
  const creatorSigningSpki = agreement.creator === currentUser.username
    ? localIdentity?.signingPublicKeySpki
    : info.creatorSigningPublicKeySpki;
  if (!creatorSigningSpki) throw new Error('مفتاح توقيع منشئ المحادثة غير متاح');
  const signingPublic = await crypto.subtle.importKey(
    'spki',
    b64UrlToBytes(creatorSigningSpki),
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['verify']
  );
  const participants = [currentUser.username, chat.other?.username].filter(Boolean).sort();
  const valid = await crypto.subtle.verify(
    { name: 'ECDSA', hash: 'SHA-256' },
    signingPublic,
    b64UrlToBytes(agreement.signature),
    encoder.encode(keyAgreementStatement(agreement, participants))
  );
  if (!valid) throw new Error('توقيع مفتاح المحادثة غير صالح');
  return true;
}

async function ensureChatKey(chat) {
  if (!chat?.id) throw new Error('المحادثة غير صالحة');
  if (chatKeyCache.has(chat.id)) return chatKeyCache.get(chat.id);
  if (!localIdentity?.privateKey) throw new Error('مفتاح E2EE المحلي غير متاح. سجّل الدخول من جديد.');
  const info = chat.e2eeInfo;
  if (!info?.keyEnvelope || !info?.peerPublicKeySpki || !info?.peerSigningPublicKeySpki) throw new Error('المحادثة لا تحتوي مفاتيح E2EE');
  await pinPeerIdentity(chat.other?.username || '', info.peerPublicKeySpki, info.peerSigningPublicKeySpki, info.peerFingerprint);
  const raw = new Uint8Array(await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, localIdentity.privateKey, b64UrlToBytes(info.keyEnvelope)));
  if (raw.length !== 32) throw new Error('مفتاح المحادثة غير صالح');
  await verifyKeyAgreement(chat, raw);
  const key = await crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
  raw.fill(0);
  chatKeyCache.set(chat.id, key);
  return key;
}

function messageAad(chatId, messageId, sender) {
  return encoder.encode(`yeznsap-message-v1|${chatId}|${messageId}|${sender}`);
}

async function encryptChatMessage(chat, text) {
  const key = await ensureChatKey(chat);
  const id = bytesToB64Url(randomBytes(16));
  const iv = randomBytes(12);
  const ct = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: messageAad(chat.id, id, currentUser.username) },
    key,
    encoder.encode(text)
  ));
  return { id, v: 1, alg: 'AES-256-GCM', iv: bytesToB64Url(iv), ct: bytesToB64Url(ct) };
}

async function decryptChatMessage(chat, message) {
  if (message?.legacy) return { ...message, text: message.text || '', legacy: true };
  if (message?.v !== 1 || message?.alg !== 'AES-256-GCM') throw new Error('Unsupported message format');
  const key = await ensureChatKey(chat);
  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: b64UrlToBytes(message.iv), additionalData: messageAad(chat.id, message.id, message.sender) },
    key,
    b64UrlToBytes(message.ct)
  );
  return { ...message, text: decoder.decode(plaintext), legacy: false };
}

async function unlockIdentityAfterAuth(phrase, username) {
  const { data } = await api('/api/e2ee/me');
  if (!data.success) throw new Error(data.message || 'تعذر تحميل هوية E2EE');
  const identity = await unlockE2eeIdentity(phrase, data.e2ee);
  if (data.e2ee.fingerprint && identity.fingerprint !== String(data.e2ee.fingerprint).toUpperCase()) throw new Error('بصمة هوية E2EE غير متطابقة');
  await saveLocalIdentity(username, identity);
  return identity;
}

function generateRecoveryPhrase() {
  const random = randomBytes(16);
  return [...random].map((byte) => RECOVERY_WORDS[byte]).join(' ');
}

function generateConfirmationPositions() {
  const positions = new Set();
  while (positions.size < 4) positions.add((randomBytes(1)[0] % 16) + 1);
  return [...positions].sort((a, b) => a - b);
}

function getConfirmWords() {
  return [...els.phraseConfirmInputs.querySelectorAll('input')].map((input) => normalizePhrase(input.value));
}

function recoveryConfirmationValid() {
  if (!registrationConfirmPositions.length) return false;
  const words = normalizePhrase(generatedPhrase).split(' ');
  const entered = getConfirmWords();
  return entered.length === registrationConfirmPositions.length && entered.every((word, index) => word === words[registrationConfirmPositions[index] - 1]);
}

function updateLoginState() {
  els.btnLogin.disabled = !(validUsername(els.loginUsername.value) && validPhrase(els.loginPhrase.value));
}

function updateTwofaState() {
  els.btnTwofaVerify.disabled = (els.twofaCode.value || '').trim().length < 6;
}

function updateRegisterState() {
  els.btnRegister.disabled = !(
    validUsername(els.registerUsername.value) &&
    validNewPhrase(generatedPhrase) &&
    els.phraseSaved.checked &&
    recoveryConfirmationValid() &&
    els.ageConfirmed.checked
  );
}

function renderPhrase(phrase) {
  const words = normalizePhrase(phrase).split(' ');
  els.phraseGrid.innerHTML = '';
  words.forEach((word, index) => {
    const item = document.createElement('div');
    item.className = 'phrase-word';
    const number = document.createElement('span');
    number.className = 'phrase-number';
    number.textContent = String(index + 1);
    const text = document.createElement('span');
    text.className = 'phrase-text';
    text.textContent = word;
    item.append(number, text);
    els.phraseGrid.appendChild(item);
  });
  els.phrasePanel.classList.remove('hidden');
}

function renderRecoveryConfirmation() {
  els.phraseConfirmInputs.innerHTML = '';
  registrationConfirmPositions.forEach((position) => {
    const label = document.createElement('label');
    label.className = 'confirm-word-field';
    const text = document.createElement('span');
    text.textContent = `الكلمة رقم ${position}`;
    const input = document.createElement('input');
    input.type = 'text';
    input.autocomplete = 'off';
    input.autocapitalize = 'none';
    input.spellcheck = false;
    input.dir = 'ltr';
    input.placeholder = `word ${position}`;
    input.addEventListener('input', () => {
      input.value = input.value.toLowerCase().replace(/[^a-z]/g, '');
      updateRegisterState();
    });
    label.append(text, input);
    els.phraseConfirmInputs.appendChild(label);
  });
}

function resetRecoveryConfirmation() {
  registrationConfirmPositions = [];
  els.phraseSaved.checked = false;
  els.phraseGrid.classList.remove('phrase-obscured');
  els.phraseConfirmBox.classList.add('hidden');
  els.phraseConfirmInputs.innerHTML = '';
}

async function api(path, options = {}) {
  const method = String(options.method || 'GET').toUpperCase();
  const headers = {
    ...(options.body ? { 'Content-Type': 'application/json' } : {}),
    ...(options.headers || {})
  };
  if (!['GET', 'HEAD', 'OPTIONS'].includes(method) && csrfToken && !path.startsWith('/api/auth/login') && !path.startsWith('/api/auth/register') && !path.startsWith('/api/auth/new-phrase') && !path.startsWith('/api/auth/2fa')) {
    headers['X-CSRF-Token'] = csrfToken;
  }

  const response = await fetch(`${API_BASE}${path}`, {
    credentials: 'include',
    ...options,
    method,
    headers
  });

  let data;
  try {
    data = await response.json();
  } catch {
    data = { success: false, message: 'استجابة غير صالحة من الخادم' };
  }

  if (data?.csrfToken) csrfToken = data.csrfToken;
  if (response.status === 423 || data?.locked) showPinLock();
  if (response.status === 401 && !path.startsWith('/api/auth/')) {
    currentUser = null;
    csrfToken = '';
  }
  return { response, data };
}

function updateUserUI(user) {
  if (!user) return;
  currentUser = user;
  const label = user.displayName || user.username || 'Y';
  els.sidebarAvatarText.textContent = label.charAt(0).toUpperCase();
  syncSecurityUI();
}

function syncSecurityUI() {
  if (!currentUser) return;
  const enabled = Boolean(currentUser.security?.twoFactorEnabled);
  els.status2fa.textContent = enabled ? '2FA مفعّل' : '2FA اختياري';
  els.totpDisabledBox.classList.toggle('hidden', enabled);
  els.totpEnabledBox.classList.toggle('hidden', !enabled);
  if (!els.totpSetupBox.dataset.active) els.totpSetupBox.classList.add('hidden');

  const privacy = currentUser.privacy || {};
  els.privacyLastSeen.value = privacy.lastSeen || 'contacts';
  els.privacyProfilePhoto.value = privacy.profilePhoto || 'contacts';
  els.privacyStatus.value = privacy.statusVisibility || 'contacts';
  els.privacyReadReceipts.checked = privacy.readReceipts !== false;
  els.privacyAutoDelete.value = currentUser.autoDeleteInactiveDays ? String(currentUser.autoDeleteInactiveDays) : 'never';
  els.btnLockNow.disabled = !currentUser.security?.pinEnabled;
}

async function loadMe() {
  const { data } = await api('/api/me');
  if (data.success && data.user) updateUserUI(data.user);
  return data;
}

async function doLogout() {
  stopMessaging();
  const username = currentUser?.username || null;
  try { await api('/api/auth/logout', { method: 'POST' }); } catch { /* ignore network failure */ }
  try { await clearLocalIdentity(username); } catch { /* best effort */ }
  currentUser = null;
  csrfToken = '';
  twoFactorLoginToken = '';
  els.loginPhrase.value = '';
  closeSecurityModal();
  hidePinLock();
  updateLoginState();
  showScreen('login');
}

els.loginUsername.addEventListener('input', () => {
  els.loginUsername.value = els.loginUsername.value.toLowerCase().replace(/[^a-z0-9._]/g, '');
  hideError(els.loginError);
  updateLoginState();
});

els.loginPhrase.addEventListener('input', () => {
  hideError(els.loginError);
  updateLoginState();
});

els.loginPhrase.addEventListener('keydown', (event) => {
  if (event.key === 'Enter' && !els.btnLogin.disabled) els.btnLogin.click();
});

els.btnToggleLoginPhrase.addEventListener('click', () => {
  els.loginPhrase.type = els.loginPhrase.type === 'password' ? 'text' : 'password';
  els.loginPhrase.focus();
});

els.btnLogin.addEventListener('click', async () => {
  if (els.btnLogin.disabled) return;
  setLoading(els.btnLogin, true);
  hideError(els.loginError);
  const phrase = normalizePhrase(els.loginPhrase.value);
  const username = normalizeUsername(els.loginUsername.value);
  try {
    pendingLoginPhrase = phrase;
    const authSecret = await deriveAuthSecret(phrase);
    const { data } = await api('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username, authSecret })
    });
    if (!data.success) {
      pendingLoginPhrase = '';
      showError(els.loginError, data.message || 'تعذر تسجيل الدخول');
      return;
    }
    if (data.requires2fa) {
      twoFactorLoginToken = data.loginToken;
      els.twofaCode.value = '';
      updateTwofaState();
      showScreen('twofa');
      setTimeout(() => els.twofaCode.focus(), 100);
      return;
    }
    await unlockIdentityAfterAuth(phrase, username);
    pendingLoginPhrase = '';
    els.loginPhrase.value = '';
    updateLoginState();
    updateUserUI(data.user);
    showScreen('main');
    startMessaging();
    showToast(`مرحبًا @${data.user.username} — E2EE جاهز`, 'success');
  } catch (error) {
    console.error(error);
    pendingLoginPhrase = '';
    showError(els.loginError, error.message || 'تعذر تسجيل الدخول بأمان');
  } finally {
    setLoading(els.btnLogin, false);
    updateLoginState();
  }
});

els.twofaCode.addEventListener('input', () => {
  hideError(els.twofaError);
  els.twofaCode.value = els.twofaCode.value.toUpperCase().replace(/[^A-Z0-9-]/g, '');
  updateTwofaState();
});

els.twofaCode.addEventListener('keydown', (event) => {
  if (event.key === 'Enter' && !els.btnTwofaVerify.disabled) els.btnTwofaVerify.click();
});

els.btnTwofaVerify.addEventListener('click', async () => {
  if (els.btnTwofaVerify.disabled || !twoFactorLoginToken) return;
  setLoading(els.btnTwofaVerify, true);
  hideError(els.twofaError);
  try {
    const { data } = await api('/api/auth/2fa', {
      method: 'POST',
      body: JSON.stringify({ loginToken: twoFactorLoginToken, code: els.twofaCode.value.trim() })
    });
    if (!data.success) {
      showError(els.twofaError, data.message || 'تعذر التحقق');
      return;
    }
    twoFactorLoginToken = '';
    await unlockIdentityAfterAuth(pendingLoginPhrase, data.user.username);
    pendingLoginPhrase = '';
    els.loginPhrase.value = '';
    els.twofaCode.value = '';
    updateUserUI(data.user);
    showScreen('main');
    startMessaging();
    showToast('تم التحقق بخطوتين وفتح مفاتيح E2EE', 'success');
  } catch (error) {
    console.error(error);
    showError(els.twofaError, 'تعذر الاتصال بالخادم');
  } finally {
    setLoading(els.btnTwofaVerify, false);
    updateTwofaState();
  }
});

els.btnTwofaCancel.addEventListener('click', () => {
  twoFactorLoginToken = '';
  pendingLoginPhrase = '';
  els.twofaCode.value = '';
  hideError(els.twofaError);
  showScreen('login');
});

els.btnOpenRegister.addEventListener('click', () => {
  hideError(els.loginError);
  showScreen('register');
  setTimeout(() => els.registerUsername.focus(), 100);
});

els.registerUsername.addEventListener('input', () => {
  els.registerUsername.value = els.registerUsername.value.toLowerCase().replace(/[^a-z0-9._]/g, '');
  hideError(els.registerError);
  updateRegisterState();
});

els.phraseSaved.addEventListener('change', () => {
  if (els.phraseSaved.checked && registrationConfirmPositions.length) {
    els.phraseGrid.classList.add('phrase-obscured');
    renderRecoveryConfirmation();
    els.phraseConfirmBox.classList.remove('hidden');
    setTimeout(() => els.phraseConfirmInputs.querySelector('input')?.focus(), 50);
  } else {
    els.phraseGrid.classList.remove('phrase-obscured');
    els.phraseConfirmBox.classList.add('hidden');
    els.phraseConfirmInputs.innerHTML = '';
  }
  updateRegisterState();
});
els.ageConfirmed.addEventListener('change', updateRegisterState);

async function handleGeneratePhrase() {
  hideError(els.registerError);
  els.btnGeneratePhrase.disabled = true;
  if (els.btnRegeneratePhrase) els.btnRegeneratePhrase.disabled = true;
  try {
    resetRecoveryConfirmation();
    generatedPhrase = generateRecoveryPhrase();
    registrationConfirmPositions = generateConfirmationPositions();
    renderPhrase(generatedPhrase);
    updateRegisterState();
  } catch (error) {
    console.error(error);
    showError(els.registerError, 'تعذر إنشاء مفتاح الاسترداد محليًا');
  } finally {
    els.btnGeneratePhrase.disabled = false;
    if (els.btnRegeneratePhrase) els.btnRegeneratePhrase.disabled = false;
  }
}

els.btnGeneratePhrase.addEventListener('click', handleGeneratePhrase);
els.btnRegeneratePhrase.addEventListener('click', handleGeneratePhrase);

els.btnCopyPhrase.addEventListener('click', async () => {
  if (!generatedPhrase) return;
  try {
    await navigator.clipboard.writeText(generatedPhrase);
    showToast('تم نسخ الكلمات الـ16. احفظها في مكان آمن ولا تضعها في مدير حافظة سحابي.', 'success');
  } catch {
    showToast('تعذر النسخ تلقائيًا. انسخ الكلمات يدويًا.', 'error');
  }
});

els.btnRegister.addEventListener('click', async () => {
  if (els.btnRegister.disabled) return;
  setLoading(els.btnRegister, true);
  hideError(els.registerError);
  const phrase = normalizePhrase(generatedPhrase);
  const username = normalizeUsername(els.registerUsername.value);
  try {
    showToast('جارٍ إنشاء هوية التشفير الطرفي على جهازك…');
    const [authSecret, e2eeResult] = await Promise.all([
      deriveAuthSecret(phrase),
      createE2eeIdentityBundle(phrase)
    ]);
    const { data } = await api('/api/auth/register', {
      method: 'POST',
      body: JSON.stringify({
        username,
        authSecret,
        e2ee: e2eeResult.bundle,
        recoveryConfirmed: recoveryConfirmationValid(),
        ageConfirmed: els.ageConfirmed.checked
      })
    });
    if (!data.success) {
      showError(els.registerError, data.message || 'تعذر إنشاء الحساب');
      return;
    }
    await saveLocalIdentity(username, e2eeResult.identity);
    updateUserUI(data.user);
    showScreen('main');
    startMessaging();
    showToast(`تم إنشاء الحساب @${data.user.username} مع E2EE`, 'success');
    generatedPhrase = '';
    resetRecoveryConfirmation();
    els.phraseGrid.textContent = '';
    els.phrasePanel.classList.add('hidden');
    els.ageConfirmed.checked = false;
    els.registerUsername.value = '';
    updateRegisterState();
  } catch (error) {
    console.error(error);
    showError(els.registerError, error.message || 'تعذر إنشاء الحساب أو مفاتيح E2EE');
  } finally {
    setLoading(els.btnRegister, false);
    updateRegisterState();
  }
});

els.btnBackLogin.addEventListener('click', () => {
  hideError(els.registerError);
  generatedPhrase = '';
  resetRecoveryConfirmation();
  els.phraseGrid.textContent = '';
  els.phrasePanel.classList.add('hidden');
  els.ageConfirmed.checked = false;
  updateRegisterState();
  showScreen('login');
});

els.btnLogout.addEventListener('click', async () => {
  await doLogout();
  showToast('تم تسجيل الخروج');
});


function avatarLetter(user) {
  const label = user?.displayName || user?.username || 'Y';
  return label.charAt(0).toUpperCase();
}

function formatChatTime(value) {
  if (!value) return '';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '';
  const now = new Date();
  const sameDay = date.toDateString() === now.toDateString();
  return sameDay
    ? date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    : date.toLocaleDateString([], { month: 'short', day: 'numeric' });
}

function makeEmptyState(title = 'لا توجد محادثات حتى الآن', text = 'ابدأ محادثة مع أحد مستخدمي Yeznsap') {
  const wrap = document.createElement('div');
  wrap.className = 'empty-state';
  const icon = document.createElement('div');
  icon.className = 'empty-icon';
  icon.textContent = '💬';
  const h = document.createElement('h3');
  h.textContent = title;
  const p = document.createElement('p');
  p.textContent = text;
  const button = document.createElement('button');
  button.className = 'btn-primary';
  button.type = 'button';
  button.textContent = 'بدء محادثة';
  button.addEventListener('click', focusChatSearch);
  wrap.append(icon, h, p, button);
  return wrap;
}

function renderChats(chats) {
  cachedChats = Array.isArray(chats) ? chats : [];
  els.conversationsList.textContent = '';
  if (!cachedChats.length) {
    els.conversationsList.appendChild(makeEmptyState());
    return;
  }
  cachedChats.forEach((chat) => {
    const other = chat.other || { username: 'unknown' };
    const row = document.createElement('button');
    row.type = 'button';
    row.className = `conversation-row${chat.id === activeChatId ? ' active' : ''}`;
    const avatar = document.createElement('div');
    avatar.className = 'conversation-avatar';
    avatar.textContent = avatarLetter(other);
    const body = document.createElement('div');
    body.className = 'conversation-body';
    const top = document.createElement('div');
    top.className = 'conversation-top';
    const name = document.createElement('strong');
    name.textContent = other.displayName || `@${other.username}`;
    const time = document.createElement('span');
    time.textContent = formatChatTime(chat.lastMessage?.createdAt || chat.updatedAt);
    top.append(name, time);
    const preview = document.createElement('div');
    preview.className = 'conversation-preview';
    preview.textContent = chat.lastMessage ? (chat.lastMessage.encrypted ? '🔒 رسالة مشفرة من طرف إلى طرف' : (chat.lastMessage.legacyText || 'رسالة قديمة')) : `ابدأ المراسلة مع @${other.username}`;
    body.append(top, preview);
    if (other.isOnline) {
      const dot = document.createElement('span');
      dot.className = 'online-dot';
      dot.title = 'متصل الآن';
      avatar.appendChild(dot);
    }
    row.append(avatar, body);
    row.addEventListener('click', () => openChat(chat.id));
    els.conversationsList.appendChild(row);
  });
}

function renderUserSearchResults(users, query) {
  els.conversationsList.textContent = '';
  if (!users.length) {
    els.conversationsList.appendChild(makeEmptyState('لم نجد مستخدمًا', `لا يوجد مستخدم مطابق لـ ${query}`));
    return;
  }
  users.forEach((user) => {
    const row = document.createElement('button');
    row.type = 'button';
    row.className = 'conversation-row user-result';
    const avatar = document.createElement('div');
    avatar.className = 'conversation-avatar';
    avatar.textContent = avatarLetter(user);
    const body = document.createElement('div');
    body.className = 'conversation-body';
    const name = document.createElement('strong');
    name.textContent = user.displayName || `@${user.username}`;
    const sub = document.createElement('div');
    sub.className = 'conversation-preview';
    sub.textContent = `${user.e2ee ? '🔒 E2EE · ' : ''}@${user.username}${user.isOnline ? ' · متصل الآن' : ''}`;
    body.append(name, sub);
    row.append(avatar, body);
    row.addEventListener('click', () => createDirectChat(user));
    els.conversationsList.appendChild(row);
  });
}

async function loadChats(silent = false) {
  try {
    const { data } = await api('/api/chats');
    if (!data.success) throw new Error(data.message || 'تعذر تحميل المحادثات');
    if (!els.chatSearch.value.trim()) renderChats(data.chats || []);
    else cachedChats = data.chats || [];
    return data.chats || [];
  } catch (error) {
    if (!silent) showToast(error.message || 'تعذر تحميل المحادثات', 'error');
    return [];
  }
}

function focusChatSearch() {
  els.chatSearch.value = '';
  renderChats(cachedChats);
  els.chatSearch.focus();
}

async function searchUsers(raw) {
  const query = normalizeUsername(String(raw || '').replace(/^@/, ''));
  if (query.length < 2) {
    renderChats(cachedChats);
    return;
  }
  try {
    const { data } = await api(`/api/users/search?q=${encodeURIComponent(query)}`);
    if (!data.success) throw new Error(data.message || 'تعذر البحث');
    renderUserSearchResults(data.users || [], `@${query}`);
  } catch (error) {
    showToast(error.message || 'تعذر البحث عن المستخدمين', 'error');
  }
}

async function createDirectChat(user) {
  const username = typeof user === 'string' ? user : user?.username;
  try {
    if (!localIdentity?.publicKeySpki) throw new Error('مفتاح E2EE المحلي غير جاهز');
    let peer = typeof user === 'object' ? user : null;
    if (!peer?.e2ee?.publicKeySpki) {
      const { data: publicData } = await api(`/api/users/${encodeURIComponent(username)}/e2ee-public`);
      if (!publicData.success) throw new Error(publicData.message || 'مفتاح المستخدم غير متاح');
      peer = publicData.user;
    }
    await pinPeerIdentity(username, peer.e2ee.publicKeySpki, peer.e2ee.signingPublicKeySpki, peer.e2ee.fingerprint);
    const rawChatKey = randomBytes(32);
    const participants = [currentUser.username, username].sort();
    const keyAgreement = await createKeyAgreement(rawChatKey, participants);
    const keyEnvelopes = {};
    keyEnvelopes[currentUser.username] = await wrapChatKey(rawChatKey, localIdentity.publicKeySpki);
    keyEnvelopes[username] = await wrapChatKey(rawChatKey, peer.e2ee.publicKeySpki);
    rawChatKey.fill(0);

    const { data } = await api('/api/chats/direct', {
      method: 'POST',
      body: JSON.stringify({ username, keyEnvelopes, keyAgreement })
    });
    if (!data.success) return showToast(data.message || 'تعذر بدء المحادثة', 'error');
    els.chatSearch.value = '';
    await loadChats(true);
    await openChat(data.chat.id);
  } catch (error) {
    console.error(error);
    showToast(error.message || 'تعذر بدء محادثة مشفرة', 'error');
  }
}

function renderChatShell(chat) {
  activeChatInfo = chat;
  const other = chat.other || { username: 'unknown' };
  activeChatOther = other;
  els.chatWindow.textContent = '';
  const header = document.createElement('div');
  header.className = 'message-header';
  const back = document.createElement('button');
  back.className = 'icon-btn chat-back-btn';
  back.type = 'button';
  back.setAttribute('aria-label', 'العودة');
  back.textContent = '←';
  back.addEventListener('click', () => els.chatWindow.classList.remove('active'));
  const avatar = document.createElement('div');
  avatar.className = 'conversation-avatar small';
  avatar.textContent = avatarLetter(other);
  const identity = document.createElement('div');
  identity.className = 'message-header-identity';
  const name = document.createElement('strong');
  name.textContent = other.displayName || `@${other.username}`;
  const state = document.createElement('span');
  const fp = chat.e2eeInfo?.peerFingerprint || other.e2ee?.fingerprint || '';
  state.textContent = fp ? `🔒 E2EE · ${formatFingerprint(fp).slice(0, 24)}…` : (other.isOnline ? 'متصل الآن' : `@${other.username}`);
  if (fp) state.title = `بصمة مفتاح @${other.username}: ${formatFingerprint(fp)} — تحقق منها مع المستخدم خارج Yeznsap عند الحاجة.`;
  identity.append(name, state);
  header.append(back, avatar, identity);

  const messages = document.createElement('div');
  messages.id = 'active-messages';
  messages.className = 'message-list';

  const composer = document.createElement('div');
  composer.className = 'message-composer';
  const input = document.createElement('textarea');
  input.id = 'message-input';
  input.rows = 1;
  input.maxLength = 4000;
  input.placeholder = 'اكتب رسالة…';
  input.setAttribute('aria-label', 'نص الرسالة');
  const send = document.createElement('button');
  send.type = 'button';
  send.className = 'send-message-btn';
  send.textContent = 'إرسال';
  const submit = () => sendActiveMessage(input, send);
  send.addEventListener('click', submit);
  input.addEventListener('keydown', (event) => {
    if (event.key === 'Enter' && !event.shiftKey) {
      event.preventDefault();
      submit();
    }
  });
  composer.append(input, send);
  els.chatWindow.append(header, messages, composer);
  els.chatWindow.classList.add('active');
  setTimeout(() => input.focus(), 50);
}

async function renderMessages(messages, chat = activeChatInfo) {
  const list = els.chatWindow.querySelector('.message-list');
  if (!list) return;
  const wasNearBottom = list.scrollHeight - list.scrollTop - list.clientHeight < 140;
  list.textContent = '';
  if (!messages.length) {
    const intro = document.createElement('div');
    intro.className = 'conversation-intro';
    intro.textContent = `🔒 بدأت محادثتك المشفرة مع @${activeChatOther?.username || ''}`;
    list.appendChild(intro);
  }
  let decrypted = [];
  try {
    decrypted = await Promise.all(messages.map(async (message) => {
      try { return await decryptChatMessage(chat, message); }
      catch (error) {
        console.error('Decrypt failed', error);
        return { ...message, text: '⚠ تعذر فك تشفير هذه الرسالة', decryptFailed: true };
      }
    }));
  } catch (error) {
    console.error(error);
  }
  decrypted.forEach((message) => {
    const bubble = document.createElement('div');
    bubble.className = `message-bubble ${message.sender === currentUser.username ? 'mine' : 'theirs'}`;
    const text = document.createElement('div');
    text.className = 'message-text';
    text.textContent = message.text;
    const meta = document.createElement('span');
    meta.className = 'message-meta';
    meta.textContent = `${message.legacy ? 'قديم · ' : '🔒 · '}${formatChatTime(message.createdAt)}`;
    bubble.append(text, meta);
    list.appendChild(bubble);
  });
  if (wasNearBottom || decrypted.length <= 3) list.scrollTop = list.scrollHeight;
}

async function refreshActiveMessages() {
  if (!activeChatId) return;
  try {
    const { data } = await api(`/api/chats/${encodeURIComponent(activeChatId)}/messages?limit=200`);
    if (!data.success) throw new Error(data.message || 'تعذر تحميل الرسائل');
    if (data.chat?.other) activeChatOther = data.chat.other;
    if (data.chat) activeChatInfo = data.chat;
    await ensureChatKey(activeChatInfo);
    await renderMessages(data.messages || [], activeChatInfo);
  } catch (error) {
    if (error.message) console.error(error);
  }
}

async function openChat(chatId) {
  activeChatId = chatId;
  try {
    const { data } = await api(`/api/chats/${encodeURIComponent(chatId)}/messages?limit=200`);
    if (!data.success) return showToast(data.message || 'تعذر فتح المحادثة', 'error');
    renderChatShell(data.chat);
    await ensureChatKey(data.chat);
    await renderMessages(data.messages || [], data.chat);
    renderChats(cachedChats);
  } catch (error) {
    showToast('تعذر فتح المحادثة', 'error');
  }
}

async function sendActiveMessage(input, button) {
  if (!activeChatId || !input || !button) return;
  const text = input.value.trim();
  if (!text) return;
  button.disabled = true;
  try {
    const encrypted = await encryptChatMessage(activeChatInfo, text);
    const { data } = await api(`/api/chats/${encodeURIComponent(activeChatId)}/messages`, {
      method: 'POST',
      body: JSON.stringify(encrypted)
    });
    if (!data.success) return showToast(data.message || 'تعذر إرسال الرسالة', 'error');
    input.value = '';
    await refreshActiveMessages();
    await loadChats(true);
    renderChats(cachedChats);
  } catch (error) {
    showToast('تعذر إرسال الرسالة', 'error');
  } finally {
    button.disabled = false;
    input.focus();
  }
}

function startMessaging() {
  if (!currentUser) return;
  loadChats(true).then((chats) => renderChats(chats));
  if (messagingPollId) clearInterval(messagingPollId);
  messagingPollId = setInterval(async () => {
    if (!currentUser || document.hidden) return;
    await loadChats(true);
    if (!els.chatSearch.value.trim()) renderChats(cachedChats);
    await refreshActiveMessages();
  }, 3000);
}

function stopMessaging() {
  if (messagingPollId) clearInterval(messagingPollId);
  messagingPollId = null;
  activeChatId = null;
  activeChatOther = null;
  cachedChats = [];
  if (els.chatSearch) els.chatSearch.value = '';
}

els.chatSearch?.addEventListener('input', () => {
  if (chatSearchTimer) clearTimeout(chatSearchTimer);
  chatSearchTimer = setTimeout(() => searchUsers(els.chatSearch.value), 220);
});
els.btnStartChat?.addEventListener('click', focusChatSearch);
els.btnNewChatSidebar?.addEventListener('click', focusChatSearch);
els.btnNewChatHeader?.addEventListener('click', focusChatSearch);
els.btnFocusChatSearch?.addEventListener('click', focusChatSearch);

function openSecurityModal() {
  els.securityModal.classList.remove('hidden');
  document.body.classList.add('modal-open');
  syncSecurityUI();
  loadSessions();
}

function closeSecurityModal() {
  els.securityModal.classList.add('hidden');
  document.body.classList.remove('modal-open');
  els.totpPhrase.value = '';
  els.totpDisablePhrase.value = '';
  els.totpDisableCode.value = '';
  els.pinPhrase.value = '';
  els.pinValue.value = '';
  els.deletePhrase.value = '';
  els.exportPassword.value = '';
}

els.btnSecuritySettings?.addEventListener('click', openSecurityModal);
els.btnCloseSecurity?.addEventListener('click', closeSecurityModal);
els.securityBackdrop?.addEventListener('click', closeSecurityModal);
document.addEventListener('keydown', (event) => {
  if (event.key === 'Escape' && !els.securityModal.classList.contains('hidden')) closeSecurityModal();
});

async function loadSessions() {
  els.sessionsList.innerHTML = '<p class="muted">جارٍ التحميل…</p>';
  try {
    const { data } = await api('/api/security/sessions');
    if (!data.success) throw new Error(data.message || 'failed');
    els.sessionsList.innerHTML = '';
    data.sessions.forEach((session) => {
      const row = document.createElement('div');
      row.className = 'session-row';
      const info = document.createElement('div');
      const title = document.createElement('strong');
      title.textContent = session.current ? `${session.label} · هذا الجهاز` : session.label;
      const sub = document.createElement('span');
      sub.textContent = `آخر نشاط: ${new Date(session.lastSeenAt).toLocaleString()}`;
      info.append(title, sub);
      const button = document.createElement('button');
      button.className = session.current ? 'mini-btn' : 'btn-danger-soft';
      button.type = 'button';
      button.textContent = session.current ? 'الحالية' : 'إنهاء';
      button.disabled = session.current;
      if (!session.current) {
        button.addEventListener('click', async () => {
          const { data: revokeData } = await api(`/api/security/sessions/${encodeURIComponent(session.id)}`, { method: 'DELETE' });
          if (revokeData.success) {
            showToast('تم إنهاء الجلسة', 'success');
            loadSessions();
          } else showToast(revokeData.message || 'تعذر إنهاء الجلسة', 'error');
        });
      }
      row.append(info, button);
      els.sessionsList.appendChild(row);
    });
    if (!data.sessions.length) els.sessionsList.innerHTML = '<p class="muted">لا توجد جلسات نشطة.</p>';
  } catch (error) {
    console.error(error);
    els.sessionsList.innerHTML = '<p class="error-message">تعذر تحميل الأجهزة.</p>';
  }
}

els.btnRevokeOthers.addEventListener('click', async () => {
  const { data } = await api('/api/security/sessions/revoke-others', { method: 'POST', body: '{}' });
  if (data.success) {
    showToast(`تم إنهاء ${data.revoked} جلسة`, 'success');
    loadSessions();
  } else showToast(data.message || 'تعذر إنهاء الجلسات', 'error');
});

els.btnTotpSetup.addEventListener('click', async () => {
  const phrase = normalizePhrase(els.totpPhrase.value);
  if (!validPhrase(phrase)) return showToast('أدخل مفتاح الاسترداد كاملًا', 'error');
  const authSecret = await deriveAuthSecret(phrase);
  const { data } = await api('/api/security/totp/setup', {
    method: 'POST',
    body: JSON.stringify({ authSecret })
  });
  if (!data.success) return showToast(data.message || 'تعذر بدء 2FA', 'error');
  els.totpSecret.textContent = data.secret;
  els.totpPhrase.value = '';
  els.totpSetupBox.dataset.active = '1';
  els.totpSetupBox.classList.remove('hidden');
  showToast('أضف المفتاح إلى تطبيق المصادقة ثم أكد الرمز', 'success');
});

els.btnTotpConfirm.addEventListener('click', async () => {
  const code = els.totpConfirmCode.value.trim();
  const { data } = await api('/api/security/totp/confirm', {
    method: 'POST',
    body: JSON.stringify({ code })
  });
  if (!data.success) return showToast(data.message || 'رمز TOTP غير صحيح', 'error');
  lastBackupCodes = data.backupCodes || [];
  els.backupCodes.textContent = lastBackupCodes.join('\n');
  els.backupCodesBox.classList.remove('hidden');
  delete els.totpSetupBox.dataset.active;
  els.totpSetupBox.classList.add('hidden');
  els.totpPhrase.value = '';
  els.totpConfirmCode.value = '';
  els.totpSecret.textContent = '';
  await loadMe();
  showToast('تم تفعيل 2FA. احفظ رموز الاسترداد الآن.', 'success');
});

els.btnCopyBackupCodes.addEventListener('click', async () => {
  if (!lastBackupCodes.length) return;
  try {
    await navigator.clipboard.writeText(lastBackupCodes.join('\n'));
    showToast('تم نسخ رموز الاسترداد', 'success');
  } catch {
    showToast('تعذر النسخ تلقائيًا', 'error');
  }
});

els.btnTotpDisable.addEventListener('click', async () => {
  const phrase = normalizePhrase(els.totpDisablePhrase.value);
  const code = els.totpDisableCode.value.trim();
  if (!validPhrase(phrase) || !code) return showToast('أدخل مفتاح الاسترداد والرمز', 'error');
  const authSecret = await deriveAuthSecret(phrase);
  const { data } = await api('/api/security/totp/disable', {
    method: 'POST',
    body: JSON.stringify({ authSecret, code })
  });
  if (!data.success) return showToast(data.message || 'تعذر تعطيل 2FA', 'error');
  lastBackupCodes = [];
  els.backupCodes.textContent = '';
  els.backupCodesBox.classList.add('hidden');
  await loadMe();
  showToast('تم تعطيل 2FA', 'success');
});

els.btnSetPin.addEventListener('click', async () => {
  const phrase = normalizePhrase(els.pinPhrase.value);
  const pin = els.pinValue.value.trim();
  if (!validPhrase(phrase) || !/^\d{6,10}$/.test(pin)) return showToast('أدخل مفتاح الاسترداد وPIN من 6 إلى 10 أرقام', 'error');
  const authSecret = await deriveAuthSecret(phrase);
  const { data } = await api('/api/security/pin', { method: 'POST', body: JSON.stringify({ authSecret, pin }) });
  if (!data.success) return showToast(data.message || 'تعذر حفظ PIN', 'error');
  els.pinPhrase.value = '';
  els.pinValue.value = '';
  await loadMe();
  showToast('تم تفعيل PIN', 'success');
});

els.btnRemovePin.addEventListener('click', async () => {
  const phrase = normalizePhrase(els.pinPhrase.value);
  if (!validPhrase(phrase)) return showToast('أدخل مفتاح الاسترداد', 'error');
  const authSecret = await deriveAuthSecret(phrase);
  const { data } = await api('/api/security/pin', { method: 'DELETE', body: JSON.stringify({ authSecret }) });
  if (!data.success) return showToast(data.message || 'تعذر حذف PIN', 'error');
  els.pinPhrase.value = '';
  els.pinValue.value = '';
  await loadMe();
  showToast('تم حذف PIN', 'success');
});

els.btnLockNow.addEventListener('click', async () => {
  const { data } = await api('/api/security/lock', { method: 'POST', body: '{}' });
  if (!data.success) return showToast(data.message || 'تعذر قفل التطبيق', 'error');
  closeSecurityModal();
  showPinLock();
});

function showPinLock() {
  els.pinLockOverlay.classList.remove('hidden');
  document.body.classList.add('modal-open');
  setTimeout(() => els.unlockPin.focus(), 100);
}

function hidePinLock() {
  els.pinLockOverlay.classList.add('hidden');
  document.body.classList.remove('modal-open');
  els.unlockPin.value = '';
}

els.unlockPin.addEventListener('keydown', (event) => {
  if (event.key === 'Enter') els.btnUnlockPin.click();
});

els.btnUnlockPin.addEventListener('click', async () => {
  const pin = els.unlockPin.value.trim();
  if (!/^\d{6,10}$/.test(pin)) return showToast('PIN غير صالح', 'error');
  setLoading(els.btnUnlockPin, true);
  try {
    const { data } = await api('/api/security/unlock', {
      method: 'POST',
      body: JSON.stringify({ pin })
    });
    if (!data.success) return showToast(data.message || 'PIN غير صحيح', 'error');
    hidePinLock();
    await loadMe();
    startMessaging();
    showToast('تم فتح Yeznsap', 'success');
  } finally {
    setLoading(els.btnUnlockPin, false);
  }
});

els.btnLockLogout.addEventListener('click', async () => {
  await doLogout();
  showToast('تم تسجيل الخروج');
});

els.btnSavePrivacy.addEventListener('click', async () => {
  const payload = {
    lastSeen: els.privacyLastSeen.value,
    profilePhoto: els.privacyProfilePhoto.value,
    statusVisibility: els.privacyStatus.value,
    readReceipts: els.privacyReadReceipts.checked,
    autoDeleteInactiveDays: els.privacyAutoDelete.value === 'never' ? null : Number(els.privacyAutoDelete.value)
  };
  const { data } = await api('/api/security/privacy', {
    method: 'PATCH',
    body: JSON.stringify(payload)
  });
  if (!data.success) return showToast(data.message || 'تعذر حفظ الخصوصية', 'error');
  updateUserUI(data.user);
  showToast('تم حفظ إعدادات الخصوصية', 'success');
});

function downloadJson(filename, object) {
  const blob = new Blob([JSON.stringify(object, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

els.btnExportEncrypted.addEventListener('click', async () => {
  const password = els.exportPassword.value;
  if (password.length < 16) return showToast('كلمة مرور التصدير يجب أن تكون 16 حرفًا على الأقل', 'error');
  const { data } = await api('/api/account/export-encrypted', {
    method: 'POST',
    body: JSON.stringify({ password })
  });
  if (!data.success) return showToast(data.message || 'تعذر التصدير', 'error');
  downloadJson(`yeznsap-${currentUser.username}-encrypted-backup.json`, data.backup);
  els.exportPassword.value = '';
  showToast('تم إنشاء نسخة تصدير مشفرة', 'success');
});

els.btnDeleteAccount.addEventListener('click', async () => {
  const phrase = normalizePhrase(els.deletePhrase.value);
  if (!validPhrase(phrase)) return showToast('أدخل مفتاح الاسترداد لتأكيد الحذف', 'error');
  if (!window.confirm('سيتم حذف الحساب نهائيًا ولا يمكن التراجع. هل أنت متأكد؟')) return;
  const authSecret = await deriveAuthSecret(phrase);
  const { data } = await api('/api/account', {
    method: 'DELETE',
    body: JSON.stringify({ authSecret })
  });
  if (!data.success) return showToast(data.message || 'تعذر حذف الحساب', 'error');
  stopMessaging();
  try { await clearLocalIdentity(currentUser?.username); } catch { /* best effort */ }
  currentUser = null;
  csrfToken = '';
  closeSecurityModal();
  showScreen('login');
  showToast('تم حذف الحساب نهائيًا', 'success');
});

async function init() {
  showScreen('login');
  updateLoginState();
  updateTwofaState();
  updateRegisterState();

  // Yeznsap has a Node.js backend. Opening public/index.html directly with file://
  // cannot provide authentication, sessions, encrypted storage, or API routes.
  if (window.location.protocol === 'file:') {
    showError(els.loginError, 'لا تفتح index.html مباشرة. على Windows شغّل START-YEZNSAP-WINDOWS.bat من مجلد المشروع، ثم افتح http://localhost:3000');
    return;
  }

  try {
    const data = await loadMe();
    if (data.success && data.user) {
      const identity = await loadLocalIdentity(data.user.username);
      if (!identity?.privateKey || !identity?.signingPrivateKey || (data.user.e2eeFingerprint && identity.fingerprint !== data.user.e2eeFingerprint)) {
        showError(els.loginError, 'الجلسة موجودة لكن مفتاح E2EE المحلي غير متاح. سجّل الدخول من جديد بمفتاح الاسترداد.');
        await doLogout();
        return;
      }
      showScreen('main');
      startMessaging();
      showToast(`مرحبًا بعودتك @${data.user.username} — E2EE جاهز`, 'success');
    } else if (data.locked) {
      showScreen('main');
      showPinLock();
    }
  } catch {
    // Stay on login.
  }
}

init();
