'use strict';

const fs = require('node:fs');
const path = require('node:path');

const root = path.join(__dirname, '..');
const read = (p) => fs.readFileSync(path.join(root, p), 'utf8');
const server = read('server.js');
const html = read('public/index.html');
const js = read('public/app.js');
const gitignore = read('.gitignore');
const pkg = JSON.parse(read('package.json'));

const errors = [];
const ok = (condition, message) => { if (!condition) errors.push(message); };

const wordBlock = server.match(/const WORDS = \[(.*?)\];/s)?.[1] || '';
const words = [...wordBlock.matchAll(/'([a-z]+)'/g)].map((m) => m[1]);
ok(words.length === 256 && new Set(words).size === 256, 'Recovery word list must contain exactly 256 unique words.');
ok(server.includes('const NEW_RECOVERY_WORD_COUNT = 16'), 'New recovery keys must use 16 words.');
ok(Math.log2(new Set(words).size || 1) * 16 >= 128, 'New recovery-key selection entropy must be at least 128 bits.');
const clientWordBlock = js.match(/const RECOVERY_WORDS = Object\.freeze\(\[(.*?)\]\);/s)?.[1] || '';
const clientWords = [...clientWordBlock.matchAll(/'([a-z]+)'/g)].map((m) => m[1]);
ok(clientWords.length === 256 && clientWords.every((word, index) => word === words[index]), 'Client/server recovery word lists must match exactly.');

const ids = [...html.matchAll(/\bid=["']([^"']+)["']/g)].map((m) => m[1]);
ok(new Set(ids).size === ids.length, 'HTML contains duplicate id attributes.');
const refs = [...js.matchAll(/getElementById\(['"]([^'"]+)/g)].map((m) => m[1]);
for (const ref of refs) ok(ids.includes(ref), `Missing HTML element referenced by app.js: ${ref}`);

ok(!/\bon(?:click|load|error|submit|input)\s*=/i.test(html), 'Inline event handlers are forbidden.');
ok(!/\beval\s*\(|new\s+Function\s*\(/.test(js), 'eval/new Function are forbidden.');
ok(!/localStorage|sessionStorage/.test(js), 'Authentication/session data must not use Web Storage.');
ok(!/fonts\.googleapis\.com|fonts\.gstatic\.com/.test(html + js + read('public/style.css')), 'Third-party Google Fonts references must not exist.');
ok(!server.includes("'unsafe-inline'"), "CSP must not contain 'unsafe-inline'.");
ok(!server.includes("'unsafe-eval'"), "CSP must not contain 'unsafe-eval'.");
ok(server.includes("sameSite: 'strict'"), 'Session/device cookies must use SameSite=Strict.');
ok(server.includes('httpOnly: true'), 'Cookies must use HttpOnly.');
ok(server.includes("'__Host-id'"), 'Production session cookie must use __Host- prefix.');
ok(server.includes('crypto.timingSafeEqual'), 'Timing-safe comparison must be used for security tokens/hashes.');
ok(server.includes('AES-256-GCM') || server.includes("'aes-256-gcm'"), 'AES-256-GCM at-rest encryption missing.');
ok(server.includes('verifyTotpCode') && server.includes('lastAcceptedCounter'), 'TOTP replay tracking missing.');
ok(server.includes('MAX_KDF_CONCURRENCY'), 'KDF concurrency guard missing.');
ok(server.includes('DATA_INDEX_KEY'), 'Independent keyed-hash secret missing.');
ok(server.includes("app.get('/api/chats'"), 'Messaging chat-list endpoint missing.');
ok(server.includes("app.post('/api/chats/direct'"), 'Direct-chat creation endpoint missing.');
ok(server.includes("app.post('/api/chats/:id/messages'"), 'Message-send endpoint missing.');
ok(server.includes("app.get('/api/e2ee/me'"), 'E2EE identity endpoint missing.');
ok(server.includes("RSA-OAEP-3072-SHA256"), 'RSA-OAEP 3072-bit E2EE identity validation missing.');
ok(js.includes("modulusLength: 3072") && js.includes("RSA-OAEP"), 'Client RSA-OAEP 3072-bit identity generation missing.');
ok(js.includes("ECDSA") && js.includes("P-256"), 'Client ECDSA P-256 identity signing key generation missing.');
ok(server.includes("normalizeKeyAgreement") && js.includes("createKeyAgreement") && js.includes("verifyKeyAgreement"), 'Signed E2EE key-agreement flow missing.');
ok(server.includes("dsaEncoding: 'ieee-p1363'"), 'Server ECDSA agreement verification must use the Web Crypto-compatible P1363 signature format.');
ok(js.includes("E2EE_WRAP_ITERATIONS = 600000"), 'Client private-key wrapping KDF is below the project baseline.');
ok(js.includes("crypto.subtle.encrypt") && js.includes("AES-GCM"), 'Client AES-GCM message encryption missing.');
ok(js.includes("deriveAuthSecret") && server.includes("normalizeAuthSecret"), 'Client-derived authentication secret flow missing.');
ok(!server.includes("req.body?.phrase"), 'Recovery phrase must never be accepted by the v4.5 server API.');
ok(!server.includes("const text = sanitizeString(req.body?.text"), 'Message endpoint must not accept plaintext message bodies.');
ok(/مشفّرة من طرف إلى طرف|التشفير الطرفي/.test(html), 'Main UI must disclose E2EE status.');
ok(!/واجهة المحادثات تجريبية|قيد التطوير/.test(html), 'Main messaging UI must not be labelled experimental or under development.');

for (const required of ['.env', 'data/store.enc', 'data/users.json', 'data/*.bak*']) {
  ok(gitignore.includes(required), `.gitignore missing ${required}`);
}

ok(/^5\./.test(String(pkg.dependencies?.express || '').replace(/^\^/, '')), 'Express 5.x is required for async error propagation in this project.');
ok(Number(String(pkg.dependencies?.['express-rate-limit'] || '').replace(/^[^0-9]*/, '').split('.')[0]) >= 8, 'Use a current express-rate-limit major.');

const secretPatterns = [
  /-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----/,
  /TWILIO_AUTH_TOKEN\s*=\s*[^\s<]+/i,
  /(?:^|\n)DATA_ENCRYPTION_KEY=[A-Za-z0-9+/]{40,}={0,2}(?:\n|$)/
];
const sourceForSecrets = [server, js, html, read('.env.example'), read('scripts/setup.js')].join('\n');
for (const pattern of secretPatterns) ok(!pattern.test(sourceForSecrets), `Possible committed secret matched ${pattern}`);

if (errors.length) {
  console.error('Source security audit FAILED:');
  for (const error of errors) console.error(`- ${error}`);
  process.exit(1);
}

console.log('Source security audit passed.');
console.log(`Recovery list: ${words.length} unique words; new-key entropy: ${Math.log2(words.length) * 16} bits.`);
console.log(`DOM check: ${ids.length} unique IDs; ${refs.length} JS element references resolved.`);
