const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const envPath = path.join(__dirname, '..', '.env');
if (fs.existsSync(envPath)) {
  console.log('.env already exists. Nothing changed.');
  process.exit(0);
}

const dataKey = crypto.randomBytes(32).toString('base64');
const indexKey = crypto.randomBytes(32).toString('base64');
const pepper = crypto.randomBytes(32).toString('base64url');
const content = [
  `DATA_ENCRYPTION_KEY=${dataKey}`,
  `DATA_INDEX_KEY=${indexKey}`,
  `AUTH_PEPPER=${pepper}`,
  'AUTH_PEPPER_PREVIOUS=',
  'PORT=3000',
  'NODE_ENV=development',
  'TRUST_PROXY=0',
  'APP_ORIGIN=http://localhost:3000',
  'ALLOWED_ORIGINS=',
  'MAX_DEVICES=5',
  'SESSION_IDLE_MINUTES=30',
  'SESSION_ABSOLUTE_DAYS=7',
  'SESSION_TOUCH_SECONDS=60',
  'MAX_KDF_CONCURRENCY=2',
  'MAX_KDF_QUEUE=50',
  'MAX_EPHEMERAL_CHALLENGES=5000',
  ''
].join('\n');

fs.writeFileSync(envPath, content, { mode: 0o600, flag: 'wx' });
try { fs.chmodSync(envPath, 0o600); } catch { /* best effort */ }
console.log('Created .env with fresh development secrets. Keep this file private and never commit it.');
