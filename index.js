#!/usr/bin/env node
/**
 * HOT Wallet Auto Claim Bot
 * Claim harian $HOT otomatis untuk akun NEAR (game.hot.tg).
 *
 * Node.js port dari bot.py. Menggunakan:
 *   - node:fetch         (HTTP, built-in Node 18+)
 *   - node:crypto        (SHA256, random bytes)
 *   - bs58               (base58 encode/decode)
 *   - tweetnacl          (ed25519 signing)
 *
 * Semua private key dibaca dari accounts.json (lokal, tidak pernah dikirim ke mana pun).
 *
 * @license MIT
 */

import { randomBytes, createHash } from 'node:crypto';
import { readFileSync, writeFileSync, existsSync, mkdirSync, appendFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import bs58 from 'bs58';
import nacl from 'tweetnacl';

// ── Lokasi file ────────────────────────────────────────────────────────────
const __dirname = dirname(fileURLToPath(import.meta.url));

const DATA_DIR = join(__dirname, 'data');
const ACCOUNTS_FILE = join(DATA_DIR, 'accounts.json');
const STATE_FILE = join(DATA_DIR, 'state.json');
const LOG_FILE = join(DATA_DIR, 'bot.log');

// ── Konstanta ──────────────────────────────────────────────────────────────
const RPC_URL = 'https://rpc.mainnet.near.org';
const API_BASE = 'https://api0.herewallet.app';
const CONTRACT = 'game.hot.tg';
const INTENTS_CONTRACT = 'intents.near';
const CHAIN_ID = 'mainnet';

const RPC_URLS = [
  'https://rpc.mainnet.near.org',
  'https://rpc.mainnet.fastnear.com',
  'https://near.drpc.org',
  'https://1rpc.io/near',
];
let _rpcIdx = 0;

// Delay claim: tunggu storage FULL baru claim (bukan delay fix).
const STORAGE_LEVELS = {
  20: 72e11, 21: 108e11, 22: 144e11, 23: 216e11, 24: 432e11, 25: 864e11,
};

const JITTER_AFTER_FULL_MIN_SEC = 5 * 60;
const JITTER_AFTER_FULL_MAX_SEC = 90 * 60;
const MIN_GAP_SEC = 20 * 60;

// ── Logging (ANSI warna + file log) ────────────────────────────────────────
const C = {
  RESET: '\x1b[0m',
  BOLD: '\x1b[1m',
  DIM: '\x1b[2m',
  RED: '\x1b[91m',
  GRN: '\x1b[92m',
  YLW: '\x1b[93m',
  BLU: '\x1b[94m',
  CYN: '\x1b[96m',
  GRY: '\x1b[90m',
};

const LEVEL_COLORS = {
  ERROR: C.RED,
  WARN: C.YLW,
  OK: C.GRN,
  INFO: C.CYN,
};

function log(msg, level = 'INFO', plain = false) {
  const ts = new Date().toISOString().replace('T', ' ').slice(0, 19);
  const line = plain
    ? `${msg}`
    : `${C.GRY}[${ts}]${C.RESET} ${LEVEL_COLORS[level] || C.CYN}${level.padEnd(5)}${C.RESET} ${msg}`;
  console.log(line);
  try {
    mkdirSync(DATA_DIR, { recursive: true });
    const clean = msg.replace(/\x1b\[[0-9;]*m/g, '');
    appendFileSync(LOG_FILE, `[${ts}] [${level}] ${clean}\n`);
  } catch { /* ignore */ }
}

function banner() {
  console.log(`${C.YLW}${C.BOLD}`);
  console.log('    ██╗  ██╗   ██╗   ███████╗');
  console.log('    ██║ ██╔╝   ██║   ╚════██║');
  console.log('    █████╔╝    ██║       ██║');
  console.log('    ██╔═██╗    ██║       ██║');
  console.log('    ██║  ██╗   ██║   ██╗ ██║');
  console.log('    ╚═╝  ╚═╝   ╚═╝   ╚═╝ ╚═╝');
  console.log(`${C.RESET}${C.BOLD}  HOT WALLET AUTO CLAIM${C.RESET} ${C.GRY}· tunggu storage full${C.RESET}`);
  console.log(`${C.GRY}  contract: game.hot.tg · backend: api0.herewallet.app${C.RESET}`);
  console.log(`${C.GRY}  ${'─'.repeat(48)}${C.RESET}`);
}

// ── Utilitas dasar ─────────────────────────────────────────────────────────
function base58Encode(data) {
  return bs58.encode(data);
}

function base58Decode(s) {
  return bs58.decode(s);
}

function base64Encode(data) {
  return Buffer.from(data).toString('base64');
}

function base64Decode(s) {
  return Buffer.from(s, 'base64');
}

function sha256(data) {
  return createHash('sha256').update(data).digest();
}

function randomBytesHex(len) {
  return randomBytes(len).toString('hex');
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function sleepMs(ms) {
  await sleep(ms);
}

// ── NEAR helpers ───────────────────────────────────────────────────────────
function parseNearKey(keyStr) {
  const key = keyStr.trim();
  let raw;
  if (key.startsWith('ed25519:')) {
    raw = base58Decode(key.split(':')[1]);
  } else {
    raw = base58Decode(key);
  }
  let skBytes; // 32 bytes, actual secret key
  let secretKey64; // 64 bytes, for tweetnacl sign()
  if (raw.length === 64) {
    skBytes = raw.slice(0, 32);
    secretKey64 = raw;
  } else if (raw.length === 32) {
    skBytes = raw;
    const pair = nacl.sign.keyPair.fromSeed(raw);
    secretKey64 = pair.secretKey;
  } else {
    throw new Error('Invalid NEAR private key length (expected 32 or 64 bytes)');
  }
  const pk = base58Encode(secretKey64.slice(32));
  return { sk: skBytes, sk64: secretKey64, pk: `ed25519:${pk}` };
}

// ── RPC ───────────────────────────────────────────────────────────────────
async function rpcCall(method, params) {
  const payload = {
    jsonrpc: '2.0',
    id: Date.now(),
    method,
    params,
  };
  let lastErr = null;
  for (let attempt = 0; attempt < 6; attempt++) {
    const url = RPC_URLS[_rpcIdx % RPC_URLS.length];
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 30000);
      const res = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
        signal: controller.signal,
      });
      clearTimeout(timeoutId);
      if (res.status === 429) {
        _rpcIdx++;
        throw new Error('429 rate limit, ganti RPC');
      }
      const data = await res.json();
      if (data.error) {
        throw new Error(`RPC error: ${JSON.stringify(data.error)}`);
      }
      return data.result;
    } catch (e) {
      lastErr = e;
      _rpcIdx++;
      await sleepMs(1500 * (attempt + 1));
    }
  }
  throw new Error(`semua RPC gagal: ${lastErr?.message || 'unknown'}`);
}

function argsToBase64(argsDict) {
  return base64Encode(JSON.stringify(argsDict));
}

async function viewFunction(contract, method, argsDict) {
  const argsB64 = argsToBase64(argsDict);
  const res = await rpcCall('query', {
    request_type: 'call_function',
    finality: 'final',
    account_id: contract,
    method_name: method,
    args_base64: argsB64,
  });
  if (res?.error) {
    throw new Error(`view error ${contract}:${method}: ${JSON.stringify(res.error)}`);
  }
  let inner = res?.result || res;
  while (inner && typeof inner === 'object' && inner.result && typeof inner.result === 'object') {
    inner = inner.result;
  }
  const arr = inner?.result ?? inner;
  let raw;
  if (Array.isArray(arr)) {
    raw = Buffer.from(arr);
  } else if (arr && typeof arr === 'object') {
    raw = Buffer.from(arr);
  } else {
    raw = Buffer.from(arr);
  }
  return raw.length ? JSON.parse(raw.toString('utf-8')) : null;
}

async function resolveAccountId(publicKey) {
  const url = `https://api.nearblocks.io/v1/keys/${publicKey}`;
  for (let attempt = 0; attempt < 6; attempt++) {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 15000);
      const res = await fetch(url, { signal: controller.signal });
      clearTimeout(timeoutId);
      if (res.status === 429) {
        await sleepMs(20000);
        continue;
      }
      if (res.status !== 200) return null;
      const data = await res.json();
      const keys = (data.keys || []).filter(k => k.account_id);
      if (keys.length === 0) return null;
      return keys[0].account_id;
    } catch (e) {
      if (e.name === 'AbortError') throw e;
      await sleepMs(10 * (attempt + 1) + 15);
    }
  }
  return null;
}

async function autoResolveAccountIds(accounts) {
  let changed = false;
  for (const acc of accounts) {
    if (acc.account_id) continue;
    if (!acc.private_key) continue;
    try {
      const { pk } = parseNearKey(acc.private_key);
      const aid = await resolveAccountId(pk);
      if (aid) {
        acc.account_id = aid;
        changed = true;
        log(`  resolve: ${pk.slice(0, 25)}... -> ${aid}`, 'OK');
      } else {
        log(`  resolve: ${pk.slice(0, 25)}... -> TIDAK KETEMU akun`, 'ERROR');
      }
    } catch (e) {
      log(`  resolve error: ${e.message}`, 'ERROR');
    }
    await sleepMs(7000);
  }
  return changed;
}

async function getAccountState(accountId) {
  const res = await rpcCall('query', {
    request_type: 'view_account',
    finality: 'final',
    account_id: accountId,
  });
  if (res?.error) return null;
  return res;
}

async function getAccessKey(accountId, publicKey) {
  const res = await rpcCall('query', {
    request_type: 'view_access_key',
    finality: 'final',
    account_id: accountId,
    public_key: publicKey,
  });
  if (res?.error) return null;
  return res;
}

async function getRecentBlockHash() {
  const res = await rpcCall('block', { finality: 'final' });
  return res.header.hash;
}

async function getAccountNonce(accountId, publicKey) {
  const key = await getAccessKey(accountId, publicKey);
  if (!key) return null;
  return key.nonce;
}

async function isPkRegisteredIntents(accountId, publicKey) {
  try {
    const res = await viewFunction(INTENTS_CONTRACT, 'public_keys_of', { account_id: accountId });
    return res !== null && (res.includes ? res.includes(publicKey) : false);
  } catch {
    return false;
  }
}

async function registerPkIntents(sk64, accountId, pkStr) {
  const nonce = (await getAccountNonce(accountId, pkStr)) || 0;
  const blockHash = await getRecentBlockHash();
  const actions = [{
    functionCall: {
      methodName: 'add_public_key',
      args: { public_key: pkStr },
      gas: 80n * 10n ** 12n,
      deposit: 1n,
    },
  }];
  const signed = buildSignedTx(sk, accountId, INTENTS_CONTRACT, actions, nonce, blockHash, pkStr);
  const txRes = await sendTx(signed);
  if (txRes?.error) {
    throw new Error(`add_public_key failed: ${txRes.error}`);
  }
  await sleepMs(3000);
  return true;
}

// ── Serialisasi transaksi NEAR ─────────────────────────────────────────────
function writeString(buf, s) {
  const data = Buffer.from(s, 'utf-8');
  const lenBuf = Buffer.alloc(4);
  lenBuf.writeUInt32LE(data.length, 0);
  return Buffer.concat([buf, lenBuf, data]);
}

function writeAction(buf, a) {
  const fc = a.functionCall;
  let out = Buffer.alloc(0);
  out = Buffer.concat([out, Buffer.from([2])]); // ActionVariant::FunctionCall
  const methodName = Buffer.from(fc.methodName, 'utf-8');
  out = Buffer.concat([out, Buffer.from(methodName)]);
  const args = Buffer.from(JSON.stringify(fc.args), 'utf-8');
  out = Buffer.concat([out, Buffer.from(args)]);
  const gasBuf = Buffer.alloc(8);
  gasBuf.writeBigUInt64LE(BigInt(fc.gas), 0);
  out = Buffer.concat([out, gasBuf]);
  const depositBuf = Buffer.alloc(8);
  depositBuf.writeBigUInt64LE(BigInt(fc.deposit), 0);
  out = Buffer.concat([out, depositBuf]);
  return Buffer.concat([buf, out]);
}

function serializeTransaction(tx) {
  let buf = Buffer.alloc(0);
  buf = writeString(buf, tx.signerId);
  buf = Buffer.concat([buf, Buffer.from([0])]); // ed25519 flag
  const pkRaw = base58Decode(tx.publicKey.split(':')[1]);
  buf = Buffer.concat([buf, pkRaw]);
  const nonceBuf = Buffer.alloc(8);
  nonceBuf.writeBigUInt64LE(BigInt(tx.nonce), 0);
  buf = Buffer.concat([buf, nonceBuf]);
  buf = writeString(buf, tx.receiverId);
  const blockHash = base58Decode(tx.blockHash);
  buf = Buffer.concat([buf, blockHash]);
  const actionsBuf = Buffer.alloc(4);
  actionsBuf.writeUInt32LE(tx.actions.length, 0);
  buf = Buffer.concat([buf, actionsBuf]);
  for (const a of tx.actions) {
    buf = writeAction(buf, a);
  }
  return buf;
}

// ── Signed transaction ────────────────────────────────────────────────────
function signMessage(msg, sk64) {
  return Buffer.from(nacl.sign.detached(msg, sk64));
}

function buildSignedTx(sk64, accountId, receiverId, actions, nonce, blockHash, pkStr) {
  const tx = {
    signerId: accountId,
    publicKey: pkStr,
    nonce,
    receiverId,
    actions,
    blockHash,
  };
  const txBytes = serializeTransaction(tx);
  const hash = sha256(txBytes);
  const sig = signMessage(hash, sk64);
  const signedBorsh = Buffer.concat([txBytes, Buffer.from([0]), sig]);
  return base64Encode(signedBorsh);
}

async function sendTx(signedTx) {
  return rpcCall('broadcast_tx_commit', [signedTx]);
}

// ── Intents signature (untuk auth backend) ─────────────────────────────────
function signAuthIntent(signingKey64, accountId) {
  const seed = randomBytesHex(32);
  const nonceTag = `hot_auth_intent_${seed}`;
  const nonceB64 = base64Encode(sha256(Buffer.from(nonceTag, 'utf-8')));
  const deadline = new Date(Date.now() + 24 * 60 * 60 * 1000)
    .toISOString()
    .replace('+00:00', '.000Z');
  const payloadStr = JSON.stringify({
    signer_id: accountId.toLowerCase(),
    deadline,
    intents: [],
    nonce: nonceB64,
    verifying_contract: INTENTS_CONTRACT,
  }, null, '');
  const sig = signMessage(Buffer.from(payloadStr, 'utf-8'), signingKey64);
  return {
    intent: {
      signature: `ed25519:${base58Encode(sig)}`,
      public_key: `ed25519:${base58Encode(signingKey64.slice(32))}`,
      standard: 'raw_ed25519',
      payload: payloadStr,
    },
    seed,
  };
}

// ── Backend API ────────────────────────────────────────────────────────────
class HotApi {
  constructor(deviceId = 'hot-claimer-bot') {
    this.deviceId = deviceId;
    this.jwt = null;
  }

  _headers() {
    const h = {
      'Content-Type': 'application/json',
      'Device-Id': this.deviceId,
      'DeviceId': this.deviceId,
      'Platform': 'web',
      'Version': '1.0',
      Origin: 'https://app.hot-labs.org',
      Referer: 'https://app.hot-labs.org/',
      'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36',
    };
    if (this.jwt) {
      h['Authorization'] = this.jwt;
    }
    return h;
  }

  async post(path, body) {
    const url = `${API_BASE}${path}`;
    for (let attempt = 0; attempt < 3; attempt++) {
      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 30000);
        const res = await fetch(url, {
          method: 'POST',
          headers: this._headers(),
          body: JSON.stringify(body),
          signal: controller.signal,
        });
        clearTimeout(timeoutId);
        if (res.status === 401) {
          throw new Error('JWT invalid/expired - need re-auth');
        }
        if (res.status === 403) {
          const text = await res.text();
          throw new Error(`Forbidden: ${text.slice(0, 200)}`);
        }
        if (res.status >= 500) {
          throw new Error(`HTTP ${res.status}`);
        }
        return res.json();
      } catch (e) {
        if (attempt === 2) throw e;
        await sleepMs(2000 * (attempt + 1));
      }
    }
  }

  async auth(signingKey, accountId, publicKey) {
    const { intent, seed } = signAuthIntent(signingKey, accountId);
    const body = {
      imported: true,
      near_account_id: accountId,
      device_id: this.deviceId,
      device_name: 'HOTClaimBot/1.0',
      ref_code: null,
      auth_intent: intent,
      auth_seed: seed,
    };
    log(`  auth: POST /api/v1/user/auth (account=${accountId})`);
    const res = await this.post('/api/v1/user/auth', body);
    if (!res.token) {
      throw new Error(`auth failed: ${JSON.stringify(res).slice(0, 300)}`);
    }
    this.jwt = res.token;
    log('  auth: JWT acquired ✓');
    return this.jwt;
  }

  async getClaimSignature(gameState, chargeGasFee = false) {
    const body = { game_state: gameState };
    const res = await this.post('/api/v1/user/hot/claim/signature', body);
    if (!res.signature) {
      throw new Error(`signature endpoint: ${JSON.stringify(res).slice(0, 300)}`);
    }
    return res;
  }
}

// ── Game state ─────────────────────────────────────────────────────────────
async function getGameState(accountId) {
  return viewFunction(CONTRACT, 'get_user', { account_id: accountId });
}

// ── Claim satu akun ────────────────────────────────────────────────────────
async function claimAccount(accountId, privateKey, chargeGasFee = false) {
  const { sk64, pk: pkStr } = parseNearKey(privateKey);

  // 1) cek akun & access key
  const st = await getAccountState(accountId);
  if (!st) {
    return { ok: false, error: `Akun NEAR ${accountId} tidak ditemukan` };
  }
  const nearBalance = Number(BigInt(st.amount) / 10n ** 24n) / 1000;
  log(`  balance: ${nearBalance.toFixed(4)} NEAR`);

  // 2) game state
  const gs = await getGameState(accountId);
  if (!gs) {
    return { ok: false, error: 'Belum terdaftar di game.hot.tg (get_user null)' };
  }
  const lastClaimNs = gs.last_claim || 0;
  const lastClaimS = lastClaimNs / 1e9;
  const balanceHot = (gs.balance || 0) / 1e6;
  log(`  game: balance=${balanceHot.toFixed(4)} HOT, storage=${gs.storage}, last_claim=${new Date(lastClaimS * 1000).toISOString().slice(11, 19)}`);

  // 2c) penjaga kedua: jangan claim sebelum storage bener-bener full
  const remaining = secondsUntilFull(gs);
  if (remaining > 0) {
    return { ok: false, deferred: true, wait: remaining };
  }

  // 2b) otomatis charge_gas_fee kalau NEAR < 0.09
  if (!chargeGasFee && nearBalance < 0.09) {
    const hotNeeded = 0.02;
    if (balanceHot >= hotNeeded) {
      log(`  NEAR < 0.09 → charge_gas_fee=True (bayar pakai HOT)`);
      chargeGasFee = true;
    } else {
      log(`  WARNING: NEAR ${nearBalance.toFixed(4)} < 0.09 tapi saldo HOT ${balanceHot.toFixed(6)} juga kurang (butuh ${hotNeeded} HOT).`, 'WARN');
    }
  }

  // 3) daftarin pk ke intents.near kalau belum
  if (!(await isPkRegisteredIntents(accountId, pkStr))) {
    log(`  daftar pk ke intents.near (1x)...`, 'INFO');
    await registerPkIntents(sk64, accountId, pkStr);
    log(`  pk terdaftar ✓`, 'OK');
  }

  // 4) auth ke backend
  const api = new HotApi(`hotbot-${accountId.split('.')[0]}`);
  await api.auth(sk64, accountId, pkStr);

  // 4) minta signature
  const sigRes = await api.getClaimSignature(gs, chargeGasFee);
  log(`  signature acquired: mining_time=${sigRes.mining_time}, max_ts=${sigRes.max_ts}`);

  // 5) kirim transaksi l2_claim
  const nonce = (await getAccountNonce(accountId, pkStr)) || 0;
  const blockHash = await getRecentBlockHash();
  const actions = [{
    functionCall: {
      methodName: 'l2_claim',
      args: {
        charge_gas_fee: Boolean(chargeGasFee),
        signature: String(sigRes.signature),
        mining_time: String(sigRes.mining_time),
        max_ts: String(sigRes.max_ts),
      },
      gas: 30n * 10n ** 12n,
      deposit: 0n,
    },
  }];
  const signed = buildSignedTx(sk, accountId, CONTRACT, actions, nonce, blockHash, pkStr);
  const txRes = await sendTx(signed);

  if (txRes?.error) {
    return { ok: false, error: `TX failed: ${txRes.error}` };
  }

  const outcomes = txRes.receipts_outcome || [];
  const statuses = outcomes.map(o => o?.outcome?.status || {});
  const success = statuses.some(s => s.SuccessValue === undefined || s.SuccessValue === '' || s.SuccessValue !== '0');
  const txHash = txRes.transaction?.hash || '?';
  const newGs = await getGameState(accountId);
  const newBal = (newGs?.balance || 0) / 1e6;
  return {
    ok: true,
    tx_hash: txHash,
    balance_before: balanceHot,
    balance_after: newBal,
    mined: newBal - balanceHot,
  };
}

// ── Scheduler ──────────────────────────────────────────────────────────────
function loadAccounts() {
  if (!existsSync(ACCOUNTS_FILE)) return [];
  const data = JSON.parse(readFileSync(ACCOUNTS_FILE, 'utf-8'));
  let accounts = data.accounts || [];
  const hasUnresolved = accounts.some(a => a.private_key && !a.account_id);
  if (hasUnresolved) {
    log('Resolve account_id dari private key...', 'INFO');
    if (autoResolveAccountIds(accounts)) {
      try {
        mkdirSync(DATA_DIR, { recursive: true });
        writeFileSync(ACCOUNTS_FILE, JSON.stringify(data, null, 2));
      } catch { /* ignore */ }
    }
  }
  return accounts;
}

function loadState() {
  if (existsSync(STATE_FILE)) {
    return JSON.parse(readFileSync(STATE_FILE, 'utf-8'));
  }
  return {};
}

function saveState(state) {
  mkdirSync(DATA_DIR, { recursive: true });
  writeFileSync(STATE_FILE, JSON.stringify(state, null, 2));
}

function storageCapacityMs(storageLevel) {
  const value = STORAGE_LEVELS[storageLevel] || 864e11;
  return value / 1e6; // value -> ms
}

function secondsUntilFull(gameState) {
  const level = gameState.storage || 25;
  const capacityMs = storageCapacityMs(level);
  const lastClaimMs = (gameState.last_claim || 0) / 1e6; // ns -> ms
  const nowMs = Date.now();
  const remainingMs = capacityMs - (nowMs - lastClaimMs);
  return Math.max(0, remainingMs / 1000);
}

function accountSlotOffset(accountId, allIds) {
  const n = allIds.length;
  if (n === 1) return 0.5;
  const ranked = [...allIds].sort((a, b) => sha256(Buffer.from(a)).compare(sha256(Buffer.from(b))));
  const rank = ranked.indexOf(accountId);
  const h = parseInt(sha256(Buffer.from(accountId)).toString('hex'), 16);
  const jitter = ((h >> 40) % 1000) / 1000.0; // 0..1
  const spread = 1.0 / n;
  return (rank / n + (jitter - 0.5) * spread * 0.9) % 1.0;
}

function jitterAfterFull(accountId, cycle) {
  const seedStr = `${accountId}:${cycle}`;
  const hash = sha256(Buffer.from(seedStr));
  let s1 = hash.readUInt32LE(0);
  let s2 = hash.readUInt32LE(4);
  let rand = () => {
    s1 = (s1 * 1664525 + 1013904223) & 0xffffffff;
    s2 = (s2 * 1664525 + 1013904223) & 0xffffffff;
    return ((s1 << 16) | (s2 >>> 16)) / 0x100000000;
  };
  return rand() * (JITTER_AFTER_FULL_MAX_SEC - JITTER_AFTER_FULL_MIN_SEC) + JITTER_AFTER_FULL_MIN_SEC;
}

function alignedNextClaim(accountId, allIds, capacitySec, lastClaimSec, cycle = 0) {
  const n = allIds.length;
  if (cycle === 0) {
    const slot = accountSlotOffset(accountId, allIds);
    const T_full = lastClaimSec + capacitySec;
    const dayStart = Math.floor(T_full / 86400) * 86400;
    let slotSec = dayStart + slot * 86400;
    while (slotSec < T_full) {
      slotSec += 86400;
    }
    return slotSec;
  }
  const T_full = lastClaimSec + capacitySec;
  const jitter = jitterAfterFull(accountId, cycle);
  return T_full + jitter;
}

// ── Tabel output ───────────────────────────────────────────────────────────
function tableFromState(accounts, state) {
  const rows = [];
  for (const acc of accounts) {
    const aid = acc.account_id;
    const st = state[aid] || {};
    const nxt = st.next_claim_at || 0;
    const last = st.last_claim_ts || 0;
    const lvl = st.storage_level || 25;
    const cap = storageCapacityMs(lvl) / 1000;
    const full_h = last ? Math.max(0, (last + cap - Date.now() / 1000) / 3600) : 0;
    const wait_h = nxt ? Math.max(0, (nxt - Date.now() / 1000) / 3600) : 999;
    rows.push({ aid, hot: st.hot_balance || 0, lvl, full_h, nxt, wait_h });
  }
  tableInit(rows);
}

function tableInit(rows) {
  console.log(`\n${C.BOLD}  #  AKUN${C.RESET}            ${C.BOLD}SALDO${C.RESET}      ${C.BOLD}LVL${C.RESET} ${C.BOLD}FULL DALAM${C.RESET}  ${C.BOLD}NEXT CLAIM${C.RESET}   ${C.BOLD}STATUS${C.RESET}`);
  console.log(`${C.GRY}  ${'─'.repeat(62)}${C.RESET}`);
  const sorted = [...rows].sort((a, b) => a.wait_h - b.wait_h);
  for (let i = 0; i < sorted.length; i++) {
    const r = sorted[i];
    const slot = new Date(r.nxt * 1000).toISOString().slice(11, 16);
    const waste_h = r.wait_h - r.full_h;
    let status;
    if (waste_h <= 1.5) status = `${C.GRN}✓ optimal${C.RESET}`;
    else if (waste_h <= 4) status = `${C.YLW}~${waste_h.toFixed(0)}j nunggu${C.RESET}`;
    else status = `${C.RED}⚠ ${waste_h.toFixed(0)}j wasted${C.RESET}`;
    console.log(
      `  ${C.GRY}${String(i + 1).padStart(2)}${C.RESET} ${C.CYN}${r.aid.slice(0, 14)}${C.RESET} ` +
      `${C.YLW}${r.hot.toFixed(2).padStart(8)}${C.RESET}  ${String(r.lvl).padStart(2)}   ` +
      `${String(r.full_h).padStart(6).padEnd(6, ' ')} jam   ${C.GRN}${slot}${C.RESET}  ${status}`
    );
  }
  console.log(`${C.GRY}  ${'─'.repeat(62)}${C.RESET}`);
  const totalHot = rows.reduce((s, r) => s + r.hot, 0);
  const nextOne = sorted[0];
  console.log(`  ${C.DIM}${rows.length} akun · total ${totalHot.toFixed(2)} HOT · claim terdekat: ${nextOne?.aid} (${nextOne?.wait_h.toFixed(1)}j)${C.RESET}\n`);
}

// ── Main loop ──────────────────────────────────────────────────────────────
async function mainLoop() {
  banner();
  let accounts = loadAccounts();
  if (accounts.length === 0) {
    log(`Tidak ada akun di ${ACCOUNTS_FILE}`, 'ERROR');
    log('Buat data/accounts.json dulu (lihat README).', 'ERROR');
    return;
  }
  log(`Loaded ${accounts.length} akun`, 'OK');

  const unresolved = accounts.filter(a => !a.account_id);
  if (unresolved.length > 0) {
    for (const a of unresolved) {
      const pk = (a.private_key || '').slice(0, 25);
      log(`Akun ${pk}... di-skip: account_id tidak diketahui`, 'WARN');
    }
    accounts = accounts.filter(a => a.account_id);
    log(`${unresolved.length} akun di-skip, lanjut dengan ${accounts.length} akun`, 'WARN');
  }
  if (accounts.length === 0) {
    log('Tidak ada akun yang bisa diproses', 'ERROR');
    return;
  }

  const state = loadState();
  const allIds = accounts.map(a => a.account_id);
  const rows = [];
  for (const acc of accounts) {
    const aid = acc.account_id;
    try {
      const gs = await getGameState(aid);
      if (!gs) {
        log(`${aid}: belum terdaftar di game.hot.tg`, 'WARN');
        state[aid] = { status: 'unregistered', next_claim_at: null };
        continue;
      }
      const rem = secondsUntilFull(gs);
      const capacitySec = storageCapacityMs(gs.storage || 25) / 1000;
      const lastClaimSec = gs.last_claim ? gs.last_claim / 1e9 : 0;
      const slotTs = alignedNextClaim(aid, allIds, capacitySec, lastClaimSec, 0);
      const wait = slotTs - Date.now() / 1000;
      state[aid] = {
        status: 'waiting',
        next_claim_at: Date.now() / 1000 + wait,
        storage_level: gs.storage,
        hot_balance: (gs.balance || 0) / 1e6,
        cycle: 0,
        last_claim_ts: lastClaimSec,
      };
      rows.push({
        aid,
        hot: (gs.balance || 0) / 1e6,
        lvl: gs.storage,
        full_h: rem / 3600,
        nxt: slotTs,
        wait_h: wait / 3600,
      });
    } catch (e) {
      log(`${aid}: ${e.message}`, 'ERROR');
      state[aid] = { status: 'error', error: e.message };
    }
  }
  saveState(state);
  if (rows.length > 0) {
    tableInit(rows);
  }

  while (true) {
    const now = Date.now() / 1000;

    for (const acc of accounts) {
      const aid = acc.account_id;
      let st = state[aid];
      if (!st) {
        st = state[aid] = { status: 'waiting', next_claim_at: now + 300 };
        saveState(state);
      }
      if (st.status === 'done_cycle' || st.status === 'unregistered') continue;
      if (!st.next_claim_at) continue;
      if (now < st.next_claim_at) continue;

      log(`--- CLAIM ${aid} ---`, 'INFO');
      try {
        const res = await claimAccount(aid, acc.private_key);
        if (res.ok) {
          let nextSlotStr = '';
          try {
            const gs2 = await getGameState(aid);
            if (gs2) {
              const cap2 = storageCapacityMs(gs2.storage || 25) / 1000;
              const last2 = gs2.last_claim ? gs2.last_claim / 1e9 : 0;
              const cyc = st.cycle ? st.cycle + 1 : 1;
              const nts = alignedNextClaim(aid, allIds, cap2, last2, cyc);
              st.next_claim_at = nts;
              st.cycle = cyc;
              st.storage_level = gs2.storage;
              st.hot_balance = (gs2.balance || 0) / 1e6;
              nextSlotStr = new Date(nts * 1000).toISOString().slice(11, 16);
              st.last_claim_ts = last2;
            }
          } catch (e) {
            log(`${aid}: gagal baca state setelah claim: ${e.message}`, 'WARN');
            st.next_claim_at = now + 3600;
          }
          st.status = 'waiting';
          st.last_tx = res.tx_hash;
          st.last_mined = res.mined;
          st.hot_balance = res.balance_after;
          saveState(state);
          log(`✅ ${aid} · +${res.mined.toFixed(2)} HOT · saldo ${res.balance_before.toFixed(2)} → ${res.balance_after.toFixed(2)} · next ${nextSlotStr}`, 'OK');
          tableFromState(accounts, state);
        } else {
          if (res.deferred) {
            const jam = res.wait / 3600;
            log(`⏳ ${aid} storage belum full — ${jam.toFixed(1)} jam lagi. Claim ditunda, timer gak di-reset.`, 'WARN');
            st.next_claim_at = now + Math.min(res.wait, 3600);
            st.status = 'waiting';
          } else {
            log(`❌ ${aid} gagal: ${res.error}`, 'ERROR');
            st.status = 'error';
            st.error = res.error;
            st.next_claim_at = now + 600;
            st.status = 'waiting';
          }
        }
      } catch (e) {
        log(`❌ ${aid} exception: ${e.message}`, 'ERROR');
        st.status = 'error';
        st.error = e.message;
        st.next_claim_at = now + 600;
        st.status = 'waiting';
      }
      saveState(state);
      await sleepMs(3000); // jeda antar akun
    }

    await sleepMs(60000); // cek lagi setiap 60 detik
  }
}

// ── Entry point ─────────────────────────────────────────────────────────────
const isMain = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;

if (isMain) {
  mainLoop().catch(e => {
    log(`FATAL: ${e.message}`, 'ERROR');
    process.exit(1);
  });
}

// Exported for tests / imports
export {
  base58Encode,
  base58Decode,
  base64Encode,
  base64Decode,
  sha256,
  randomBytesHex,
  parseNearKey,
  serializeTransaction,
  buildSignedTx,
  signAuthIntent,
  HotApi,
  claimAccount,
  loadAccounts,
  loadState,
  saveState,
  storageCapacityMs,
  secondsUntilFull,
  mainLoop,
};

// Required for pathToFileURL
import { pathToFileURL } from 'node:url';
