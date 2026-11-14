# HOT Wallet Auto Claim Bot (Node.js)

Node.js port dari `bot.py` — bot otomatis claim harian $HOT untuk akun NEAR di game **game.hot.tg**.

## Fitur

- Claim otomatis saat storage full (bukan delay fix)
- Rotasi RPC server kalau kena rate limit (429)
- Anti-bot: jitter 5–90 menit setelah storage full, sebaran awal akun
- Auto-resolve `account_id` dari private key (via nearblocks)
- Charge gas fee otomatis kalau NEAR < 0.09 (bayar pakai HOT)
- JWT auth ke backend API0.herewallet.app
- Multi-akun, state disimpan di `data/state.json`
- Logging ANSI + flat file log di `data/bot.log`

## Struktur proyek

```
.
├── index.js           # entry point (main loop)
├── package.json       # deps & scripts
├── README.md          # ini
├── .gitignore         # jangan upload data/ & node_modules/
├── accounts.example.json   # contoh accounts.json (ganti private key)
└── data/              # di-generate otomatis (bukan repo)
    ├── accounts.json
    ├── state.json
    └── bot.log
```

## Setup

1. **Clone & install deps**
   ```bash
   npm install
   ```

2. **Siapkan akun**
   ```bash
   cp accounts.example.json data/accounts.json
   ```
   Isi `data/accounts.json` dengan daftar akun:
   ```json
   {
     "accounts": [
       {
         "account_id": "your.near.account",
         "private_key": "ed25519:XXXX..."
       }
     ]
   }
   ```
   - `account_id` bersifat opsional — kalau kosong, bot akan otomatis resolve dari private key via nearblocks API.
   - **Jangan** kirim `accounts.json` atau private key ke mana pun. File ini hanya di-simpan lokal.

3. **Jalankan**
   ```bash
   npm start
   ```

## Cara kerja

1. Baca `data/accounts.json` → cek `account_id`, kalau kosong resolve dari PK.
2. Hitung kapan storage full masing-masing akun (berdasarkan `storage_level` dari `get_user` view).
3. Setiap akun tunggu sampai storage full + jitter 5–90 menit, lalu claim.
4. Saat claim:
   - Ambil `game_state` dari `game.hot.tg` via RPC `view`
   - Request signature ke backend API0.herewallet.app
   - Daftarin public key ke `intents.near` (1x per akun)
   - Auth ke backend → dapat JWT
   - Kirim transaksi `l2_claim` via RPC `broadcast_tx_commit`
5. Simpan state (next claim time, balance, etc.) ke `data/state.json`.
6. Ulangi setiap 60 detik.

## Catatan penting

- **Private key**: disimpan di `data/accounts.json`. Jangan commit atau bagikan file ini.
- **RPC rate limit**: bot menyediakan 4 RPC endpoint dan berputar kalau ada yg kena 429.
- **NEAR balance < 0.09**: kalau saldo HOT cukup (>= 0.02 HOT), bot otomatis setel `charge_gas_fee = true` untuk bayar gas pakai HOT.
- **Storage full**: bot cek terlebih dahulu apakah storage sudah benar-benar full sebelum claim (anti-wasted claim).
- **Node version**: minimal Node.js 18 (pakai built-in `fetch`).

## License

MIT
