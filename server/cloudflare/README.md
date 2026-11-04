# sshield sync server (Cloudflare Workers, free plan)

Stores your **already encrypted** vault so your devices stay in sync. The Worker only ever
holds ciphertext keyed by a hash of a token derived from your account name + master password.

Free-plan limits (Cloudflare, check current numbers): ~100k requests/day, 1 GB KV storage,
1,000 KV writes/day — far more than one person needs.

## Deploy (one time, ~2 minutes)

```bash
cd server/cloudflare
npx wrangler login
npx wrangler kv namespace create VAULTS      # copy the printed id into wrangler.toml
npx wrangler deploy                          # prints https://sshield-sync.<you>.workers.dev
```

## Use it

In sshield: Settings → Security & Sync → *Sync server*: paste the Worker URL, choose an account
name, and press **Upload this vault**. On another device: unlock/create nothing — choose
**Download existing vault** on the lock screen's sync section, enter the same account + master password.

## Notes

- KV is eventually consistent and has no transactions; the `If-Match` revision check protects
  against the normal "two devices edited" case, not against two writes in the same second.
- Changing the master password re-keys the vault: push from that device, then re-download elsewhere.
- Anyone who learns your account name can try guessing your password offline against the stored blob
  (same as for any cloud-stored password vault) — use a strong master password.

## Shared terminal sessions

The same Worker relays live shared terminals through a Durable Object (one per session; the
free plan supports SQLite-backed Durable Objects). In sshield click **🔗 Share** on a terminal tab,
send the link, and the other person pastes it under **🔗 Join**.

- Frames are end-to-end encrypted (XChaCha20-Poly1305). The key lives only in the link; the relay
  forwards ciphertext and never sees terminal contents.
- Every frame carries a per-connection sender id and a strictly increasing counter inside the
  encryption, and typed input also carries the host's per-session epoch. A relay that replays,
  reorders or drops frames is detected: replays are discarded (the host shows a "replayed frame(s)
  blocked" warning), and a viewer that sees a gap re-syncs from a fresh snapshot.
  Residual: a hostile relay can still delay or withhold frames, or end the session - it just can't
  forge or repeat them.
- Viewers are read-only until the host ticks *Allow viewers to type*; the host can stop any time.
- Anyone holding the link can watch, so treat it like a password. Up to 8 viewers per session.
- Redeploy after pulling updates: `npx wrangler deploy` (the `[[migrations]]` block creates the class).
- Local test: `npx wrangler dev --local --port 8799`, then
  `SSHIELD_RELAY=http://localhost:8799 cargo test -p sshield-core --test relay`.
