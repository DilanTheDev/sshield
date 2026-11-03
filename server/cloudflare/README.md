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
