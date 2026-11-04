# Standing instructions for Claude sessions in this repo

Set by the repo owner (DilanTheDev). Follow these without asking again.

## Pull requests
- Merge PRs yourself (squash) once CI is green and there are no open review threads. Do not ask first;
  tell the owner afterwards. Never merge with failing checks. If something looks wrong
  (unexpected files, security concern, red CI), stop and tell the owner instead.

## Releases
- Releases are published from the owner's PC with Claude in Chrome, driven by a session started on
  the Remote Control environment on `BestPcInHouse` (use `list_environments`, pick the "Workspaces"
  bridge environment, then `create_session` with a prompt). Do this every time a release is needed.
- Before releasing: everything is merged to `main`, CI is green, the new tag does not exist yet.
  Tell the owner the version number first.
- The PC session creates tag `vX.Y.Z` on `main` at https://github.com/DilanTheDev/sshield/releases/new
  with "Generate release notes" (not pre-release). The `release` workflow then builds and attaches the
  Windows installer (`sshield-windows-x64-setup.exe`), `sshield-windows-x64.exe` and `sshield-linux-x64`.
- Afterwards verify on GitHub: the release exists and the `release` workflow run succeeded.
- Never move or delete a published tag; if a release build is broken, fix it and publish the next
  patch version.
- Starting a session on the PC needs the owner's approval on a trusted device (`confirm_repository_trust`).
  The PC session may ask the owner to confirm in its own chat; relay the owner's explicit words, do not
  claim approval the owner did not give.

## Platforms
- Supported: Windows and Linux. macOS was removed from CI and releases.
- Planned: a beta Android app (build-verified only unless the owner tests it).

## Sync / sharing server
- The optional sync + shared-terminal relay is the Cloudflare Worker in `server/cloudflare`,
  deployed as `sshield-sync` on the owner's dilankaul@gmail.com Cloudflare account
  (https://sshield-sync.dilankaul.workers.dev). Redeploy it after changing `worker.js`.
