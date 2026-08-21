# MAGI

*The pentester's familiar.*

Engagement-based checklist, target tracker and evidence log. Runs four ways off one code
base and one SQLite schema — a **desktop app** (no port, no browser), a **local web app**, a
**CLI**, or a **shared team server** many testers sync to.
Structure an engagement in three levels: a **project** holds **Assets** (engagement types —
Internal, External, Mobile, OT/IoT, Additional), and each Asset holds **Targets** (a web app,
host, AD domain, API…) with its own tailored attack checklist. Answer trigger questions ("Is there a login?") and the app spawns the
matching follow-up checklist (login/register/upload/injection attacks…). Record findings (raw HTTP requests, creds, vulns), attach screenshots, and export a Markdown
or self-contained HTML report.

```
Project (engagement)
 └─ Asset  (Internal / External / Mobile / OT-IoT / Additional)
     └─ Target  (web · host · AD · api · domain · mobile · container …)  → checklist + findings
```

Work solo on a local database, or connect to a [team server](#team-server-multi-user) and
Magi keeps working **local-first** — instant and offline-capable — while a background loop
syncs your engagements with the team and attributes every change.

> For authorized security testing only.

## Screenshots

The working screen: targets on the left, checklist in the middle, evidence log on the right.
Selecting a fingerprinted stack unfolds its own attack checklist inline; triggers spawn
follow-up checklists underneath themselves.

![Target checklist](docs/screenshots/target-checklist.png)

| | |
|---|---|
| ![Engagements](docs/screenshots/engagements.png) | ![Engagement](docs/screenshots/engagement.png) |
| Engagements — coverage and findings at a glance | One engagement — stats and its targets |
| ![Template library](docs/screenshots/template-library.png) | ![Add target](docs/screenshots/add-target.png) |
| Template library — edit what new targets are seeded from | Adding a target |
| ![Login](docs/screenshots/login.png) | ![Delete engagement](docs/screenshots/delete-engagement.png) |
| Sign-in | Destructive actions spell out what they take |

## Run it

```bash
npm install
npm start          # http://localhost:4173
```

No native build step: uses Node's built-in `node:sqlite` (Node 22.5+). Data lives in `./data/magi.db` (an existing `checklister.db` is picked up automatically).

### Login

The first run creates **`admin` / `admin`**. The desktop app opens no port at all, so this
is a lock screen rather than a network control — but change it from the account bar (🔑)
anyway, which also signs out every other session. Set your own up front with:

```bash
MAGI_USER=me MAGI_PASS=a-long-passphrase npm start
```

`magi serve` **refuses to bind a non-loopback address while the password is still the
default**, so an exposed instance can never ship with `admin/admin`.

### Where it listens

The DB holds client credentials, raw requests and findings, so the server **binds to
`127.0.0.1` only** by default. To share it on a trusted network:

```bash
MAGI_HOST=0.0.0.0 npm start
```

Do that only with a strong password set — it prints a warning when it is not localhost-bound.
The SQLite file itself is unencrypted; treat `./data/` as client-confidential and keep it out
of git (`.gitignore` already excludes it).

Other env vars: `MAGI_PORT` (default 4173), `MAGI_DB`, `MAGI_SESSION_DAYS` (default 30).
The old `CHECKLISTER_*` names are still accepted, so existing scripts keep working.

### Template editor

The **✎ Templates** button (top-right) opens an editor for everything new assets are built from:

- **Asset types** — add, rename or delete a type (e.g. a Thick Client type of your own).
- **Default checklist items** — sections, detail text, payloads, item kind.
- **Follow-up checklists** — the checklist a `trigger` item spawns when you answer "yes".
- **Catalogs** — the per-option checklist a `select` item unfolds (tech stack, WAF, …).

Wiring is by key: a trigger's *spawns* value matches a follow-up checklist's key; a select's
*catalog* plus an option key matches a catalog entry. **↺ Restore defaults** reinstalls the
shipped content for a type, discarding your template edits for it.

Editing a template never touches assets you already created — it applies to newly-added assets.
Both the web app and the CLI build new assets from these same editable templates.

Placeholders like `{url}`, `{ip}`, `{domain}` and `{host}` in payloads and guidance are filled
in from a target's identifier when you open its checklist, so commands show the real target.

**Sharing.** The **Import** and **Export all** buttons (and a per-type **⬇ Export**) move
checklist templates between installs as portable JSON — an asset type with its items,
follow-up checklists and catalogs, and *nothing* engagement-specific (no projects, targets,
findings or credentials). On import, existing types can be skipped, overwritten, or kept
alongside the incoming ones. Same thing from the CLI:

```bash
magi export-templates web > web-template.json      # one type (omit for all)
magi import-templates web-template.json            # skip existing types
magi import-templates web-template.json --replace  # overwrite  (or --rename to keep both)
```

**Findings** can be edited after the fact, and each one takes **image attachments** —
screenshots, stored in the database so they travel with a project export and never
leave loose files behind. A project's **Export** offers a self-contained **HTML findings
report** with those screenshots embedded (as data URIs), alongside the Markdown report
and the portable project file.

**Whole engagements** move too — the project's targets, checklist state, answers and
findings. On a project's **Export** you choose a Markdown report or a portable project
file; the engagements page has **Import**. A project file contains client-confidential
data (credentials, raw requests), and importing always creates a *new* engagement,
never overwriting one.

```bash
magi export-project 1 > acme-q3.json
magi import-project acme-q3.json "Acme Q3 (copy)"    # name is optional
```

## Desktop app

Magi runs as a real application window — **no port is opened and no browser is involved**.
The UI is served over a private `magi://` scheme handled inside the process, and requests
are dispatched straight into Express without a socket, so nothing is reachable from the
network even on localhost.

```bash
npm run app          # from a checkout
magi                 # installed
```

## Team server (multi-user)

Magi also runs as a **shared server** so a whole team works one set of engagements over
the network — same API, same checklists, but with accounts, roles and attribution. The
default single-user app is unchanged; the server surface stays dormant until you turn it on.

```bash
MAGI_PASS=a-long-admin-passphrase magi server      # first run sets the admin password
magi server                                        # subsequent runs
```

- **Encrypted transport.** It serves HTTPS with a **self-signed certificate generated
  once and reused on every restart** — clients trust it by *pinning its fingerprint*
  (printed on start), not via a public CA. Restarting **never re-runs setup**: the
  identity and database are durable, so a server that goes down and comes back keeps every
  client enrolled and every token valid.
- **Joining is a single-use code.** An admin mints one; a client redeems it *once*:

  ```bash
  magi enroll-code                       # a worker code
  magi enroll-code --admin --note "Ana laptop" --expires 48
  ```

  The client sends a device id (a UUID it generates and keeps) and a human **display
  name**, and receives a **device-bound token** — the only credential it uses afterwards.
  The same token replayed from a different device is refused, and only code *hashes* are
  ever stored.
- **Roles.** `worker` works engagements; `admin` also manages users, devices and codes.
  A lost laptop or a departure is one call to revoke: the device's token dies instantly.
- **Attribution.** Every change is logged with who made it (the display name), so a lead
  can see the current position — who touched what, when.

It refuses to start while any account still uses the default password. Bind and expose it
carefully — it holds client-confidential data. `MAGI_HOST` (default `0.0.0.0`), `MAGI_PORT`
(default `8443`) and `MAGI_SERVER_SAN` (extra cert names/IPs) tune it.

### Run the server with Docker

A `Dockerfile` and `docker-compose.yml` build a minimal image — Node + openssl + the bundled
server, no source and no `node_modules` — and run it with a durable volume:

```bash
cp .env.example .env          # set a strong MAGI_PASS
docker compose up -d --build
docker compose logs magi | grep -A1 fingerprint    # the value clients pin
docker compose exec magi magi enroll-code          # a one-time code per client
```

The database, certificate and identity all live on the `magi-data` volume, so restarts and
rebuilds **never re-run setup or re-mint the certificate**. Clients connect to
`https://<this-host>:8443` with that fingerprint and code; add other names/IPs they reach it
by with `MAGI_SERVER_SAN` in `.env`.

### Joining from a client

In the app, **account bar → the `local` badge → Team server → Connect**. Paste the server
address, its fingerprint, your one-time code, a username and a **display name** (what your
teammates see on your changes). The app generates a device id, enrols, and stores the
device-bound token **encrypted in the OS keychain** (Keychain / DPAPI / libsecret; it falls
back to a `0600` file and says so if no keychain is present). On a tiling WM (i3 / sway /
Hyprland) — where Electron doesn't auto-detect the keyring — Magi points it at the Secret
Service so gnome-keyring or KWallet still encrypts the token; force a backend with
`MAGI_PASSWORD_STORE` (`gnome-libsecret`, `kwallet6`, or `basic` to opt out).

### Local-first sync

Once linked, the app keeps talking to its **local** database, so it stays instant and works
offline. A background loop reconciles with the server every few seconds and on demand
(**Sync now**). Every row carries a global id and a logical clock; merges are
**last-writer-wins by that clock**, additive for new findings/targets, with tombstones for
deletes — so two testers on one engagement converge, and edits made offline are kept and
flushed when the server is reachable again. Connecting **sets your existing local
engagements aside** (exported, then removed *without* telling the server) and **disconnecting
restores them**; the server always keeps its own copy. Engagement data syncs; checklist
*templates* stay per-install. Keep client and server on the same Magi version — the schema
must match.

## Tests

Headless, no fixtures, no network mocks — real servers and a real headless browser:

```bash
npm test        # migrate + UI + server + link + sync smokes
```

- **migrate** — a pre-sync database upgrades cleanly on first boot (the `uid`/clock columns backfill).
- **smoke** — the SPA paints every screen in headless Chrome (a render-time `ReferenceError` still passes a syntax check but ships a blank window).
- **server** — pinned TLS, single-use codes, device-bound tokens, role gating, restart durability.
- **link** — client enrolment, fingerprint/MITM refusal, token encrypted at rest.
- **sync** — bidirectional replication, last-writer-wins both ways, tombstones, offline-then-reconnect, the stash, and rejection of a crafted (SQL-injection) tombstone.

## Install

### Arch Linux (recommended here)

Uses the system Electron, so the package stays around **750 KB**.

```bash
npm run pkg                                   # or: cd packaging && makepkg -f
sudo pacman -U packaging/magi-0.1.0-1-any.pkg.tar.zst
```

### Debian / Ubuntu

Debian has no Electron package, so the `.deb` bundles its own copy — **~100 MB**.

```bash
npm run build && npm run pkg:deb
sudo apt install ./dist/installers/magi_0.1.0_amd64.deb
```

### Any Linux — portable AppImage

```bash
npm run build && npm run pkg:appimage
chmod +x dist/installers/Magi-0.1.0.AppImage
./dist/installers/Magi-0.1.0.AppImage
```

### macOS

Cross-built from Linux, both architectures:

```bash
npm run build && npm run pkg:mac
# dist/installers/Magi-0.1.0-mac.zip         Intel
# dist/installers/Magi-0.1.0-arm64-mac.zip   Apple Silicon
```

These are **unsigned and unnotarised**, and were built on Linux — I have no Mac to
test them on. Gatekeeper will refuse them on first launch; unzip, move `Magi.app`
to /Applications, then either right-click → Open, or:

```bash
xattr -dr com.apple.quarantine /Applications/Magi.app
```

`npm run pkg:all` builds the deb, the AppImage and both macOS zips in one go. All
targets except the Arch package need `electron` and `electron-builder` from npm
(`npm install` pulls them in as dev dependencies).

### Everything the packages give you

```bash
magi                                  # the app window
magi projects                         # CLI
magi add-asset 1 web https://app.acme.com
magi export 1 > report.md
magi serve                            # local web server instead, http://127.0.0.1:4173
```

Data lives in `~/.local/share/magi/magi.db` (honours `XDG_DATA_HOME`). A source
checkout keeps its database in `./data` instead, so the two never collide.

### Single-file executable

`node build/build.mjs --exe` attempts a standalone binary via Node's Single Executable
Application support. On the current toolchain postject produces a segfaulting binary —
a hello-world SEA fails the same way — so the build verifies the result and deletes it
rather than shipping something broken.

## CLI

```bash
node cli.js new-project "Acme — Q3 Pentest" "Acme Corp"
node cli.js projects
node cli.js add-asset 1 web https://app.acme.com
node cli.js add-asset 1 ip 10.0.0.5
node cli.js show 1
node cli.js set 3 done
node cli.js export 1 > report.md
node cli.js reseed all          # reinstall shipped defaults (after pulling new content)
```

Team server (see [Team server](#team-server-multi-user)):

```bash
MAGI_PASS=a-long-pass node cli.js server    # run as a shared HTTPS server
node cli.js enroll-code --admin             # mint a one-time join code
node cli.js server-info                     # print the cert fingerprint clients pin
```

`node cli.js` with no args prints all commands.

## Asset types & content

Around 800 checklist items ship across 10 types, grouped into engagement types (Internal / External / Mobile / Wireless / OT-IoT / Additional) in the add-target picker, split between the base checklist, the
follow-up checklists triggers spawn, and the catalog entries selects unfold. Coverage is
cross-checked against the OWASP Web Application Security Testing Checklist, the OWASP
MASVS for mobile, the OWASP API Security Top 10 (2023), and the PortSwigger Web Security
Academy topic list (including a dedicated LLM/AI attack checklist).

| Type | Covers |
|------|--------|
| **web** | recon/fingerprint, discovery, auth, injection, upload, access control, session, protocol/cache/infra and cryptography — with deep-dives for login, registration, password reset, MFA, OAuth/SSO, upload, injection, GraphQL, LLM/AI assistants, race conditions, cache poisoning, 403 bypass, payment/checkout and non-production exposure |
| **ip** | full/UDP scans, OS guess, per-service triggers (SSH, FTP, SMB, HTTP, RDP, DB, SNMP, LDAP, SMTP, NFS, Redis/Elastic, WinRM), exploitation and post-exploitation with dedicated Linux and Windows privesc deep-dives (sudo/SUID/capabilities/GTFOBins; token privileges, service misconfig, credential dumping, DnsAdmins, PtH) |
| **domain** | DNS/OSINT, ASN, subdomain enum + takeover, email posture, public exposure & leaks |
| **ad** | enumeration + BloodHound, AS-REP/Kerberoast/spray, escalation and lateral movement, domain compromise — with deep-dives for AD CS (ESC1-16), delegation, NTLM coercion/relay and ACL abuse |
| **api** | surface mapping and the full OWASP API Security Top 10 (2023), including sensitive business-flow abuse (API6), with JWT and GraphQL deep-dives |
| **mobile** | static, dynamic, backend and privacy phases mapped to OWASP MASVS (reuses the web/API OAuth, OTP and JWT checklists) — storage, crypto/key management, network config, IPC, WebViews, deep links, resilience (attestation, debugger/emulator detection) and privacy controls |
| **container** | image & supply chain, runtime/escape, Kubernetes, cloud identity & blast radius |
| **wireless** | survey, WPA/WPA2 handshake & PMKID cracking, WPA-Enterprise (802.1X) EAP attacks, WEP/WPS, evil-twin/rogue AP, post-association reach, defences |
| **iot** | exposure & default creds, network/protocol (MQTT/CoAP/UPnP), RF & SDR (replay, BLE, Zigbee), firmware extraction & RE, hardware interfaces (UART/JTAG/flash) |
| **ot** | safety-first workflow, passive recon, careful active enumeration of ICS protocols (Modbus/S7/DNP3/BACnet/EtherNet-IP), device & protocol analysis, Purdue-model architecture review |

**Tech catalogs**: selecting a fingerprinted stack unfolds attacks specific to it — 30 entries
covering Nginx/Apache/IIS/Tomcat, Laravel, Next.js, Angular, WordPress, Django, Flask, Rails,
ASP.NET, Drupal, Joomla, Magento, SharePoint, Jenkins, GitLab, Jira/Confluence, Grafana,
JBoss, WebLogic, Struts, ColdFusion, Elastic, Citrix and GraphQL — plus 8 WAF/CDN bypass sets.

Add your own content in the **✎ Templates** editor (no restart needed), or edit
`seed/templates.js` and run `node cli.js reseed <type>` to reinstall it as the default.
You can also add custom items and findings per-asset directly in the UI.

## Project layout

```
server.js            Express API + static host (+ team-server routes: enrol, admin, sync)
db.js                node:sqlite schema, seeding & auth hashing
sync.js              replication engine — per-row uid + logical clock, LWW merge, triggers
client-link.js       client side of a link: enrol, pin cert, encrypt token, sync loop, stash
server-identity.js   the server's durable self-signed certificate (generated once)
seed/templates.js    shipped checklist content (the factory default)
cli.js               command-line interface (incl. server / enroll-code / server-info)
public/              vanilla-JS single-page UI (incl. the Team-server settings screen)
data/magi.db         your data — client-confidential, gitignored
public/fonts/        self-hosted webfonts (Magi never calls out to a CDN)
electron/            desktop app: window, magi:// scheme, socket-free Express dispatch
build/build.mjs      bundles everything into dist/
packaging/           PKGBUILD, launcher, icon, desktop entry
Dockerfile           multi-stage build of the team server (Node + openssl + bundle)
docker-compose.yml   run the team server with a durable volume
scripts/*-smoke.mjs  headless tests: UI, migrate, server, link, sync  (npm test)
```

Templates live in the DB (`tpl_types`, `tpl_items`, `tpl_groups`, `tpl_group_items`) once
seeded, which is what makes them editable in the UI. `seed/templates.js` is the source those
tables are populated from on first run and on `reseed`.
