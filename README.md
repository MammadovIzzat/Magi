# MAGI

*The pentester's familiar.*

Engagement-based checklist, target tracker and evidence log. **Web app + CLI**, sharing one local SQLite DB.
Add assets (Web, IP, Subnet, Domain, AD, API, Mobile, Container); each gets a tailored
attack checklist. Answer trigger questions ("Is there a login?") and the app spawns the
matching follow-up checklist (login/register/upload/injection attacks…). Record findings
(raw HTTP requests, creds, vulns) and export a Markdown report.

> For authorized security testing only.

## Run it

```bash
npm install
npm start          # http://localhost:4173
```

No native build step: uses Node's built-in `node:sqlite` (Node 22.5+). Data lives in `./data/magi.db` (an existing `checklister.db` is picked up automatically).

### Login

On first run an account is created and **its password is printed once** in the startup log —
there is no default password. Save it, or set your own up front:

```bash
MAGI_USER=me MAGI_PASS=a-long-passphrase npm start
```

Change it later from the account bar (🔑); doing so signs out every other session.
Auth is a session-cookie gate over the whole app (all signed-in users share the same projects).

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

`node cli.js` with no args prints all commands.

## Asset types & content

Roughly 580 checklist items ship across 8 types, split between the base checklist, the
follow-up checklists triggers spawn, and the catalog entries selects unfold.

| Type | Covers |
|------|--------|
| **web** | recon/fingerprint, discovery, auth, injection, upload, access control, session, and protocol/cache/infra — with deep-dives for login, registration, password reset, MFA, OAuth/SSO, upload, injection, GraphQL, race conditions, cache poisoning and 403 bypass |
| **ip** | full/UDP scans, OS guess, per-service triggers (SSH, FTP, SMB, HTTP, RDP, DB, SNMP, LDAP, SMTP, NFS, Redis/Elastic, WinRM), exploitation and post-exploitation with a local-privesc deep-dive |
| **subnet** | host discovery, sweeps, poisoning/relay, segmentation and egress testing, triage |
| **domain** | DNS/OSINT, ASN, subdomain enum + takeover, email posture, public exposure & leaks |
| **ad** | enumeration + BloodHound, AS-REP/Kerberoast/spray, escalation and lateral movement, domain compromise — with deep-dives for AD CS (ESC1-16), delegation, NTLM coercion/relay and ACL abuse |
| **api** | surface mapping, OWASP API Top 10 (BOLA, BFLA, BOPLA, resource consumption, inventory), with JWT and GraphQL deep-dives |
| **mobile** | static, dynamic and backend/business-logic phases (storage, deep links, WebView, pinning, IPC) |
| **container** | image & supply chain, runtime/escape, Kubernetes, cloud identity & blast radius |

**Tech catalogs**: selecting a fingerprinted stack unfolds attacks specific to it — 30 entries
covering Nginx/Apache/IIS/Tomcat, Laravel, Next.js, Angular, WordPress, Django, Flask, Rails,
ASP.NET, Drupal, Joomla, Magento, SharePoint, Jenkins, GitLab, Jira/Confluence, Grafana,
JBoss, WebLogic, Struts, ColdFusion, Elastic, Citrix and GraphQL — plus 8 WAF/CDN bypass sets.

Add your own content in the **✎ Templates** editor (no restart needed), or edit
`seed/templates.js` and run `node cli.js reseed <type>` to reinstall it as the default.
You can also add custom items and findings per-asset directly in the UI.

## Project layout

```
server.js            Express API + static host
db.js                node:sqlite schema, seeding & auth hashing
seed/templates.js    shipped checklist content (the factory default)
cli.js               command-line interface
public/              vanilla-JS single-page UI
data/magi.db         your data — client-confidential, gitignored
public/fonts/        self-hosted webfonts (Magi never calls out to a CDN)
```

Templates live in the DB (`tpl_types`, `tpl_items`, `tpl_groups`, `tpl_group_items`) once
seeded, which is what makes them editable in the UI. `seed/templates.js` is the source those
tables are populated from on first run and on `reseed`.
