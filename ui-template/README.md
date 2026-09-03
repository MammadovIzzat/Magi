# Magi — UI templates

Static, real-CSS snapshots of every Magi screen and key dialog, for design work
(e.g. Claude Design). Each `.html` is a captured render of the live app populated
with sample data, linking the real `style.css` (fonts in `fonts/`). No JavaScript —
these are visual references, not the app.

Open `index.html` for the gallery, or serve the folder:

```bash
cd ui-template && python3 -m http.server 8080   # then open http://localhost:8080
```

## What's here

| File | Screen |
|------|--------|
| `login.html` | Sign-in (lock screen) |
| `engagements.html` | Engagements — the home list |
| `engagement.html` | One engagement — stats + its targets |
| `asset-folder.html` | Asset folder — targets in one engagement type |
| `target-checklist.html` | Target — attack checklist + evidence log (the main working screen) |
| `target-poc.html` | PoC target — checklist-free findings |
| `target-retest.html` | Retest target — remediation items |
| `templates-editor.html` | Template library / editor |
| `settings-local.html` | Settings — local workspace + encryption |
| `admin-panel.html` | Admin panel — team-server management |
| `modal-new-engagement.html` | Dialog — new engagement |
| `modal-add-target.html` | Dialog — add a target |
| `modal-finding.html` | Dialog — record a finding |
| `modal-connect-server.html` | Dialog — connect to a team server |

## Regenerating

These are generated from the running app (they stay in sync with `public/style.css`
and the real markup):

```bash
node scripts/gen-ui-templates.mjs
```

Screenshots in findings are replaced with a grey placeholder; everything else is the
real rendered DOM.
