# Agent handoff: a2c EAB Profile Editor

## Goal

Build a **cross-platform desktop app** that creates and edits **YAML** `kid_profiles` files for [acme2certifier](https://github.com/grindsa/acme2certifier) **EAB profiling** (`kid_profile_handler`).

Primary reference in the sibling/parent repo (or upstream):

- `docs/eab_profiling.md`
- `acme2certifier/share/skeletons/eab_handler/kid_profiles.{yml,json}`
- CI fixtures: `.github/actions/wf_specific/eab_profiling/fixtures/*.json` (and `*.yml`)

## Agreed software stack

| Layer | Choice |
|--------|--------|
| Shell | **Tauri 2** (Rust) |
| UI | **SvelteKit** + TypeScript + Vite, **`@sveltejs/adapter-static`**, SPA mode (`ssr = false`) |
| Styling | Tailwind CSS + **shadcn-svelte** |
| Validation | **Zod** generated/driven from template |
| YAML I/O | `yaml` package |
| Raw editor | CodeMirror 6 |
| Tests | Vitest + Playwright |
| CI | GitHub Actions + `tauri-apps/tauri-action` |

**Do not** use React. Prefer SvelteKit SPA for Tauri (no SSR).

## Product requirements

1. New / open / save YAML `kid_profiles` files (Windows, macOS, Linux).
2. CRUD keyid entries (add, rename, modify, delete).
3. **Template-driven UI**: forms come from `templates/*.yaml`, not hard-coded field lists.
4. Import **JSON** fixtures (as used in a2c CI) → edit → export **YAML**.
5. Preserve **unknown / extra** keys on round-trip (`additionalProperties` / Extra fields panel).
6. Support `string | string[]` (common for `profile_id`, `template_name`, subject RDNs).
7. HMAC helper (generate Base64url secret).
8. Optional CA-handler **overlays** under `templates/overlays/`.

## Data model (runtime document)

```text
Record<keyid, {
  hmac: string;                    // required
  cahandler?: Record<string, unknown>;
  challenge?: Record<string, unknown>;
  authorization?: Record<string, unknown>;
  order?: Record<string, unknown>;
  [extraSection: string]: unknown; // preserve unknowns
}>
```

Field semantics and examples: see upstream `docs/eab_profiling.md` and CI fixtures. Values are often string **or** list; booleans in fixtures may be string `"True"` / `"False"` (**boolish**).

## Template system (critical)

- Default: `templates/kid_profiles.template.yaml`
- Meta-schema: `templates/template.meta.schema.json`
- Overlays: `templates/overlays/*.yaml` (`extends` + `fields_add`)
- Load order: bundled default → optional local file / URL override (user setting)
- Never strip keys absent from the template; show them under **Extra fields**
- Bump `version` in template when incompatible; app must refuse incompatible meta-schema versions gracefully

Implement:

1. Template loader + meta-schema validation
2. Overlay merge
3. Form renderer from section/field types: `string`, `secret`, `boolish`, `list`, `string_or_list`, `map`
4. Document ↔ YAML serialize/parse with stable key order where practical

## UI targets (mockups)

See `docs/mockups/`:

| File | Screen |
|------|--------|
| `mockup-01-main-editor.png` | Keyid list + CA handler form |
| `mockup-02-authorization-yaml.png` | Authorization lists + YAML preview |
| `mockup-03-template-source.png` | Template source (bundled / file / URL) + overlay |
| `mockup-04-subject-extra.png` | Subject DN whitelist + Extra fields |

Suggested routes:

- `/` — keyid master/detail (or list + editor)
- `/entries/[keyid]` — optional deep link
- `/raw` — full YAML
- `/templates` — template source settings

Visual direction: light cool-gray / teal utility UI (match mockups). Avoid purple gradients, cream/terracotta “AI brochure” look, emoji clutter.

## Suggested implementation order

1. SvelteKit static scaffold + Tauri 2 window + open/save file dialogs
2. Parse/serialize YAML + JSON import; in-memory store (Svelte 5 runes or writable)
3. Template loader + Zod/runtime validation from template
4. Section form components (`string_or_list`, list editor, secret, map/subject)
5. Extra-fields panel + unknown-key preservation tests
6. Overlay picker + template source settings persistence
7. HMAC generator
8. Vitest (IO + template merge) + Playwright smoke
9. GitHub Actions release matrix (Windows / macOS / Linux)

## CI note (while nested in acme2certifier)

Workflow path in the parent monorepo: `.github/workflows/eab-profile-editor-ci.yml`. After splitting to a standalone repo, move that file to `.github/workflows/` inside this project and drop the `a2c-eab-profile-editor/` path prefix from `defaults.run.working-directory` / `cache-dependency-path`.

## Repo hosting note

This tree currently lives under **acme2certifier** as `a2c-eab-profile-editor/` because the agent token could not `createRepository`. **Intended end state:** separate public repo e.g. `grindsa/a2c-eab-profile-editor`. When splitting:

```bash
git subtree split -P a2c-eab-profile-editor -b eab-editor-split
# create empty repo on GitHub, then:
git push git@github.com:grindsa/a2c-eab-profile-editor.git eab-editor-split:main
```

## Out of scope (v1)

- Talking to a live acme2certifier instance
- Editing `acme_srv.cfg`
- Replacing `a2c_eab_chk` (optional later: shell out or reimplement checks)

## Done when

- [ ] Open/edit/save YAML matching skeleton + CI fixture shapes
- [ ] Template + overlay change adds/removes form fields without code changes
- [ ] Unknown keys survive save
- [ ] Mockup flows covered (list/edit, authz+preview, template source, subject+extra)
- [ ] Desktop builds for Win/macOS/Linux via CI
