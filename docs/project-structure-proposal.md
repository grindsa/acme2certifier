# acme2certifier Project Structure Proposal

## Executive Summary

Yes, your idea makes sense and is aligned with the project’s current direction: `acme_srv` is already the core runtime, while CA/EAB/hooks are currently mostly plugin-style artifacts under `examples/`.

I recommend moving toward a **clear package-first layout** where:

- runtime code is inside a single Python package (`acme2certifier/`)
- `acme_srv` remains the core ACME server module
- handler families get dedicated namespaces
- tools become package modules
- docs and deployment examples stay separate as first-class top-level directories

This gives better maintainability, cleaner imports, easier packaging, and safer long-term evolution.

## Current State (Observed)

- Core runtime module: `acme_srv/`
- Utility scripts: `tools/`
- Handler implementations/templates mostly in `examples/ca_handler`, `examples/eab_handler`, `examples/hooks`
- Extensive docs in `docs/`
- Deployment examples in `examples/` (`Docker`, `apache2`, `nginx`, install scripts, django, trigger, etc.)
- Dynamic plugin loading relies on config file paths (`handler_file`, `eab_handler_file`, `hooks_file`)
- Packaging currently includes many files via `setup.py data_files` and also `pyproject.toml`

## Proposed Target Structure

```text
acme2certifier/
├── pyproject.toml
├── README.md
├── LICENSE
├── docs/
│   ├── architecture/
│   ├── handlers/
│   ├── deployment/
│   └── ...
├── examples/
│   ├── docker/
│   ├── apache2/
│   ├── nginx/
│   ├── install_scripts/
│   ├── django/
│   └── trigger/
├── acme2certifier/
│   ├── __init__.py
│   ├── acme_srv/
│   │   ├── __init__.py
│   │   ├── challenge_validators/
│   │   └── helpers/
│   ├── cahandlers/
│   │   ├── __init__.py
│   │   ├── skeleton.py
│   │   ├── certifier.py
│   │   └── ...
│   ├── eabhandlers/
│   │   ├── __init__.py
│   │   ├── file.py
│   │   ├── json.py
│   │   ├── sql.py
│   │   └── skeleton.py
│   ├── hookhandlers/
│   │   ├── __init__.py
│   │   ├── skeleton.py
│   │   └── email.py
│   └── tools/
│       ├── __init__.py
│       ├── a2c_cli.py
│       ├── cert_poll.py
│       └── ...
└── tests/
```

## Design Principles

1. **Single import root**: everything runtime-related importable from `acme2certifier.*`.
2. **Runtime vs example separation**: production modules in package; deployment/config examples in `examples/`.
3. **Backward compatibility first**: retain old path-based plugin loading during transition.
4. **Stepwise migration**: avoid “big bang” moves.
5. **Stable operator experience**: configuration keys continue to work while new ones are introduced.

## Why This Structure Is Better

- Reduces ambiguity between “code to run” vs “code to copy from examples”.
- Improves discoverability for contributors.
- Enables cleaner packaging and wheel installation.
- Makes handler APIs explicit and testable.
- Simplifies future refactoring, deprecation, and versioning.

## Key Implications

### 1) Import Paths and Runtime Compatibility

- Existing imports like `acme_srv.*` and references to `examples/...` handlers may break if moved directly.
- Mitigation: provide compatibility shim modules and dual import support during migration.

### 2) Configuration Compatibility

- Existing deployments reference file paths such as:
  - `handler_file: examples/ca_handler/...`
  - `eab_handler_file: examples/eab_handler/...`
  - `hooks_file: examples/hooks/...`
- Mitigation:
  - keep path-based loading working
  - add module-based loading options (e.g. `handler_module`, `eab_handler_module`, `hooks_module`)
  - document precedence and deprecation timeline

### 3) Packaging and Install Layout

- Current `setup.py` `data_files` strategy is broad and path-specific.
- Moving runtime code into package namespaces requires packaging cleanup and clearer include rules.
- Mitigation: migrate toward `pyproject.toml` + setuptools package discovery and explicit package data.

### 4) CI/CD and Tests

- Workflows currently copy skeleton files into `acme_srv/` for tests.
- After restructuring, workflow paths and fixtures must be updated.
- Mitigation: stage CI updates in the same migration phase as code movement and keep temporary compatibility copies.

### 5) Documentation and User Guidance

- Existing docs reference old paths in examples and tools.
- Mitigation: update docs in lockstep with each migration phase and provide a “migration cheatsheet”.

## Recommended Migration Scenarios

### Scenario A — Conservative (Recommended)

**Goal:** zero/minimal user disruption.

1. Introduce new package namespaces (`acme2certifier.cahandlers`, `eabhandlers`, `hookhandlers`, `tools`) while keeping old paths.
2. Add compatibility wrappers at old locations.
3. Update loader logic to support both file-based and module-based handlers.
4. Migrate docs and examples gradually.
5. Deprecate old paths after at least one major/minor release cycle.

**Pros:** safest, easiest adoption.  
**Cons:** temporary duplication and maintenance overhead.

### Scenario B — Phased but Faster

**Goal:** faster cleanup with controlled breakage.

1. Move modules and update imports.
2. Provide short-term wrappers only for critical paths.
3. Announce strict deprecation schedule.

**Pros:** shorter transition.  
**Cons:** higher risk for existing deployments.

### Scenario C — Big Bang

**Goal:** immediate final structure.

1. Move all modules in one release.
2. Remove old paths directly.

**Pros:** fastest technical completion.  
**Cons:** highest migration risk; not recommended for broad user base.

## Implementation Plan

### Phase 0: Preparation

- Define target package layout and naming conventions.
- Decide canonical handler module names.
- Define backward compatibility policy and deprecation windows.
- Freeze restructuring scope (avoid mixing unrelated refactors).

### Phase 1: Introduce New Namespaces (No Breaking Changes)

- Create `acme2certifier/` package root.
- Add `acme2certifier/acme_srv` and new handler/tool subpackages.
- Keep existing top-level modules as compatibility wrappers or aliases.
- Add tests validating old and new import paths.

### Phase 2: Loader and Config Dual Support

- Extend plugin loading to accept module-based entries in addition to file paths.
- Keep current config keys functional.
- Add structured warnings when deprecated path-based patterns are used.
- Document new configuration examples.

### Phase 3: Move Handler Implementations

- Move CA/EAB/hooks implementations to dedicated package subdirectories.
- Keep example-only templates/config snippets in `examples/`.
- Update tests, fixtures, and workflow scripts to new locations.

### Phase 4: Package/Build Cleanup

- Align build metadata on `pyproject.toml`.
- Simplify `setup.py` compatibility story (or phase it out if no longer required).
- Ensure wheel/sdist include required docs/examples artifacts.

### Phase 5: Documentation and Migration Guide

- Update all path references in docs.
- Add “old path → new path” mapping table.
- Publish migration guidance for operators and contributors.

### Phase 6: Deprecation Enforcement

- After agreed grace period, remove legacy wrappers.
- Remove deprecated config behavior.
- Keep one release of explicit migration warnings before final removal.

## Risk Matrix (High-Level)

- **High:** breaking existing `acme_srv.cfg` file-path plugins  
  **Control:** dual support + warnings + migration guide
- **High:** CI and packaging regressions after file moves  
  **Control:** incremental moves + per-phase validation
- **Medium:** doc drift during phased rollout  
  **Control:** phase-gated documentation updates
- **Medium:** temporary code duplication  
  **Control:** explicit end-of-life dates for wrappers

## Concrete Next Steps

1. Approve target namespace names and compatibility strategy.
2. Implement Scenario A with phased delivery.
3. Start with namespace introduction + loader dual-support as first PR.
4. Split handler migration into small PRs by handler family (CA/EAB/hooks).
5. Finalize with packaging cleanup and deprecation notices.

## Suggested “Definition of Done” for the Restructure

- New package layout implemented.
- Old configurations still functional (during transition window).
- CI green with updated paths.
- Documentation fully updated, including migration mapping.
- Deprecation timeline documented and communicated.
