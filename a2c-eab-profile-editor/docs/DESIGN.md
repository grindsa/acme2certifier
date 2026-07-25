# Design notes

## UX

- Master/detail: keyid list (left) + sectioned editor (center) + optional YAML preview (right).
- Sections from template: HMAC, CA handler, Challenge, Authorization, Order, Extra.
- Template source screen: bundled / local path / URL + CA overlay selector.
- Subject DN editor supports string, list, or `*` per RDN (RFC 3039 attribute names).

## Template-driven forms

The UI must not hard-code CA-handler field inventories. Field definitions live in:

- `templates/kid_profiles.template.yaml`
- `templates/overlays/<handler>.yaml`

Unknown document keys are editable under Extra and must round-trip.

## Visual direction

Match `docs/mockups/*`: light cool-gray surface, teal accents, utility density, no purple “AI SaaS” theme.
