/**
 * Placeholder: load + validate templates/kid_profiles.template.yaml
 * and merge overlays (fields_add). See AGENTS.md.
 */
import type { ProfileTemplate } from '../schema/types';

export async function loadBundledTemplate(): Promise<ProfileTemplate> {
	throw new Error('loadBundledTemplate not implemented — wire template fetch/fs next');
}

export function mergeOverlay(base: ProfileTemplate, overlay: ProfileTemplate): ProfileTemplate {
	// Minimal stub: replace sections by id when overlay provides fields_add
	const sections = base.sections.map((section) => {
		const over = overlay.sections?.find((s) => s.id === section.id);
		if (!over?.fields_add?.length) return section;
		const names = new Set(section.fields.map((f) => f.name));
		const fields = [...section.fields];
		for (const f of over.fields_add) {
			if (!names.has(f.name)) fields.push(f);
		}
		return { ...section, fields };
	});
	return { ...base, sections };
}
