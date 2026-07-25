/**
 * Template types for kid_profiles UI templates.
 * Full loader/merger to be implemented — see AGENTS.md.
 */

export type FieldType =
	| 'string'
	| 'secret'
	| 'boolish'
	| 'list'
	| 'string_or_list'
	| 'map';

export interface TemplateField {
	name: string;
	type: FieldType;
	required?: boolean;
	help?: string;
	encoding?: string;
	item?: string;
	additionalProperties?: { type: FieldType };
}

export interface TemplateSection {
	id: string;
	label: string;
	path?: string;
	additionalProperties?: boolean;
	fields: TemplateField[];
	fields_add?: TemplateField[];
}

export interface ProfileTemplate {
	version: number;
	format: 'kid_profiles';
	description?: string;
	extends?: string;
	entry: {
		key_pattern?: string;
		required: string[];
	};
	sections: TemplateSection[];
}

/** Runtime document: keyid → entry */
export type KidProfilesDoc = Record<string, KidProfileEntry>;

export interface KidProfileEntry {
	hmac: string;
	cahandler?: Record<string, unknown>;
	challenge?: Record<string, unknown>;
	authorization?: Record<string, unknown>;
	order?: Record<string, unknown>;
	[section: string]: unknown;
}
