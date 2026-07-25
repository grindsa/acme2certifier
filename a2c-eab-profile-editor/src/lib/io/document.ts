import { parse, stringify } from 'yaml';
import type { KidProfilesDoc } from '../schema/types';

export function parseKidProfilesYaml(text: string): KidProfilesDoc {
	const data = parse(text);
	if (data === null || typeof data !== 'object' || Array.isArray(data)) {
		throw new Error('kid_profiles document must be a YAML mapping of keyid → entry');
	}
	return data as KidProfilesDoc;
}

export function parseKidProfilesJson(text: string): KidProfilesDoc {
	const data = JSON.parse(text) as unknown;
	if (data === null || typeof data !== 'object' || Array.isArray(data)) {
		throw new Error('kid_profiles document must be a JSON object of keyid → entry');
	}
	return data as KidProfilesDoc;
}

export function serializeKidProfilesYaml(doc: KidProfilesDoc): string {
	return stringify(doc, { lineWidth: 0, defaultKeyType: 'PLAIN' });
}
