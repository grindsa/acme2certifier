import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { parseKidProfilesYaml, serializeKidProfilesYaml } from './document';

describe('document IO', () => {
	it('parses example fixture and round-trips keyids', () => {
		const path = resolve('fixtures/example.kid_profiles.yaml');
		const raw = readFileSync(path, 'utf8');
		const doc = parseKidProfilesYaml(raw);
		expect(Object.keys(doc)).toEqual(['keyid_00', 'keyid_01', 'keyid_02', 'keyid_03']);
		expect(doc.keyid_00.hmac).toBeTruthy();
		expect(doc.keyid_03.authorization).toBeTruthy();
		const again = parseKidProfilesYaml(serializeKidProfilesYaml(doc));
		expect(Object.keys(again)).toEqual(Object.keys(doc));
	});
});
