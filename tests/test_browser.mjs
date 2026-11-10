import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { bytesToHex, generateFsc, hexToBytes, md5 } from '../docs/core.mjs';

const data = JSON.parse(readFileSync(new URL('../docs/mdg1_public_data.json', import.meta.url), 'utf8'));

test('MD5 matches a standard test vector', () => {
  assert.equal(bytesToHex(md5(new TextEncoder().encode('abc'))), '900150983cd24fb0d6963f7d28e17f72');
});

test('browser output matches both known FSC vectors', () => {
  const expected = new Map([
    [0x017c, '24ae475aaf4a7abdf38297c29acc8b50a04b21e53f6641805fdc08e98420379b'],
    [0x0180, 'da9b523b7029a05b203d9fb8f83a0e15ef74072cda36f353be1b7380d9943f2f'],
  ]);
  for (const [appId, sha256] of expected) {
    const result = generateFsc('9J29436', appId, data);
    assert.equal(result.bytes.length, 188);
    assert.equal(createHash('sha256').update(result.bytes).digest('hex'), sha256);
  }
});

test('invalid VIN is rejected', () => {
  assert.throws(() => generateFsc('short', 0x017c, data), /seven VIN/);
});

test('explicit template has the same result as the built-in template', () => {
  const template = hexToBytes(data.built_in_template_hex);
  const builtIn = generateFsc('9J29436', 0x017c, data);
  const supplied = generateFsc('9J29436', 0x017c, data, template);
  assert.deepEqual(supplied.bytes, builtIn.bytes);
});
