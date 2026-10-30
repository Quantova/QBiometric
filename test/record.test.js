// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const Q = require('..');

function freshKey() {
  return Q.generateKey();
}

function digestOf(text) {
  return crypto.createHash('sha3-256').update(text).digest('hex');
}

function enrolReference(key, subject) {
  return Q.enrol({ key, modality: 'face', templateDigest: digestOf('template-a'), subject: Q.keyId(subject), enrollerLabel: 'Enrolment Centre' });
}

test('an enrolment is a well formed signed record of the enroller', () => {
  const enroller = freshKey();
  const person = freshKey();
  const ref = enrolReference(enroller, person);
  assert.strictEqual(ref.format, 'qbiometric/1');
  assert.strictEqual(ref.type, 'enrol');
  assert.strictEqual(ref.algorithm, 'ML-DSA-65');
  assert.strictEqual(ref.signer.id, Q.keyId(enroller));
  assert.strictEqual(ref.statement.enrollerKeyId, Q.keyId(enroller));
  assert.strictEqual(ref.statement.subjectKeyId, Q.keyId(person));
  assert.match(ref.statement.templateDigest, /^[0-9a-f]{64}$/);
  assert.match(ref.statement.bioId, /^[0-9a-f]{32}$/);
  assert.strictEqual(Buffer.from(ref.signature, 'base64').length, Q.SIGNATURE_BYTES);
});

test('the match, renew and lock records chain to the same reference', () => {
  const enroller = freshKey();
  const person = freshKey();
  const verifier = freshKey();
  const custodian = freshKey();
  const ref = enrolReference(enroller, person);
  const m = Q.match({ key: verifier, reference: ref, outcome: 'match', score: 9800 });
  const rn = Q.renew({ key: enroller, record: ref, templateDigest: digestOf('template-b') });
  const lk = Q.lock({ key: custodian, record: rn, reason: 'account under review' });
  assert.strictEqual(m.statement.bioId, ref.statement.bioId);
  assert.strictEqual(m.statement.enrolRef, Q.recordRef(ref));
  assert.strictEqual(rn.statement.priorRef, Q.recordRef(ref));
  assert.strictEqual(lk.statement.priorRef, Q.recordRef(rn));
  assert.strictEqual(m.statement.outcome, 'match');
});

test('invalid inputs are refused before anything is signed', () => {
  const key = freshKey();
  const person = freshKey();
  const base = { key, modality: 'face', templateDigest: digestOf('t'), subject: Q.keyId(person) };
  assert.throws(() => Q.enrol(Object.assign({}, base, { modality: 'gait' })), /modality must be one of/);
  assert.throws(() => Q.enrol(Object.assign({}, base, { templateDigest: 'short' })), /templateDigest must be/);
  assert.throws(() => Q.enrol(Object.assign({}, base, { subject: 'nothex' })), /subject is a/);
  assert.throws(() => Q.enrol(Object.assign({}, base, { unknownField: 1 })), /is not an option of enrol/);
  const ref = enrolReference(key, person);
  assert.throws(() => Q.match({ key, reference: ref, outcome: 'maybe', score: 1 }), /outcome must be one of/);
  assert.throws(() => Q.match({ key, reference: ref, outcome: 'match', score: 20000 }), /score is larger than/);
  assert.throws(() => Q.match({ key, reference: ref, outcome: 'match', score: -1 }), /score must be a whole number/);
});

test('a score of zero is accepted on a no match', () => {
  const key = freshKey();
  const person = freshKey();
  const ref = enrolReference(key, person);
  const m = Q.match({ key, reference: ref, outcome: 'no_match', score: 0 });
  assert.strictEqual(m.statement.score, 0);
});

test('a signing key must be a well formed 32 byte seed', () => {
  const person = freshKey();
  assert.throws(() => enrolReference(new Uint8Array(16), person), /32 byte Uint8Array seed/);
  assert.throws(() => enrolReference(new Uint8Array(32), person), /too few different byte values/);
});

test('a well formed record verifies and a type mismatch is invalid', async () => {
  const enroller = freshKey();
  const person = freshKey();
  const ref = enrolReference(enroller, person);
  const ok = await Q.verify(ref, { type: 'enrol', network: 'testnet', requireAnchor: false, strict: false });
  assert.strictEqual(ok.status, 'valid');
  assert.strictEqual(ok.type, 'enrol');
  assert.strictEqual(ok.bioId, ref.statement.bioId);
  const wrongType = await Q.verify(ref, { type: 'match', network: 'testnet', requireAnchor: false, strict: false });
  assert.strictEqual(wrongType.status, 'invalid');
  const wrongSigner = await Q.verify(ref, { type: 'enrol', network: 'testnet', requireAnchor: false, strict: false, signerKeyId: Q.keyId(freshKey()) });
  assert.strictEqual(wrongSigner.status, 'invalid');
});

test('a tampered statement no longer verifies', async () => {
  const enroller = freshKey();
  const person = freshKey();
  const ref = enrolReference(enroller, person);
  const forged = JSON.parse(JSON.stringify(ref));
  forged.statement.modality = 'iris';
  const r = await Q.verify(forged, { type: 'enrol', network: 'testnet', requireAnchor: false, strict: false });
  assert.strictEqual(r.status, 'invalid');
  assert.ok(r.checks.some((c) => c.name === 'signature' && !c.ok));
});

test('the prior link binds a match to the reference it checks against', async () => {
  const enroller = freshKey();
  const person = freshKey();
  const verifier = freshKey();
  const ref = enrolReference(enroller, person);
  const m = Q.match({ key: verifier, reference: ref, outcome: 'match', score: 9000 });
  const good = await Q.verify(m, { type: 'match', network: 'testnet', requireAnchor: false, strict: false, prior: ref });
  assert.ok(good.checks.some((c) => c.name === 'prior' && c.ok));
  const otherRef = enrolReference(enroller, person);
  const bad = await Q.verify(m, { type: 'match', network: 'testnet', requireAnchor: false, strict: false, prior: otherRef });
  assert.strictEqual(bad.status, 'invalid');
  assert.ok(bad.checks.some((c) => c.name === 'prior' && !c.ok));
});

test('the kind and constants are the ones pinned for the biometric line', () => {
  assert.strictEqual(Q.KIND, 1505);
  assert.strictEqual(Q.FORMAT, 'qbiometric/1');
  assert.deepStrictEqual([...Q.TYPES], ['enrol', 'match', 'renew', 'lock', 'erase']);
  assert.deepStrictEqual([...Q.MODALITIES], ['face', 'fingerprint', 'iris', 'voice', 'palm']);
  assert.deepStrictEqual([...Q.OUTCOMES], ['match', 'no_match', 'inconclusive']);
});
