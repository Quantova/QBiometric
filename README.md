# QBiometric

QBiometric is a live production post quantum biometric enrolment and match attestation tool on the Quantova network. It proves the enrolment, match, re enrolment, lock and erasure of a biometric reference, and it lets any third party confirm that history without trusting the party that created it.

QBiometric never touches the biometric. Only a one way digest of a template, computed off the chain by the party that holds the data, is ever referenced in a record. The template itself never leaves that party and is never written anywhere by this tool. A person is named only by a chain address, and only a salted cryptographic commitment is written to the chain.

## What it records

Each record is a signed envelope of one of five types.

1. enrol, an enroller states the modality and template digest of a new biometric reference for a person.
2. match, a verifier records the outcome and score of a comparison against the reference.
3. renew, an enroller replaces the template digest of the reference.
4. lock, a custodian locks the reference and states why.
5. erase, a custodian records the permanent erasure of the reference and states why.

Every record is signed with ML-DSA-65 under FIPS 204 by the party whose role it names, and each later record links to the one before it so the whole life of a reference forms a chain.

## Proving the time

A record on its own carries only the claim of its signer. Anchoring a record on the Quantova network through Qstamp adds a post quantum evidence anchor that fixes the latest moment the record existed, provable against the record and the signer by anyone, without claiming a regulated timestamp status that Quantova Inc does not hold.

## Install

```
npm install @quantovainc/qbiometric
```

## Use

```js
const crypto = require('crypto');
const qbiometric = require('@quantovainc/qbiometric');

const enroller = qbiometric.generateKey();
const person = qbiometric.generateKey();
const templateDigest = crypto.createHash('sha3-256').update(templateBytesHeldLocally).digest('hex');
const reference = qbiometric.enrol({
  key: enroller,
  modality: 'face',
  templateDigest,
  subject: qbiometric.keyId(person),
  enrollerLabel: 'Border Enrolment Centre',
});

const anchored = await qbiometric.anchor(reference, { seed, index: 0, network: 'testnet' });
const result = await qbiometric.verify(anchored[0], { type: 'enrol', network: 'testnet' });
```

## What a record does not establish

1. It does not show that the stated facts are true. It shows only that the signer stated them and that the statement existed unchanged at a point in time.
2. It does not identify a natural person, and it never holds a biometric. The subject is a chain address and the template is referenced only by a digest.
3. The labels are text written by the signer, they are not a verified identity.

## License

Apache-2.0 OR MIT
