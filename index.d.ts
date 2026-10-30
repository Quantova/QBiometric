// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

export type Modality = 'face' | 'fingerprint' | 'iris' | 'voice' | 'palm';
export type Outcome = 'match' | 'no_match' | 'inconclusive';
export type RecordType = 'enrol' | 'match' | 'renew' | 'lock' | 'erase';

export interface KeyDescription {
  format: 'qbiometric-key/1';
  algorithm: 'ML-DSA-65';
  id: string;
  publicKey: string;
}

export type Party = string | Uint8Array | KeyDescription;

export interface Signer {
  id: string;
  publicKey: string;
}

export interface Envelope<T = Record<string, unknown>> {
  format: 'qbiometric/1';
  type: RecordType;
  algorithm: 'ML-DSA-65';
  signer: Signer;
  statement: T;
  signature: string;
  anchor?: unknown;
}

export interface EnrolOptions {
  key: Uint8Array;
  modality: Modality;
  templateDigest: string;
  subject: Party;
  enrollerLabel?: string;
  enrolledAt?: string;
  note?: string;
}

export interface MatchOptions {
  key: Uint8Array;
  reference: Envelope;
  outcome: Outcome;
  score: number;
  verifierLabel?: string;
  matchedAt?: string;
  note?: string;
}

export interface RenewOptions {
  key: Uint8Array;
  record: Envelope;
  templateDigest: string;
  enrollerLabel?: string;
  renewedAt?: string;
  note?: string;
}

export interface LockOptions {
  key: Uint8Array;
  record: Envelope;
  reason: string;
  custodianLabel?: string;
  lockedAt?: string;
  note?: string;
}

export interface EraseOptions {
  key: Uint8Array;
  record: Envelope;
  reason: string;
  custodianLabel?: string;
  erasedAt?: string;
  note?: string;
}

export interface AnchorOptions {
  seed?: Uint8Array;
  index?: number;
  network?: string;
  rpc?: string;
  clients?: unknown[];
  trustSingleEndpoint?: boolean;
  trustCustomEndpoints?: boolean;
  allowLoopback?: boolean;
  maxFee?: string | number | bigint;
  meter?: string | number | bigint;
  timeoutMs?: number;
  onPending?: (pending: unknown) => void;
  signal?: AbortSignal;
}

export interface VerifyOptions {
  type?: RecordType;
  prior?: Envelope;
  bioId?: string;
  signerKeyId?: string;
  signerPublicKey?: string | Uint8Array;
  network: string;
  strict?: boolean;
  requireAnchor?: boolean;
  maxAnchorDelay?: number;
  at?: string;
  deadlineMs?: number;
  rpc?: string;
  clients?: unknown[];
  trustSingleEndpoint?: boolean;
  trustCustomEndpoints?: boolean;
  allowLoopback?: boolean;
}

export interface Check {
  name: string;
  ok: boolean;
  detail: string;
  transport: boolean;
  indeterminate: boolean;
  unproven: boolean;
}

export interface VerifyResult {
  valid: boolean;
  status: 'valid' | 'unproven' | 'indeterminate' | 'invalid';
  type: RecordType | null;
  bioId?: string;
  signerId?: string;
  statement?: Record<string, unknown>;
  anchoredAt?: string | null;
  endpoints: string[];
  officialEndpoints: boolean | null;
  checks: Check[];
}

export function generateKey(): Uint8Array;
export function publicKey(key: Uint8Array): Uint8Array;
export function keyId(key: Uint8Array): string;
export function describeKey(key: Uint8Array): KeyDescription;
export function subjectRef(secret: Uint8Array, reference: string): string;
export function enrol(options: EnrolOptions): Envelope;
export function match(options: MatchOptions): Envelope;
export function renew(options: RenewOptions): Envelope;
export function lock(options: LockOptions): Envelope;
export function erase(options: EraseOptions): Envelope;
export function anchor(envelopes: Envelope | Envelope[], options: AnchorOptions): Promise<Envelope[]>;
export function complete(envelopes: Envelope | Envelope[], pending: unknown, options?: AnchorOptions): Promise<Envelope[]>;
export function verify(envelope: Envelope, options: VerifyOptions): Promise<VerifyResult>;
export function anchorDigest(envelope: Envelope): string;
export function recordRef(envelope: Envelope): string;

export const FORMAT: 'qbiometric/1';
export const ALGORITHM: 'ML-DSA-65';
export const KIND: 1505;
export const TYPES: readonly RecordType[];
export const MODALITIES: readonly Modality[];
export const OUTCOMES: readonly Outcome[];
export const MAX_SCORE: 10000;
export const PUBLIC_KEY_BYTES: 1952;
export const SIGNATURE_BYTES: 3309;
