import { verifyRecord } from '@atcute/repo';
import {
	parsePublicMultikey,
	Secp256k1PublicKey,
	P256PublicKey,
	type PublicKey,
} from '@atcute/crypto';
import type { AtprotoDid } from '@atcute/lexicons/syntax';

export type VerificationLevel = 'service-signature' | 'cid-integrity';

export interface StratosVerificationResult {
	level: VerificationLevel;
}

// signing key cache keyed by service DID
const signingKeyCache = new Map<string, PublicKey>();

/**
 * resolves a Stratos service's signing public key from its did:web document.
 * results are cached — the key doesn't change unless the service rotates it.
 */
export const resolveServiceSigningKey = async (serviceDid: string): Promise<PublicKey> => {
	const cached = signingKeyCache.get(serviceDid);
	if (cached) return cached;

	if (!serviceDid.startsWith('did:web:')) {
		throw new Error(`expected did:web, got: ${serviceDid}`);
	}

	const host = serviceDid.slice('did:web:'.length).replaceAll(':', '/');
	const url = `https://${host}/.well-known/did.json`;

	const res = await fetch(url);
	if (!res.ok) {
		throw new Error(`failed to fetch DID document: ${res.status} ${res.statusText}`);
	}

	const doc = (await res.json()) as {
		verificationMethod?: Array<{
			type: string;
			publicKeyMultibase?: string;
		}>;
	};

	const methods = doc.verificationMethod;
	if (!methods || methods.length === 0) {
		throw new Error('DID document has no verificationMethod');
	}

	const multikey = methods.find((m) => m.type === 'Multikey' && m.publicKeyMultibase);
	if (!multikey || !multikey.publicKeyMultibase) {
		throw new Error('DID document has no Multikey verificationMethod');
	}

	const found = parsePublicMultikey(multikey.publicKeyMultibase);

	let key: PublicKey;
	switch (found.type) {
		case 'secp256k1':
			key = await Secp256k1PublicKey.importRaw(found.publicKeyBytes);
			break;
		case 'p256':
			key = await P256PublicKey.importRaw(found.publicKeyBytes);
			break;
		default:
			throw new Error(`unsupported key type: ${(found as { type: string }).type}`);
	}

	signingKeyCache.set(serviceDid, key);
	return key;
};

/**
 * verifies a Stratos record with signature verification when possible,
 * falling back to CID integrity if the signing key can't be resolved.
 */
export const verifyStratosRecord = async (
	carBytes: Uint8Array,
	did: string,
	collection: string,
	rkey: string,
	serviceDid: string | undefined,
): Promise<StratosVerificationResult> => {
	let signingKey: PublicKey | undefined;
	if (serviceDid) {
		try {
			signingKey = await resolveServiceSigningKey(serviceDid);
		} catch {
			// key resolution failed — fall through to CID-only
		}
	}

	if (signingKey) {
		await verifyRecord({
			carBytes,
			collection,
			rkey,
			did: did as AtprotoDid,
			publicKey: signingKey,
		});
		return { level: 'service-signature' };
	}

	await verifyRecord({
		carBytes,
		collection,
		rkey,
		did: did as AtprotoDid,
	});
	return { level: 'cid-integrity' };
};
