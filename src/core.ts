import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256, sha512 } from "@noble/hashes/sha2.js";
import { concatBytes, randomBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import { CHUNK, openChunk, sealChunk, type Version } from "./stream.ts";
import { treeHasher } from "./treehash.ts";

type Hybrid = typeof import("@noble/post-quantum/hybrid.js");
type Falcon = typeof import("@noble/post-quantum/falcon.js");
type Curves = typeof import("@noble/curves/ed25519.js");
type Sha3 = typeof import("@noble/hashes/sha3.js");

const hybrid = () => require("@noble/post-quantum/hybrid.js") as Hybrid;

let kemCache: Hybrid["ml_kem768_x25519"] | null = null;
let signerCache: ReturnType<Hybrid["combineSigners"]> | null = null;

export const kem = () => {
	kemCache ||= hybrid().ml_kem768_x25519;
	return kemCache;
};

const falconOf = () => require("@noble/post-quantum/falcon.js") as Falcon;
const edOf = () => (require("@noble/curves/ed25519.js") as Curves).ed25519;
const shakeOf = () => (require("@noble/hashes/sha3.js") as Sha3).shake256;

export function expandSignKeys(seed: Uint8Array): SignKeys {
	const falcon = falconOf().falcon512padded;
	const ec = hybrid().ecSigner(edOf());
	const fLen = falcon.lengths.seed;
	const eLen = ec.lengths.seed;
	const expanded = shakeOf()(seed, { dkLen: fLen + eLen });
	const f = falcon.keygen(expanded.slice(0, fLen));
	const e = ec.keygen(expanded.slice(fLen, fLen + eLen));
	return {
		publicKey: concatBytes(f.publicKey, e.publicKey),
		falconSecret: f.secretKey,
		edSecret: e.secretKey,
	};
}

const signWith = (keys: SignKeys, msg: Uint8Array, fixed = false) =>
	concatBytes(
		falconOf().falcon512padded.sign(
			msg,
			keys.falconSecret,
			fixed ? { extraEntropy: false } : undefined,
		),
		hybrid().ecSigner(edOf()).sign(msg, keys.edSecret),
	);

export const signer = () => {
	if (!signerCache) {
		const { combineSigners, ecSigner, expandSeedXof } = hybrid();
		const { falcon512padded } =
			require("@noble/post-quantum/falcon.js") as Falcon;
		const { ed25519 } = require("@noble/curves/ed25519.js") as Curves;
		const { shake256 } = require("@noble/hashes/sha3.js") as Sha3;
		signerCache = combineSigners(
			32,
			expandSeedXof(shake256),
			falcon512padded,
			ecSigner(ed25519),
		);
	}
	return signerCache;
};

export const KEM_PK = 1216;
export const SIGN_PK = 929;
export const SALT_LEN = 2;
export const NONCE_LEN = 8;
export const CORE_LEN = SALT_LEN + KEM_PK + SIGN_PK + NONCE_LEN;
export const KEM_CT = 1120;
export const SIG_LEN = 730;
export const BUNDLE_LEN = SALT_LEN + KEM_PK + SIGN_PK + NONCE_LEN + SIG_LEN;
export const SEED_LEN = 74;
export const CHARSET = "abcdefghijklmnopqrstuvwxyz234567";

const MAGIC = utf8ToBytes("NPE4");
const MAGIC_V3 = utf8ToBytes("NPE3");
const MAGIC_V2 = utf8ToBytes("NPE2");
const MAGIC_V1 = utf8ToBytes("NPE1");
const LEN_LEN = 8;
export const UNPADDED = 2n ** 64n - 1n;
export const TRAILER = SIGN_PK + SIG_LEN;
const INNER_CTX = utf8ToBytes("np/v1/inner");

const innerDigest = (header: Uint8Array, hash: Uint8Array) =>
	concatBytes(INNER_CTX, sha512(concatBytes(header, hash)));

export const signInner = (id: Identity, header: Uint8Array, hash: Uint8Array) =>
	concatBytes(
		id.signKeys.publicKey,
		signWith(id.signKeys, innerDigest(header, hash)),
	);

export function openInner(
	header: Uint8Array,
	trailer: Uint8Array,
	hash: Uint8Array,
) {
	if (trailer.length !== TRAILER) return null;
	const signKey = trailer.slice(0, SIGN_PK);
	try {
		return signer().verify(
			trailer.slice(SIGN_PK),
			innerDigest(header, hash),
			signKey,
		)
			? signKey
			: null;
	} catch {
		return null;
	}
}

export function padTo(len: number) {
	if (len < 64) return 64;
	const e = Math.floor(Math.log2(len));
	const step = 2 ** (e - (Math.floor(Math.log2(e)) + 1));
	return Math.ceil(len / step) * step;
}
const FP_CTX = utf8ToBytes("np/v2/fingerprint");
const SELF_CTX = utf8ToBytes("np/v1/self");

const selfDigest = (core: Uint8Array) => concatBytes(SELF_CTX, sha512(core));

export function verifyKey(key: Uint8Array) {
	if (key.length !== BUNDLE_LEN) return false;
	try {
		return signer().verify(
			key.slice(CORE_LEN),
			selfDigest(key.slice(0, CORE_LEN)),
			signerKey(key),
		);
	} catch {
		return false;
	}
}

export function toWords(bytes: Uint8Array) {
	const out: number[] = [];
	let acc = 0;
	let bits = 0;
	for (const b of bytes) {
		acc = ((acc << 8) | b) >>> 0;
		bits += 8;
		while (bits >= 5) {
			bits -= 5;
			out.push((acc >>> bits) & 31);
		}
	}
	if (bits) out.push((acc << (5 - bits)) & 31);
	return out;
}

function fromWords(words: number[]) {
	const out = new Uint8Array(Math.floor((words.length * 5) / 8));
	let acc = 0;
	let bits = 0;
	let i = 0;
	for (const w of words) {
		acc = ((acc << 5) | w) >>> 0;
		bits += 5;
		if (bits >= 8) {
			bits -= 8;
			out[i++] = (acc >>> bits) & 0xff;
		}
	}
	if (acc & ((1 << bits) - 1)) throw new Error("non-zero padding bits");
	return out;
}

const checksum = (hrp: string, payload: Uint8Array) =>
	sha256(concatBytes(utf8ToBytes(`np/v1/${hrp}`), payload)).slice(0, 4);

export const toBech = (hrp: string, bytes: Uint8Array) =>
	`${hrp}1${toWords(concatBytes(bytes, checksum(hrp, bytes)))
		.map((w) => CHARSET[w])
		.join("")}`;

export function fromBech(hrp: string, s: string) {
	const given = s.trim();
	if (given !== given.toLowerCase() && given !== given.toUpperCase())
		throw new Error(`mixed case in a ${hrp}1... string`);
	const t = given.toLowerCase();
	if (!t.startsWith(`${hrp}1`)) throw new Error(`expected a ${hrp}1... string`);
	const words = [...t.slice(hrp.length + 1)].map((c) => {
		const w = CHARSET.indexOf(c);
		if (w < 0) throw new Error(`invalid character "${c}"`);
		return w;
	});
	const raw = fromWords(words);
	if (raw.length < 5) throw new Error("too short");
	const payload = raw.slice(0, -4);
	const check = checksum(hrp, payload);
	if (!raw.slice(-4).every((b, i) => b === check[i]))
		throw new Error(`corrupt ${hrp}1... string (bad checksum)`);
	return payload;
}

export const signerKey = (key: Uint8Array) =>
	key.slice(SALT_LEN + KEM_PK, SALT_LEN + KEM_PK + SIGN_PK);

export function fingerprint(key: Uint8Array) {
	const hash = sha256(concatBytes(FP_CTX, key)).slice(0, 10);
	const words = toWords(hash)
		.map((w) => CHARSET[w])
		.join("")
		.slice(0, 16);
	return (words.match(/.{4}/g) ?? []).join("-");
}

export type Identity = {
	seed: Uint8Array;
	readonly bundle: Uint8Array;
	readonly key: Uint8Array;
	readonly kemSecret: Uint8Array;
	readonly signKeys: SignKeys;
};

export type SignKeys = {
	publicKey: Uint8Array;
	falconSecret: Uint8Array;
	edSecret: Uint8Array;
};

export function identityFromSeed(
	seed: Uint8Array,
	known?: Uint8Array,
	cached?: SignKeys,
): Identity {
	if (seed.length === 66)
		throw new Error("identity is from an old np version, re-run `np key new`");
	if (seed.length !== SEED_LEN) throw new Error("bad seed length");
	if (known && known.length !== BUNDLE_LEN)
		throw new Error("bad key bundle length");
	let kemKeys: ReturnType<ReturnType<typeof kem>["keygen"]> | null = null;
	let signKeys: SignKeys | null = null;
	const kemPair = () => {
		kemKeys ||= kem().keygen(seed.slice(0, 32));
		return kemKeys;
	};
	const signPair = () => {
		signKeys ||= cached ?? expandSignKeys(seed.slice(32, 64));
		return signKeys;
	};
	let bundleCache = known ?? null;
	const bundleOf = () => {
		if (bundleCache) return bundleCache;
		const core = concatBytes(
			seed.slice(64, 66),
			kemPair().publicKey,
			signPair().publicKey,
			seed.slice(66),
		);
		bundleCache = concatBytes(
			core,
			signWith(signPair(), selfDigest(core), true),
		);
		return bundleCache;
	};
	const matching = (pk: Uint8Array, at: number) => {
		const bundle = bundleOf();
		if (!pk.every((b, i) => b === bundle[at + i]))
			throw new Error(
				"the secret key does not match the public key next to it, restore the identity file from a backup",
			);
		return true;
	};
	return {
		seed,
		get bundle() {
			return bundleOf();
		},
		get key() {
			return bundleOf();
		},
		get kemSecret() {
			const pair = kemPair();
			matching(pair.publicKey, SALT_LEN);
			return pair.secretKey;
		},
		get signKeys() {
			const pair = signPair();
			matching(pair.publicKey, SALT_LEN + KEM_PK);
			return pair;
		},
	};
}

export function decodeKey(s: string) {
	const key = fromBech("npkey", s);
	if (key.length !== BUNDLE_LEN) throw new Error("bad key length");
	if (!verifyKey(key))
		throw new Error(
			"that key is not signed by its own signing half, so its two halves may belong to different people",
		);
	return key;
}

export const encodeKey = (key: Uint8Array) => toBech("npkey", key);

const MSG_CTX = utf8ToBytes("np/v1/msg");
const FILE_CTX = utf8ToBytes("np/v1/file");

const digest = (ctx: Uint8Array, msg: Uint8Array) =>
	concatBytes(ctx, sha512(msg));

export const signBytes = (id: Identity, msg: Uint8Array, file = false) =>
	signWith(id.signKeys, digest(file ? FILE_CTX : MSG_CTX, msg));

export const signFileHash = (id: Identity, hash: Uint8Array) =>
	signWith(id.signKeys, concatBytes(FILE_CTX, hash));

export function verifyFileHash(
	signKey: Uint8Array,
	sig: Uint8Array,
	hash: Uint8Array,
) {
	try {
		return signer().verify(sig, concatBytes(FILE_CTX, hash), signKey);
	} catch {
		return false;
	}
}

export function verifyBytes(
	signKey: Uint8Array,
	sig: Uint8Array,
	msg: Uint8Array,
	file = false,
) {
	try {
		return signer().verify(
			sig,
			digest(file ? FILE_CTX : MSG_CTX, msg),
			signKey,
		);
	} catch {
		return false;
	}
}

const claimDigest = (name: string, bundle: Uint8Array) =>
	concatBytes(
		utf8ToBytes("np/v1/claim"),
		sha512(concatBytes(utf8ToBytes(`${name}\n`), bundle)),
	);

export const signClaim = (id: Identity, name: string) =>
	signWith(id.signKeys, claimDigest(name, id.bundle));

export function verifyClaim(bundle: Uint8Array, name: string, sig: Uint8Array) {
	try {
		return signer().verify(sig, claimDigest(name, bundle), signerKey(bundle));
	} catch {
		return false;
	}
}

const rotateDigest = (from: Uint8Array, to: Uint8Array) =>
	concatBytes(utf8ToBytes("np/v2/rotate"), sha512(concatBytes(from, to)));

export const signRotation = (old: Identity, next: Uint8Array) =>
	signWith(old.signKeys, rotateDigest(old.key, next));

export function verifyRotation(
	from: Uint8Array,
	to: Uint8Array,
	sig: Uint8Array,
) {
	try {
		return signer().verify(sig, rotateDigest(from, to), signerKey(from));
	} catch {
		return false;
	}
}

const revokeDigest = (key: Uint8Array, reason: string) =>
	concatBytes(
		utf8ToBytes("np/v2/revoke"),
		sha512(concatBytes(key, utf8ToBytes(`\n${reason}\n`))),
	);

export const signRevocation = (id: Identity, reason: string) =>
	signWith(id.signKeys, revokeDigest(id.key, reason));

export function verifyRevocation(
	key: Uint8Array,
	reason: string,
	sig: Uint8Array,
) {
	try {
		return signer().verify(sig, revokeDigest(key, reason), signerKey(key));
	} catch {
		return false;
	}
}

const wrapKey = (ss: Uint8Array) =>
	hkdf(sha256, ss, undefined, utf8ToBytes("np/v1/wrap"), 32);
const payloadKey = (fk: Uint8Array, v: Version) =>
	hkdf(sha256, fk, undefined, utf8ToBytes(`np/v${v}/payload`), 32);

export const STANZA_LEN = KEM_CT + 48;

const headStart = (v: Version) =>
	v < 3 ? 5 : v < 4 ? 5 + LEN_LEN : 6 + LEN_LEN;

const stanzaAad = (head: Uint8Array, i: number) =>
	concatBytes(head, new Uint8Array([i]));

export function encryptHeader(
	recipients: Uint8Array[],
	plainLen?: number,
	signed = false,
	message = false,
) {
	if (!recipients.length) throw new Error("no recipients");
	if (recipients.length > 255) throw new Error("too many recipients");
	const fileKey = randomBytes(32);
	const len = new Uint8Array(LEN_LEN);
	const padded =
		plainLen === undefined
			? undefined
			: padTo(plainLen) + (signed ? TRAILER : 0);
	new DataView(len.buffer).setBigUint64(
		0,
		plainLen === undefined ? UNPADDED : BigInt(plainLen),
	);
	const head = concatBytes(
		MAGIC,
		new Uint8Array([recipients.length, (signed ? 1 : 0) | (message ? 2 : 0)]),
		len,
	);
	const parts = [head];
	for (const [i, bundle] of recipients.entries()) {
		const { cipherText, sharedSecret } = kem().encapsulate(
			bundle.slice(SALT_LEN, SALT_LEN + KEM_PK),
		);
		parts.push(
			cipherText,
			xchacha20poly1305(
				wrapKey(sharedSecret),
				new Uint8Array(24),
				stanzaAad(head, i),
			).encrypt(fileKey),
		);
	}
	return {
		key: payloadKey(fileKey, 4),
		header: concatBytes(...parts),
		v: 4 as Version,
		padded,
	};
}

export function openHeader(bin: Uint8Array, id: Identity) {
	if (!isEncrypted(bin)) throw new Error("not an np encrypted blob");
	const v: Version =
		bin[3] === 0x34 ? 4 : bin[3] === 0x33 ? 3 : bin[3] === 0x32 ? 2 : 1;
	const n = bin[4];
	if (!n) throw new Error("corrupt header");
	const flags = v >= 4 ? (bin[5] ?? 0) : 0;
	const signed = (flags & 1) === 1;
	const message = (flags & 2) === 2;
	const start = headStart(v);
	const bodyOffset = start + n * STANZA_LEN;
	if (bin.length < bodyOffset) throw new Error("corrupt header");
	const head = bin.slice(0, start);
	const plainLen =
		v < 3
			? UNPADDED
			: new DataView(head.buffer, head.byteOffset, start).getBigUint64(
					v < 4 ? 5 : 6,
				);
	for (let i = 0; i < n; i++) {
		const off = start + i * STANZA_LEN;
		try {
			const ss = kem().decapsulate(bin.slice(off, off + KEM_CT), id.kemSecret);
			const fileKey = xchacha20poly1305(
				wrapKey(ss),
				new Uint8Array(24),
				v < 3 ? undefined : stanzaAad(head, i),
			).decrypt(bin.slice(off + KEM_CT, off + STANZA_LEN));
			return {
				key: payloadKey(fileKey, v),
				bodyOffset,
				header: bin.slice(0, bodyOffset),
				v,
				plainLen,
				signed,
				message,
			};
		} catch {}
	}
	throw new Error(
		`not encrypted to your key (${n} recipient${n > 1 ? "s" : ""})`,
	);
}

export const isEncrypted = (bin: Uint8Array) =>
	bin.length > 5 &&
	[MAGIC, MAGIC_V3, MAGIC_V2, MAGIC_V1].some((m) =>
		m.every((b, i) => bin[i] === b),
	);

export function encryptBytes(
	plain: Uint8Array,
	recipients: Uint8Array[],
	signer?: Identity,
	message = false,
) {
	const { key, header, padded } = encryptHeader(
		recipients,
		plain.length,
		!!signer,
		message,
	);
	const full = new Uint8Array(padded ?? plain.length);
	full.set(plain);
	if (signer) {
		const h = treeHasher();
		h.update(plain);
		full.set(signInner(signer, header, h.root()), padTo(plain.length));
	}
	const chunks = [header];
	const total = Math.max(1, Math.ceil(full.length / CHUNK));
	for (let i = 0; i < total; i++)
		chunks.push(
			sealChunk(
				key,
				i,
				i === total - 1,
				full.slice(i * CHUNK, (i + 1) * CHUNK),
			),
		);
	return concatBytes(...chunks);
}

export function decryptBytes(bin: Uint8Array, id: Identity) {
	const { key, bodyOffset, v, plainLen, signed, message, header } = openHeader(
		bin,
		id,
	);
	const body = bin.slice(bodyOffset);
	const sealed = CHUNK + 16;
	const total = Math.max(1, Math.ceil(body.length / sealed));
	const chunks = [];
	for (let i = 0; i < total; i++)
		chunks.push(
			openChunk(
				key,
				i,
				i === total - 1,
				body.slice(i * sealed, (i + 1) * sealed),
				v,
			),
		);
	const out = concatBytes(...chunks);
	if (plainLen === UNPADDED) {
		if (!signed) return { data: out, signKey: null, message };
		const data = out.slice(0, out.length - TRAILER);
		const h = treeHasher();
		h.update(data);
		const signKey = openInner(
			header,
			out.slice(out.length - TRAILER),
			h.root(),
		);
		if (!signKey) throw new Error("the signature inside does not match");
		return { data, signKey, message };
	}
	const len = Number(plainLen);
	const data = out.slice(0, len);
	if (!signed) return { data, signKey: null, message };
	const h = treeHasher();
	h.update(data);
	const at = padTo(len);
	const signKey = openInner(header, out.slice(at, at + TRAILER), h.root());
	if (!signKey) throw new Error("the signature inside does not match");
	return { data, signKey, message };
}

const b64 = (b: Uint8Array) => Buffer.from(b).toString("base64");
const unb64 = (s: string) => Uint8Array.from(Buffer.from(s, "base64"));
const wrap64 = (s: string) => s.match(/.{1,64}/g)?.join("\n") ?? "";

function rule(label: string) {
	const inner = `[ ${label} ]`;
	const left = Math.floor((64 - inner.length) / 2);
	return `${"-".repeat(left)}${inner}${"-".repeat(64 - inner.length - left)}`;
}

export const ARMOR_END = "-".repeat(64);
export const PUB_BEGIN = rule("np public key");
export const PUB_END = ARMOR_END;
export const ALIAS_BEGIN = rule("np alias");
export const ALIAS_END = ARMOR_END;
export const ROT_BEGIN = rule("np rotation");
export const ROT_END = ARMOR_END;
export const REV_BEGIN = rule("np revocation");
export const REV_END = ARMOR_END;
export const SIGNED_BEGIN = rule("np signed message");
export const SIGNED_END = ARMOR_END;
export const SIG_BEGIN = rule("np signature");
export const SIG_END = ARMOR_END;
export const ENC_BEGIN = rule("np encrypted message");
export const ENC_END = ARMOR_END;

export const armorBundle = (bundle: Uint8Array, comment?: string) =>
	[
		PUB_BEGIN,
		...(comment ? [`untrusted comment: ${comment}`, ""] : []),
		wrap64(encodeKey(bundle)),
		PUB_END,
		"",
	].join("\n");

export function extractBundleString(text: string) {
	const i = text.indexOf(PUB_BEGIN);
	if (i >= 0) {
		const j = text.indexOf(PUB_END, i + PUB_BEGIN.length);
		if (j < 0) return null;
		return text
			.slice(i + PUB_BEGIN.length, j)
			.split("\n")
			.filter((l) => !l.includes(": "))
			.join("")
			.replace(/[\s-]+/g, "");
	}
	if (text.includes(ROT_BEGIN) || text.includes(REV_BEGIN))
		throw new Error(
			"that is a rotation or revocation certificate, not a key. ask them for their key",
		);
	return text.match(/npkey1[a-z2-7]{1000,}/i)?.[0] ?? null;
}

export const armorAlias = (name: string, sig: Uint8Array) =>
	[
		ALIAS_BEGIN,
		`name: ${name}`,
		"",
		wrap64(Buffer.from(sig).toString("base64")),
		ALIAS_END,
		"",
	].join("\n");

export function parseAliases(text: string) {
	const out: { name: string; sig: Uint8Array }[] = [];
	let from = 0;
	while (true) {
		const i = text.indexOf(ALIAS_BEGIN, from);
		if (i < 0) break;
		const j = text.indexOf(ALIAS_END, i + ALIAS_BEGIN.length);
		if (j < 0) break;
		from = j + ALIAS_END.length;
		try {
			const { field, b64: body } = armorParts(
				text.slice(i + ALIAS_BEGIN.length, j),
			);
			const name = field("name");
			const sig = unb64(body);
			if (name && b64(sig) === body && sig.length === SIG_LEN)
				out.push({ name, sig });
		} catch {}
	}
	return out;
}

export const armorRevocation = (
	key: Uint8Array,
	reason: string,
	sig: Uint8Array,
) =>
	[
		REV_BEGIN,
		`key: ${encodeKey(key)}`,
		`reason: ${reason}`,
		"",
		wrap64(Buffer.from(sig).toString("base64")),
		REV_END,
		"",
	].join("\n");

export function parseRevocations(text: string) {
	const out: { key: Uint8Array; reason: string; sig: Uint8Array }[] = [];
	let at = 0;
	while (true) {
		const i = text.indexOf(REV_BEGIN, at);
		if (i < 0) break;
		const j = text.indexOf(REV_END, i + REV_BEGIN.length);
		if (j < 0) break;
		at = j + REV_END.length;
		try {
			const { field, b64: body } = armorParts(
				text.slice(i + REV_BEGIN.length, j),
			);
			const raw = field("key");
			const sig = unb64(body);
			if (raw && b64(sig) === body && sig.length === SIG_LEN)
				out.push({
					key: decodeKey(raw),
					reason: field("reason") ?? "",
					sig,
				});
		} catch {}
	}
	return out;
}

export const armorRotation = (
	from: Uint8Array,
	to: Uint8Array,
	sig: Uint8Array,
) =>
	[
		ROT_BEGIN,
		`from: ${encodeKey(from)}`,
		`to: ${encodeKey(to)}`,
		"",
		wrap64(Buffer.from(sig).toString("base64")),
		ROT_END,
		"",
	].join("\n");

export function parseRotations(text: string) {
	const out: { from: Uint8Array; to: Uint8Array; sig: Uint8Array }[] = [];
	let at = 0;
	while (true) {
		const i = text.indexOf(ROT_BEGIN, at);
		if (i < 0) break;
		const j = text.indexOf(ROT_END, i + ROT_BEGIN.length);
		if (j < 0) break;
		at = j + ROT_END.length;
		try {
			const { field, b64: body } = armorParts(
				text.slice(i + ROT_BEGIN.length, j),
			);
			const from = field("from");
			const to = field("to");
			const sig = unb64(body);
			if (from && to && b64(sig) === body && sig.length === SIG_LEN)
				out.push({ from: decodeKey(from), to: decodeKey(to), sig });
		} catch {}
	}
	return out;
}

const sigBody = (id: Identity, sig: Uint8Array) =>
	wrap64(b64(concatBytes(id.signKeys.publicKey, sig)));

export function armorSignedMessage(msg: string, id: Identity, as?: string) {
	const sig = signBytes(id, utf8ToBytes(msg));
	return [
		SIGNED_BEGIN,
		msg,
		SIG_BEGIN,
		`untrusted comment: ${as ? `signed by ${as}` : "signed with np"}`,
		"",
		sigBody(id, sig),
		SIGNED_END,
		"",
	].join("\n");
}

export function armorDetachedSig(
	fileHash: Uint8Array,
	fileName: string,
	id: Identity,
	as?: string,
	alg?: string,
) {
	const sig = signFileHash(id, fileHash);
	return [
		SIG_BEGIN,
		`untrusted comment: signature of ${fileName}${as ? ` by ${as}` : ""}`,
		...(alg ? [`hash: ${alg}`] : []),
		"",
		sigBody(id, sig),
		SIG_END,
		"",
	].join("\n");
}

const B64_LINE = /^[A-Za-z0-9+/]+={0,2}$/;
const FIELD_LINE = /^[a-z][a-z ]*: /;

export function armorParts(block: string) {
	const fields = new Map<string, string>();
	const data: string[] = [];
	let past = false;
	for (const raw of block.replaceAll("\r", "").split("\n")) {
		const line = raw.trim();
		if (!line) {
			past = fields.size > 0 || data.length > 0;
			continue;
		}
		if (line.startsWith("-") && line.endsWith("-") && !line.includes(" "))
			throw new Error("a second armor block is nested inside this one");
		if (!past && FIELD_LINE.test(line)) {
			const at = line.indexOf(": ");
			const key = line.slice(0, at);
			if (!fields.has(key)) fields.set(key, line.slice(at + 2).trim());
			continue;
		}
		if (!B64_LINE.test(line) || (data.length && data.at(-1)?.includes("=")))
			throw new Error(
				"unexpected text inside an np block, it may have been tampered with",
			);
		data.push(line);
	}
	return { field: (k: string) => fields.get(k), b64: data.join("") };
}

function parseSigBlock(block: string) {
	const { field, b64: body } = armorParts(block);
	const raw = unb64(body);
	if (raw.length !== SIGN_PK + SIG_LEN || b64(raw) !== body)
		throw new Error("corrupt signature block");
	return {
		signKey: raw.slice(0, SIGN_PK),
		sig: raw.slice(SIGN_PK),
		alg: field("hash"),
	};
}

export function parseSignedMessage(text: string) {
	const t = text.replaceAll("\r\n", "\n").trim();
	if (!t.startsWith(SIGNED_BEGIN) || !t.endsWith(SIGNED_END))
		throw new Error("not a signed message");
	const sigIdx = t.lastIndexOf(`\n${SIG_BEGIN}\n`);
	if (sigIdx < 0) throw new Error("missing signature block");
	if (t[SIGNED_BEGIN.length] !== "\n") throw new Error("not a signed message");
	const msg = t.slice(SIGNED_BEGIN.length + 1, sigIdx);
	const { signKey, sig } = parseSigBlock(
		t.slice(sigIdx + SIG_BEGIN.length + 2, t.length - SIGNED_END.length),
	);
	return { msg, signKey, sig };
}

export function parseDetachedSig(text: string) {
	const t = text.replaceAll("\r\n", "\n").trim();
	if (!t.startsWith(SIG_BEGIN) || !t.endsWith(SIG_END))
		throw new Error("not a signature file");
	return parseSigBlock(t.slice(SIG_BEGIN.length, t.length - SIG_END.length));
}

export const armorEncrypted = (bin: Uint8Array) =>
	[ENC_BEGIN, wrap64(b64(bin)), ENC_END, ""].join("\n");

export function unarmorEncrypted(text: string) {
	const t = text.replaceAll("\r\n", "\n").trim();
	if (!t.startsWith(ENC_BEGIN) || !t.endsWith(ENC_END))
		throw new Error("not an encrypted message");
	const { b64: body } = armorParts(
		t.slice(ENC_BEGIN.length, t.length - ENC_END.length),
	);
	const bin = unb64(body);
	if (b64(bin) !== body) throw new Error("corrupt encrypted block");
	return bin;
}
