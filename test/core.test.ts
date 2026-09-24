import { describe, expect, test } from "bun:test";
import { concatBytes, randomBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import {
	armorAlias,
	armorBundle,
	armorEncrypted,
	armorRotation,
	armorSignedMessage,
	decodeKey,
	decryptBytes,
	encodeKey,
	encryptBytes,
	expandSignKeys,
	extractBundleString,
	fromBech,
	identityFromSeed,
	KEM_PK,
	parseAliases,
	parseRotations,
	parseSignedMessage,
	SALT_LEN,
	SIGN_PK,
	signBytes,
	signClaim,
	signer,
	signerKey,
	signRotation,
	toBech,
	unarmorEncrypted,
	verifyBytes,
	verifyClaim,
	verifyRotation,
} from "../src/core.ts";
import { packSignKeys, unpackSignKeys } from "../src/store.ts";
import { sealChunk } from "../src/stream.ts";
import { mint } from "./helpers.ts";

const bytes = (n: number) =>
	Uint8Array.from({ length: n }, (_, i) => (i * 7 + 13) & 0xff);
const utf8 = (s: string) => new TextEncoder().encode(s);

describe("encoding", () => {
	test("roundtrips and rejects corruption", () => {
		const data = randomBytes(64);
		const s = toBech("np", data);
		expect(fromBech("np", s)).toEqual(data);
		const flipped = `${s.slice(0, 20)}${s[20] === "a" ? "b" : "a"}${s.slice(21)}`;
		expect(() => fromBech("np", flipped)).toThrow(/checksum/);
	});

	test("key strings are charset-safe", () => {
		const id = encodeKey(mint().key);
		expect(id.startsWith("npkey1")).toBe(true);
		expect(id).toMatch(/^npkey1[a-z2-7]+$/);
	});

	test("rejects the wrong prefix", () => {
		expect(() => fromBech("npsec", mint().key)).toThrow();
	});
});

describe("signatures", () => {
	test("verifies, and rejects tampering", () => {
		const id = mint();
		const armored = armorSignedMessage("hello", id, "tester");
		const parsed = parseSignedMessage(armored);
		expect(parsed.signKey).toEqual(signerKey(id.key));
		expect(verifyBytes(parsed.signKey, parsed.sig, utf8(parsed.msg))).toBe(
			true,
		);
		expect(verifyBytes(parsed.signKey, parsed.sig, utf8("hell0"))).toBe(false);
	});

	test("another key cannot verify", () => {
		const id = mint();
		const other = mint();
		const { sig, msg } = parseSignedMessage(armorSignedMessage("hi", id));
		expect(verifyBytes(signerKey(other.key), sig, utf8(msg))).toBe(false);
	});

	test("message and file contexts are separate", () => {
		const id = mint();
		const { sig, msg } = parseSignedMessage(armorSignedMessage("x", id));
		expect(verifyBytes(signerKey(id.key), sig, utf8(msg), true)).toBe(false);
	});

	test("armor never exceeds 64 columns", () => {
		const id = mint();
		const blocks = [
			armorSignedMessage("hello", id, "tester"),
			armorBundle(id.key, "np public key of tester"),
			armorAlias("tester", signClaim(id, "tester")),
			armorEncrypted(encryptBytes(utf8("x"), [id.key])),
		];
		for (const b of blocks)
			for (const line of b.split("\n"))
				expect(line.length).toBeLessThanOrEqual(64);
	});
});

describe("encryption", () => {
	test("every recipient can open it, outsiders cannot", () => {
		const a = mint();
		const b = mint();
		const eve = mint();
		const ct = encryptBytes(utf8("secret meow"), [a.bundle, b.bundle]);
		expect(new TextDecoder().decode(decryptBytes(ct, a).data)).toBe(
			"secret meow",
		);
		expect(new TextDecoder().decode(decryptBytes(ct, b).data)).toBe(
			"secret meow",
		);
		expect(() => decryptBytes(ct, eve).data).toThrow(
			/not encrypted to your key/,
		);
	});

	test("survives multi-chunk payloads", () => {
		const id = mint();
		const big = bytes(200_000);
		expect(decryptBytes(encryptBytes(big, [id.key]), id).data).toEqual(big);
	});

	test("detects truncation", () => {
		const id = mint();
		const ct = encryptBytes(bytes(200_000), [id.key]);
		expect(() =>
			decryptBytes(ct.slice(0, ct.length - 65552).data, id),
		).toThrow();
	});

	test("detects chunk reordering", () => {
		const id = mint();
		const ct = encryptBytes(bytes(200_000), [id.key]);
		const sealed = 65536 + 16;
		const head = ct.length - 200_000 - 4 * 16;
		const swapped = new Uint8Array(ct);
		const first = swapped.slice(head, head + sealed);
		swapped.set(swapped.slice(head + sealed, head + 2 * sealed), head);
		swapped.set(first, head + sealed);
		expect(() => decryptBytes(swapped, id).data).toThrow();
	});

	test("handles empty input", () => {
		const id = mint();
		expect(
			decryptBytes(encryptBytes(new Uint8Array(0), [id.key]), id).data.length,
		).toBe(0);
	});

	test("armor roundtrips", () => {
		const id = mint();
		const armored = armorEncrypted(encryptBytes(utf8("meow"), [id.key]));
		expect(
			new TextDecoder().decode(
				decryptBytes(unarmorEncrypted(armored), id).data,
			),
		).toBe("meow");
	});
});

describe("key bundles", () => {
	test("armored and raw both parse to the same bundle", () => {
		const id = mint();
		const raw = encodeKey(id.key);
		expect(extractBundleString(armorBundle(id.key, "c"))).toBe(raw);
		expect(extractBundleString(raw)).toBe(raw);
		expect(extractBundleString(`<pre>${armorBundle(id.key)}</pre>`)).toBe(raw);
		expect(decodeKey(raw)).toEqual(id.key);
	});
});

describe("alias claims", () => {
	test("bind a key to one name only", () => {
		const id = mint();
		const evil = mint();
		const file = wellKnownLike(id, "tiago.zip");
		const [alias] = parseAliases(file);
		expect(alias?.name).toBe("tiago.zip");
		expect(verifyClaim(id.key, "tiago.zip", alias.sig)).toBe(true);
		expect(verifyClaim(id.key, "evil.com", alias.sig)).toBe(false);
		expect(verifyClaim(evil.key, "tiago.zip", alias.sig)).toBe(false);
	});
});

describe("rotation certificates", () => {
	test("prove a succession, and only that one", () => {
		const old = mint();
		const next = mint();
		const evil = mint();
		const [cert] = parseRotations(
			armorRotation(old.key, next.key, signRotation(old, next.key)),
		);
		expect(cert.from).toEqual(old.key);
		expect(cert.to).toEqual(next.key);
		expect(verifyRotation(cert.from, cert.to, cert.sig)).toBe(true);
		expect(verifyRotation(old.key, evil.key, cert.sig)).toBe(false);
		expect(verifyRotation(evil.key, cert.from, cert.to, cert.sig)).toBe(false);
	});
});

describe("identity", () => {
	test("is deterministic from the seed", () => {
		const id = mint();
		expect(identityFromSeed(id.seed).key).toEqual(id.key);
	});

	test("rejects dead seed formats", () => {
		expect(() => identityFromSeed(randomBytes(66))).toThrow(/old np version/);
		expect(() => identityFromSeed(randomBytes(32))).toThrow(/bad seed length/);
	});
});

function wellKnownLike(id: ReturnType<typeof mint>, name: string) {
	return (
		armorBundle(id.key, `np public key of ${name}`) +
		armorAlias(name, signClaim(id, name))
	);
}

describe("identity loading", () => {
	test("a stored bundle that doesn't match the seed is caught", () => {
		const seed = randomBytes(74);
		const other = identityFromSeed(randomBytes(74));
		const id = identityFromSeed(seed, other.key);
		expect(id.key).toBe(other.key);
		expect(() => id.kemSecret).toThrow(/does not match/);
		expect(() => id.signKeys).toThrow(/does not match/);
	});

	test("a stored bundle that matches is used as-is", () => {
		const seed = randomBytes(74);
		const derived = identityFromSeed(seed);
		const loaded = identityFromSeed(seed, derived.bundle);
		expect(loaded.key).toBe(derived.key);
		expect(loaded.signKeys.falconSecret).toEqual(derived.signKeys.falconSecret);
		expect(loaded.kemSecret).toEqual(derived.kemSecret);
	});
});

describe("stream limits", () => {
	test("the chunk counter refuses to wrap", () => {
		const key = new Uint8Array(32);
		expect(() => sealChunk(key, 2 ** 32, false, new Uint8Array(4))).toThrow(
			/256 TiB/,
		);
		expect(() =>
			sealChunk(key, 2 ** 32 - 1, true, new Uint8Array(4)),
		).not.toThrow();
	});
});

describe("cached sign keys", () => {
	test("a cached keypair signs and verifies like a derived one", () => {
		const seed = concatBytes(
			randomBytes(32),
			randomBytes(32),
			randomBytes(2),
			randomBytes(8),
		);
		const derived = identityFromSeed(seed);
		const pk = derived.bundle.slice(
			SALT_LEN + KEM_PK,
			SALT_LEN + KEM_PK + SIGN_PK,
		);
		const cached = identityFromSeed(seed, derived.bundle, {
			publicKey: pk,
			falconSecret: derived.signKeys.falconSecret,
			edSecret: derived.signKeys.edSecret,
		});
		const msg = utf8ToBytes("cached key signing");
		expect(
			verifyBytes(signerKey(derived.bundle), signBytes(cached, msg), msg),
		).toBe(true);
		expect(cached.key).toBe(derived.key);
	});

	test("a cached keypair from the wrong identity is refused", () => {
		const a = identityFromSeed(
			concatBytes(
				randomBytes(32),
				randomBytes(32),
				randomBytes(2),
				randomBytes(8),
			),
		);
		const b = identityFromSeed(
			concatBytes(
				randomBytes(32),
				randomBytes(32),
				randomBytes(2),
				randomBytes(8),
			),
		);
		const wrong = identityFromSeed(a.seed, a.bundle, {
			publicKey: b.bundle.slice(SALT_LEN + KEM_PK, SALT_LEN + KEM_PK + SIGN_PK),
			falconSecret: b.signKeys.falconSecret,
			edSecret: b.signKeys.edSecret,
		});
		expect(() => wrong.signKeys).toThrow(/does not match/);
	});
});

describe("sign key cache format", () => {
	test("packs and unpacks a keypair", () => {
		const id = identityFromSeed(
			concatBytes(
				randomBytes(32),
				randomBytes(32),
				randomBytes(2),
				randomBytes(8),
			),
		);
		const keys = {
			publicKey: id.key.slice(SALT_LEN + KEM_PK, SALT_LEN + KEM_PK + SIGN_PK),
			falconSecret: id.signKeys.falconSecret,
			edSecret: id.signKeys.edSecret,
		};
		const stored = `${toBech("npsec", id.seed)}\n${packSignKeys(keys)}`;
		const back = unpackSignKeys(stored);
		expect(back?.publicKey).toEqual(keys.publicKey);
		expect(back?.falconSecret).toEqual(keys.falconSecret);
		expect(back?.edSecret).toEqual(keys.edSecret);
	});

	test("ignores a missing, truncated or damaged cache line", () => {
		expect(unpackSignKeys("npsec1abc")).toBeUndefined();
		expect(unpackSignKeys("npsec1abc\nnpsign1 ")).toBeUndefined();
		expect(unpackSignKeys("npsec1abc\nnpsign1 aGk=.aGk=.aGk=")).toBeUndefined();
	});
});

describe("hybrid signer composition", () => {
	test("expanded keys match what the combined signer derives", () => {
		const seed = randomBytes(32);
		expect(expandSignKeys(seed).publicKey).toEqual(
			signer().keygen(seed).publicKey,
		);
	});

	test("signatures interoperate with the combined signer both ways", () => {
		const seed = concatBytes(
			randomBytes(32),
			randomBytes(32),
			randomBytes(2),
			randomBytes(8),
		);
		const id = identityFromSeed(seed);
		const msg = utf8ToBytes("interop");
		const mine = signBytes(id, msg);
		const theirs = signer().sign(msg, seed.slice(32, 64));
		const pk = id.key.slice(SALT_LEN + KEM_PK, SALT_LEN + KEM_PK + SIGN_PK);
		expect(mine.length).toBe(theirs.length);
		expect(verifyBytes(signerKey(id.key), mine, msg)).toBe(true);
		expect(signer().verify(theirs, msg, pk)).toBe(true);
	});
});
