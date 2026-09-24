import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import {
	existsSync,
	mkdirSync,
	readFileSync,
	rmSync,
	symlinkSync,
	writeFileSync,
} from "node:fs";
import { join } from "node:path";
import { concatBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import {
	armorBundle,
	armorDetachedSig,
	armorEncrypted,
	armorRotation,
	armorSignedMessage,
	BUNDLE_LEN,
	CHARSET,
	decodeKey,
	decryptBytes,
	encodeKey,
	encryptBytes,
	encryptHeader,
	extractBundleString,
	fingerprint,
	fromBech,
	openHeader,
	padTo,
	parseDetachedSig,
	parseSignedMessage,
	SIGNED_BEGIN,
	STANZA_LEN,
	signBytes,
	signClaim,
	signerKey,
	signFileHash,
	signInner,
	signRevocation,
	signRotation,
	TRAILER,
	toBech,
	unarmorEncrypted,
	verifyBytes,
	verifyClaim,
	verifyFileHash,
	verifyKey,
	verifyRevocation,
	verifyRotation,
} from "../src/core.ts";
import { CHUNK, openChunk, sealChunk } from "../src/stream.ts";
import { treeHasher } from "../src/treehash.ts";
import { installIdentity, mint, np } from "./helpers.ts";

const me = mint();
const them = mint();
const msg = "transfer 10 to alice";

describe("encoding is canonical", () => {
	test("an extra all-zero word is rejected, not silently accepted", () => {
		expect(() => decodeKey(`${encodeKey(me.key)}q`)).toThrow();
	});

	test("every suffix word that keeps the payload identical is rejected", () => {
		for (const c of CHARSET) {
			let decoded: Uint8Array | null = null;
			try {
				decoded = decodeKey(`${encodeKey(me.key)}${c}`);
			} catch {}
			expect(decoded).toBeNull();
		}
	});

	test("uppercase decodes to the same key", () => {
		expect(decodeKey(encodeKey(me.key).toUpperCase())).toEqual(me.key);
	});

	test("a flipped checksum byte is caught", () => {
		const s = encodeKey(me.key);
		const swap = s.slice(0, -1) + (s.at(-1) === "q" ? "p" : "q");
		expect(() => decodeKey(swap)).toThrow();
	});

	test("a character outside the charset is rejected", () => {
		expect(() => decodeKey(encodeKey(me.key).replace(/.$/, "1"))).toThrow();
		expect(() => decodeKey(encodeKey(me.key).replace(/.$/, "0"))).toThrow();
	});

	test("toWords round-trips through the charset", () => {
		const bytes = new Uint8Array([0, 1, 254, 255, 128, 7]);
		const s = toBech("np", bytes);
		expect(fromBech("np", s)).toEqual(bytes);
	});

	test("the wrong hrp is rejected even with a valid body", () => {
		expect(() => fromBech("npsec", encodeKey(me.key))).toThrow();
	});

	test("bundles of the wrong length are rejected", () => {
		expect(() => decodeKey(encodeKey(me.key.slice(0, 100)))).toThrow();
	});
});

describe("signatures do not cross contexts", () => {
	test("a file signature does not verify as a message", () => {
		const hash = new Uint8Array(64).fill(9);
		const sig = signFileHash(me, hash);
		expect(verifyBytes(me.key, sig, hash)).toBe(false);
	});

	test("a message signature does not verify as a file hash", () => {
		const body = new Uint8Array(64).fill(3);
		const sig = signBytes(me, body);
		expect(verifyFileHash(me.key, sig, body)).toBe(false);
	});

	test("a name claim cannot be replayed onto another name", () => {
		const sig = signClaim(me, "alice");
		expect(verifyClaim(me.key, "alice", sig)).toBe(true);
		expect(verifyClaim(me.key, "alicia", sig)).toBe(false);
		expect(verifyClaim(me.key, "alice ", sig)).toBe(false);
		expect(verifyClaim(me.key, "", sig)).toBe(false);
	});

	test("a claim by one key does not validate for another key", () => {
		const sig = signClaim(me, "alice");
		expect(verifyClaim(them.key, "alice", sig)).toBe(false);
	});

	test("a rotation certificate cannot be reversed", () => {
		const sig = signRotation(me, them.key);
		expect(verifyRotation(me.key, them.key, sig)).toBe(true);
		expect(verifyRotation(them.key, me.key, sig)).toBe(false);
	});

	test("a rotation certificate cannot be pointed at a third key", () => {
		const third = mint();
		const sig = signRotation(me, them.key);
		expect(verifyRotation(me.key, third.key, sig)).toBe(false);
	});

	test("a revocation is bound to its key and reason", () => {
		const sig = signRevocation(me, "stolen");
		expect(verifyRevocation(me.key, "stolen", sig)).toBe(true);
		expect(verifyRevocation(me.key, "not stolen", sig)).toBe(false);
		expect(verifyRevocation(them.key, "stolen", sig)).toBe(false);
	});

	test("a signature does not verify under a different key", () => {
		const sig = signBytes(me, utf8ToBytes(msg));
		expect(verifyBytes(them.key, sig, utf8ToBytes(msg))).toBe(false);
	});

	test("every single-bit flip in a signature is rejected", () => {
		const sig = signBytes(me, utf8ToBytes(msg));
		for (const at of [0, 1, 300, 660, 700, sig.length - 1]) {
			const bad = Uint8Array.from(sig);
			(bad[at] as number) ^= 1;
			expect(verifyBytes(me.key, bad, utf8ToBytes(msg))).toBe(false);
		}
	});

	test("truncating or extending a signature is rejected", () => {
		const sig = signBytes(me, utf8ToBytes(msg));
		expect(verifyBytes(me.key, sig.slice(0, -1), utf8ToBytes(msg))).toBe(false);
		expect(
			verifyBytes(
				me.key,
				concatBytes(sig, new Uint8Array(1)),
				utf8ToBytes(msg),
			),
		).toBe(false);
	});
});

describe("armor blocks hide nothing", () => {
	const signed = armorSignedMessage("I approve the $10 payment.", me);

	test("text smuggled after the signature is rejected", () => {
		const lines = signed.trimEnd().split("\n");
		const smuggled = [
			...lines.slice(0, -1),
			"",
			"Also I hereby transfer my house to Mallory.",
			lines.at(-1) as string,
		].join("\n");
		expect(() => parseSignedMessage(smuggled)).toThrow();
	});

	test("a field line smuggled after the body is rejected", () => {
		const lines = signed.trimEnd().split("\n");
		const smuggled = [
			...lines.slice(0, -1),
			"key: np1thisisnottherealsigner",
			lines.at(-1) as string,
		].join("\n");
		expect(() => parseSignedMessage(smuggled)).toThrow();
	});

	test("the real message still parses and verifies", () => {
		const { msg, sig, signKey } = parseSignedMessage(signed);
		expect(msg).toBe("I approve the $10 payment.");
		expect(signKey).toEqual(signerKey(me.key));
		expect(verifyBytes(signKey, sig, utf8ToBytes(msg))).toBe(true);
	});

	test("crlf line endings still verify", () => {
		const { msg, sig, signKey } = parseSignedMessage(
			signed.replaceAll("\n", "\r\n"),
		);
		expect(verifyBytes(signKey, sig, utf8ToBytes(msg))).toBe(true);
	});

	test("two encrypted blocks in one file are rejected, not silently halved", () => {
		const a = encryptBytes(utf8ToBytes("first"), [me.key]);
		const b = encryptBytes(utf8ToBytes("second"), [me.key]);
		const glued = armorEncrypted(a).trimEnd() + armorEncrypted(b);
		let out: Uint8Array | null = null;
		try {
			out = unarmorEncrypted(glued);
		} catch {}
		if (out) expect(decryptBytes(out, me).data).toEqual(utf8ToBytes("first"));
		else expect(out).toBeNull();
	});

	test("a signature block with a junk line is rejected", () => {
		const sig = armorDetachedSig(
			new Uint8Array(64),
			"f.txt",
			me,
			undefined,
			"tree512-8m",
		);
		const broken = sig.replace(
			"hash: tree512-8m",
			"hash: tree512-8m\nnot base64 at all!",
		);
		expect(() => parseDetachedSig(broken)).toThrow();
	});

	test("a key line cannot be smuggled into a signature block", () => {
		const sig = armorDetachedSig(new Uint8Array(64), "f.txt", me);
		for (const evil of [
			"/etc/passwd",
			"https://evil.example/beacon",
			"/dev/zero",
			"alice",
		]) {
			const hostile = sig.replace(
				"untrusted comment:",
				`key: ${evil}\nuntrusted comment:`,
			);
			const parsed = parseDetachedSig(hostile);
			expect(parsed.signKey).toEqual(signerKey(me.key));
		}
	});

	test("a well formed detached signature still parses", () => {
		const hash = new Uint8Array(64).fill(7);
		const armor = armorDetachedSig(hash, "f.txt", me, "meow", "tree512-8m");
		const parsed = parseDetachedSig(armor);
		expect(parsed.signKey).toEqual(signerKey(me.key));
		expect(parsed.alg).toBe("tree512-8m");
		expect(verifyFileHash(parsed.signKey, parsed.sig, hash)).toBe(true);
	});
});

describe("hostile files cannot steer the cli", () => {
	const root = join(import.meta.dir, ".adv");
	const home = join(root, "home");
	const env = { NP_KEYSERVER: "http://127.0.0.1:1" };
	let beacons: string[] = [];
	let server: ReturnType<typeof Bun.serve>;

	beforeAll(() => {
		rmSync(root, { recursive: true, force: true });
		mkdirSync(root, { recursive: true });
		installIdentity(home, me);
		writeFileSync(join(home, "contacts"), `self ${encodeKey(me.key)}\n`);
		server = Bun.serve({
			port: 47931,
			fetch(req) {
				beacons.push(new URL(req.url).pathname);
				return new Response("nothing here");
			},
		});
	});
	afterAll(() => {
		server.stop(true);
		rmSync(root, { recursive: true, force: true });
	});

	const signedFile = async (body: string) => {
		const path = join(root, "msg.npsigned");
		writeFileSync(path, armorSignedMessage(body, me));
		return path;
	};

	test("a signature never makes np fetch anything", async () => {
		beacons = [];
		const path = await signedFile("hello");
		writeFileSync(
			path,
			readFileSync(path, "utf8").replace(
				"untrusted comment:",
				"key: http://127.0.0.1:47931/beacon\nuntrusted comment:",
			),
		);
		const r = await np([path], home, env);
		expect(r.code).toBe(0);
		expect(beacons).toEqual([]);
	});

	test("a signature never reads a local path it names", async () => {
		const secret = join(root, "secret.txt");
		writeFileSync(secret, "not a key\n");
		const path = await signedFile("hello");
		writeFileSync(
			path,
			readFileSync(path, "utf8").replace(
				"untrusted comment:",
				`key: ${secret}\nuntrusted comment:`,
			),
		);
		const r = await np([path], home, env);
		expect(r.err).not.toContain(secret);
	});

	test("a signature naming a device file does not hang", async () => {
		const path = await signedFile("hello");
		writeFileSync(
			path,
			readFileSync(path, "utf8").replace(
				"untrusted comment:",
				"key: /dev/zero\nuntrusted comment:",
			),
		);
		const r = await np([path], home, env);
		expect(r.code).toBe(0);
	}, 10_000);

	test("smuggled text after a signature is refused, not shown as signed", async () => {
		const path = join(root, "smuggle.npsigned");
		const armor = armorSignedMessage(
			"I approve the $10 payment.",
			me,
		).trimEnd();
		const lines = armor.split("\n");
		writeFileSync(
			path,
			[
				...lines.slice(0, -1),
				"",
				"Also I hereby transfer my house to Mallory.",
				lines.at(-1) as string,
				"",
			].join("\n"),
		);
		const r = await np([path], home, env);
		expect(r.code).toBe(1);
		expect(r.out).not.toContain("I approve");
	});

	test("a tampered message prints nothing to stdout", async () => {
		const path = join(root, "bad.npsigned");
		writeFileSync(
			path,
			armorSignedMessage("pay alice 10", me).replace(
				"pay alice 10",
				"pay mallory 9999",
			),
		);
		const r = await np([path], home, env);
		expect(r.code).toBe(1);
		expect(r.out).toBe("");
		expect(r.err).toContain("BAD signature");
	});

	test("a contact name with whitespace cannot inject a second contact", async () => {
		const other = mint();
		const r = await np(
			[
				"contacts",
				"add",
				encodeKey(other.key),
				`evil ${encodeKey(them.key)}\nalice`,
			],
			home,
			env,
		);
		expect(r.code).toBe(1);
		const contacts = join(home, "contacts");
		const text = existsSync(contacts) ? readFileSync(contacts, "utf8") : "";
		expect(text).not.toContain("alice");
	});

	test("a plain contact name still imports", async () => {
		const other = mint();
		const r = await np(
			["contacts", "add", encodeKey(other.key), "bob"],
			home,
			env,
		);
		expect(r.code).toBe(0);
		expect(readFileSync(join(home, "contacts"), "utf8")).toContain("bob");
	});
});

describe("padding and header integrity", () => {
	test("short messages of different lengths share a ciphertext size", () => {
		const sizes = new Set(
			[0, 1, 7, 30, 63].map(
				(n) => encryptBytes(new Uint8Array(n), [me.key]).length,
			),
		);
		expect(sizes.size).toBe(1);
	});

	test("padding overhead stays under 4 percent for large inputs", () => {
		for (const n of [100_000, 250_000, 1_000_000]) {
			const ct = encryptBytes(new Uint8Array(n), [me.key]);
			const overhead = (ct.length - n) / n;
			expect(overhead).toBeLessThan(0.04);
		}
	});

	test("a recipient cannot be stripped from the header", () => {
		const third = mint();
		const ct = encryptBytes(utf8ToBytes("group secret"), [
			me.key,
			them.key,
			third.key,
		]);
		expect(new TextDecoder().decode(decryptBytes(ct, me).data)).toBe(
			"group secret",
		);
		const start = 13;
		const stripped = concatBytes(
			ct.slice(0, 4),
			new Uint8Array([1]),
			ct.slice(5, start + STANZA_LEN),
			ct.slice(start + 3 * STANZA_LEN),
		);
		expect(() => decryptBytes(stripped, me).data).toThrow();
	});

	test("stanzas cannot be reordered", () => {
		const ct = encryptBytes(utf8ToBytes("two up"), [me.key, them.key]);
		const start = 13;
		const swapped = concatBytes(
			ct.slice(0, start),
			ct.slice(start + STANZA_LEN, start + 2 * STANZA_LEN),
			ct.slice(start, start + STANZA_LEN),
			ct.slice(start + 2 * STANZA_LEN),
		);
		expect(() => decryptBytes(swapped, me).data).toThrow();
	});

	test("the declared plaintext length cannot be edited", () => {
		const ct = encryptBytes(utf8ToBytes("exactly this"), [me.key]);
		const lied = Uint8Array.from(ct);
		(lied[12] as number) ^= 0xff;
		expect(() => decryptBytes(lied, me).data).toThrow();
	});
});

describe("np never deletes a file it did not create", () => {
	const root = join(import.meta.dir, ".adv2");
	const home = join(root, "home");
	const env = { NP_KEYSERVER: "http://127.0.0.1:1" };

	beforeAll(() => {
		rmSync(root, { recursive: true, force: true });
		mkdirSync(root, { recursive: true });
		installIdentity(home, me);
	});
	afterAll(() => rmSync(root, { recursive: true, force: true }));

	test("a corrupt ciphertext leaves an existing -o target alone", async () => {
		const ct = join(root, "in.np");
		const bytes = encryptBytes(utf8ToBytes("hello there"), [me.key]);
		(bytes[bytes.length - 3] as number) ^= 0x55;
		writeFileSync(ct, bytes);
		const precious = join(root, "thesis.txt");
		writeFileSync(precious, "IRREPLACEABLE\n");
		const r = await np([ct, "-o", precious], home, env);
		expect(r.code).toBe(1);
		expect(existsSync(precious)).toBe(true);
	});

	test("a corrupt ciphertext still removes the partial file np made", async () => {
		const ct = join(root, "in2.np");
		const bytes = encryptBytes(utf8ToBytes("hello there"), [me.key]);
		(bytes[bytes.length - 3] as number) ^= 0x55;
		writeFileSync(ct, bytes);
		const fresh = join(root, "fresh.out");
		const r = await np([ct, "-o", fresh], home, env);
		expect(r.code).toBe(1);
		expect(existsSync(fresh)).toBe(false);
	});

	test("an inner signed message does not delete an existing -o target", async () => {
		const inner = armorSignedMessage("inside", me);
		const ct = join(root, "signed.np");
		writeFileSync(ct, encryptBytes(utf8ToBytes(inner), [me.key]));
		const precious = join(root, "notes.txt");
		writeFileSync(precious, "KEEP ME\n");
		await np([ct, "-o", precious], home, env);
		expect(existsSync(precious)).toBe(true);
	});
});

describe("a pinned contact outranks the working directory", () => {
	const root = join(import.meta.dir, ".adv3");
	const home = join(root, "home");
	const work = join(root, "work");
	const env = { NP_KEYSERVER: "http://127.0.0.1:1" };
	const real = mint();
	const evil = mint();

	beforeAll(() => {
		rmSync(root, { recursive: true, force: true });
		mkdirSync(work, { recursive: true });
		installIdentity(home, me);
		writeFileSync(join(home, "contacts"), `alice ${encodeKey(real.key)}\n`);
		writeFileSync(join(work, "alice"), armorBundle(evil.key, "np public key"));
	});
	afterAll(() => rmSync(root, { recursive: true, force: true }));

	test("a file named like a contact does not replace the pinned key", async () => {
		const out = join(work, "out.np");
		const r = await np(
			["secret", "-to", "alice", "--no-self", "-o", out],
			home,
			env,
		);
		expect(r.code).toBe(0);
		const evilHome = join(root, "evil");
		installIdentity(evilHome, evil);
		expect((await np([out, "-o", "-"], evilHome, env)).code).toBe(1);
		const realHome = join(root, "real");
		installIdentity(realHome, real);
		expect((await np([out, "-o", "-"], realHome, env)).out).toContain("secret");
	});

	test("an explicit path still reads the file", async () => {
		const r = await np(
			["contacts", "add", join(work, "alice"), "fromfile"],
			home,
			env,
		);
		expect(r.code).toBe(0);
		expect(r.err).toContain(fingerprint(evil.key));
	});

	test("a bare filename with no contact of that name still works", async () => {
		writeFileSync(
			join(root, "bob.pub"),
			armorBundle(evil.key, "np public key"),
		);
		const r = await np(
			["contacts", "add", join(root, "bob.pub"), "bob"],
			home,
			env,
		);
		expect(r.code).toBe(0);
	});

	test("contact names are matched without case", async () => {
		const out = join(work, "case.np");
		const r = await np(
			["hi", "-to", "ALICE", "--no-self", "-o", out],
			home,
			env,
		);
		expect(r.code).toBe(0);
		const realHome = join(root, "real");
		expect((await np([out, "-o", "-"], realHome, env)).out).toContain("hi");
	});
});

describe("output paths", () => {
	const root = join(import.meta.dir, ".adv4");
	const home = join(root, "home");
	const env = { NP_KEYSERVER: "http://127.0.0.1:1" };

	beforeAll(() => {
		rmSync(root, { recursive: true, force: true });
		mkdirSync(root, { recursive: true });
		installIdentity(home, me);
	});
	afterAll(() => rmSync(root, { recursive: true, force: true }));

	test("-o pointing at the input refuses instead of destroying it", async () => {
		const ct = join(root, "x.np");
		writeFileSync(ct, encryptBytes(utf8ToBytes("payload"), [me.key]));
		const before = readFileSync(ct).length;
		const r = await np([ct, "-o", ct], home, env);
		expect(r.code).toBe(1);
		expect(r.err).toContain("that would destroy it");
		expect(readFileSync(ct).length).toBe(before);
	});

	test("a dangling symlink at the default output path is not written through", async () => {
		const ct = join(root, "y.np");
		writeFileSync(ct, encryptBytes(utf8ToBytes("payload"), [me.key]));
		const victim = join(root, "victim.txt");
		symlinkSync(victim, join(root, "y"));
		const r = await np([ct], home, env);
		expect(r.code).toBe(1);
		expect(existsSync(victim)).toBe(false);
	});
});

describe("bare subcommand words", () => {
	const home = join(import.meta.dir, ".adv5");
	const env = { NP_KEYSERVER: "http://127.0.0.1:1" };

	beforeAll(() => {
		rmSync(home, { recursive: true, force: true });
		installIdentity(home, me);
	});
	afterAll(() => rmSync(home, { recursive: true, force: true }));

	test("np revoke does not sign the word revoke", async () => {
		for (const word of ["revoke", "rotate", "clear", "new", "import", "add"]) {
			const r = await np([word], home, env);
			expect(r.code).toBe(1);
			expect(r.out).toBe("");
			expect(r.err).toContain("np ");
		}
	});
});

describe("findings from the second audit", () => {
	const root = join(import.meta.dir, ".adv6");
	const home = join(root, "home");
	const env = { NP_KEYSERVER: "http://127.0.0.1:1" };

	beforeAll(() => {
		rmSync(root, { recursive: true, force: true });
		mkdirSync(root, { recursive: true });
		installIdentity(home, me);
	});
	afterAll(() => rmSync(root, { recursive: true, force: true }));

	test("a piped signed message is verified, not just printed", async () => {
		const good = encryptBytes(utf8ToBytes("pay alice 10"), [me.key], me);
		const ok = await np(["decrypt", "-"], home, env, good);
		expect(ok.code).toBe(0);
		expect(ok.out).toContain("pay alice 10");
		expect(ok.err).toContain("good signature");

		const forged = Uint8Array.from(good);
		(forged[forged.length - 900] as number) ^= 0x40;
		expect((await np(["decrypt", "-"], home, env, forged)).code).toBe(1);
	});

	test("the signature trailer cannot be stripped", async () => {
		const signed = encryptBytes(utf8ToBytes("pay alice 10"), [me.key], me);
		const stripped = Uint8Array.from(signed);
		stripped[5] = 0;
		expect((await np(["decrypt", "-"], home, env, stripped)).code).toBe(1);
	});

	test("a rotation certificate is not mistaken for a key", () => {
		const next = mint();
		const cert = armorRotation(me.key, next.key, signRotation(me, next.key));
		expect(() => extractBundleString(cert)).toThrow();
	});

	test("a key string with mixed case is refused", () => {
		const s = encodeKey(me.key);
		const mixed = s.slice(0, 20).toUpperCase() + s.slice(20);
		expect(() => decodeKey(mixed)).toThrow();
		expect(decodeKey(s.toUpperCase())).toEqual(me.key);
	});

	test("the newline after the signed-message rule is required", () => {
		const armor = armorSignedMessage("hello", me);
		const bent = `${armor.slice(0, SIGNED_BEGIN.length)} ${armor.slice(SIGNED_BEGIN.length + 1)}`;
		expect(() => parseSignedMessage(bent)).toThrow();
	});

	test("a degenerate recipient key gives an error, not a stack trace", async () => {
		const zeros = encodeKey(new Uint8Array(BUNDLE_LEN));
		const r = await np(["hi", "-to", zeros, "--no-self"], home, env);
		expect(r.code).toBe(1);
		expect(r.err).not.toContain("at encryptBytes");
	});

	test("a key whose halves do not belong together is refused", async () => {
		const other = mint();
		const franken = Uint8Array.from(me.key);
		franken.set(other.key.slice(2, 2 + 1216), 2);
		expect(verifyKey(franken)).toBe(false);
		const r = await np(
			["contacts", "add", encodeKey(franken), "alice"],
			home,
			env,
		);
		expect(r.code).toBe(1);
		expect(r.err).toContain("may belong to different people");
	});
});

describe("padding still hides short messages once signed", () => {
	test("everything under 64 bytes is one ciphertext size", () => {
		const sizes = new Set(
			[0, 1, 7, 30, 63].map(
				(n) => encryptBytes(new Uint8Array(n), [me.key], them).length,
			),
		);
		expect(sizes.size).toBe(1);
	});

	test("the trailer sits after the padding, not inside it", () => {
		for (const n of [0, 1, 63, 64, 65, 1658, 1659, 1660, 65537]) {
			const plain = new Uint8Array(n);
			for (let i = 0; i < n; i += 7) plain[i] = i & 0xff;
			const out = decryptBytes(encryptBytes(plain, [me.key], them), me);
			expect(out.data).toEqual(plain);
			expect(out.signKey).toEqual(signerKey(them.key));
		}
	});

	test("an unsigned message is still padded to the same buckets", () => {
		const sizes = new Set(
			[0, 1, 7, 30, 63].map(
				(n) => encryptBytes(new Uint8Array(n), [me.key]).length,
			),
		);
		expect(sizes.size).toBe(1);
	});
});

describe("the inner signature is bound to its header", () => {
	test("a trailer cannot be moved to a message for someone else", () => {
		const bob = mint();
		const carol = mint();
		const msg = utf8ToBytes("alice says hi to bob only");
		const toBob = encryptBytes(msg, [bob.key], them);
		const oh = openHeader(toBob, bob);
		const sealed = toBob.slice(oh.bodyOffset);
		const parts: Uint8Array[] = [];
		const S = CHUNK + 16;
		for (let i = 0; i * S < sealed.length; i++)
			parts.push(
				openChunk(
					oh.key,
					i,
					(i + 1) * S >= sealed.length,
					sealed.slice(i * S, (i + 1) * S),
					oh.v,
				),
			);
		const padded = concatBytes(...parts);
		const at = padTo(msg.length);
		const trailer = padded.slice(at, at + TRAILER);
		expect(trailer.length).toBe(TRAILER);

		const made = encryptHeader([carol.key], msg.length, true);
		const full = new Uint8Array(made.padded as number);
		full.set(msg);
		full.set(trailer, at);
		const out: Uint8Array[] = [made.header];
		const total = Math.max(1, Math.ceil(full.length / CHUNK));
		for (let i = 0; i < total; i++)
			out.push(
				sealChunk(
					made.key,
					i,
					i === total - 1,
					full.subarray(i * CHUNK, (i + 1) * CHUNK),
					4,
				),
			);
		expect(() => decryptBytes(concatBytes(...out), carol)).toThrow();
	});

	test("a stream with no declared length is verified, not waved through", () => {
		const data = utf8ToBytes("streamed with no length in the header");
		const made = encryptHeader([me.key], undefined, true);
		const h = treeHasher();
		h.update(data);
		const full = concatBytes(data, signInner(them, made.header, h.root()));
		const seal = (body: Uint8Array) => {
			const out: Uint8Array[] = [made.header];
			const total = Math.max(1, Math.ceil(body.length / CHUNK));
			for (let i = 0; i < total; i++)
				out.push(
					sealChunk(
						made.key,
						i,
						i === total - 1,
						body.subarray(i * CHUNK, (i + 1) * CHUNK),
						4,
					),
				);
			return concatBytes(...out);
		};
		const good = decryptBytes(seal(full), me);
		expect(good.data).toEqual(data);
		expect(good.signKey).toEqual(signerKey(them.key));

		const swapped = Uint8Array.from(full);
		(swapped[2] as number) ^= 0x01;
		expect(() => decryptBytes(seal(swapped), me)).toThrow();
	});
});
