import { describe, expect, test } from "bun:test";
import {
	armorAlias,
	armorBundle,
	armorDetachedSig,
	armorEncrypted,
	armorRevocation,
	armorRotation,
	armorSignedMessage,
	decodeKey,
	decryptBytes,
	encodeKey,
	encryptBytes,
	extractBundleString,
	parseAliases,
	parseDetachedSig,
	parseRevocations,
	parseRotations,
	parseSignedMessage,
	signClaim,
	signRevocation,
	signRotation,
	unarmorEncrypted,
	verifyBytes,
	verifyClaim,
	verifyFileHash,
	verifyRevocation,
	verifyRotation,
} from "../src/core.ts";
import { mint } from "./helpers.ts";

let seed = 0x5eed1;
const rnd = () => {
	seed = (seed * 1664525 + 1013904223) >>> 0;
	return seed / 0x100000000;
};
const pick = <T>(xs: T[]) => xs[Math.floor(rnd() * xs.length)] as T;
const utf8 = (s: string) => new TextEncoder().encode(s);

function mutate(text: string) {
	const lines = text.split("\n");
	switch (Math.floor(rnd() * 6)) {
		case 0:
			return text.slice(0, Math.floor(rnd() * text.length));
		case 1: {
			const at = Math.floor(rnd() * text.length);
			const c = "abcdefghijklmnopqrstuvwxyz0123456789+/= \n-";
			return text.slice(0, at) + pick([...c]) + text.slice(at + 1);
		}
		case 2:
			return lines
				.filter((_, i) => i !== Math.floor(rnd() * lines.length))
				.join("\n");
		case 3:
			return `${text}${pick(["A", "\n", "====", "np1", "-".repeat(64)])}`;
		case 4:
			return lines.map((l) => (rnd() < 0.15 ? l.toUpperCase() : l)).join("\n");
		default: {
			const a = Math.floor(rnd() * lines.length);
			const b = Math.floor(rnd() * lines.length);
			const copy = [...lines];
			[copy[a], copy[b]] = [copy[b] as string, copy[a] as string];
			return copy.join("\n");
		}
	}
}

const clean = (fn: () => unknown) => {
	try {
		return { threw: false as const, value: fn() };
	} catch (e) {
		expect(e).toBeInstanceOf(Error);
		expect((e as Error).message.length).toBeGreaterThan(0);
		return { threw: true as const, value: undefined };
	}
};

const alice = mint();
const bob = mint();

describe("mangled signed messages", () => {
	const good = armorSignedMessage("the original message", alice, "alice");

	test("never verify as valid, and never crash", () => {
		let parsed = 0;
		for (let i = 0; i < 200; i++) {
			const bad = mutate(good);
			if (bad === good) continue;
			const r = clean(() => parseSignedMessage(bad));
			if (r.threw || !r.value) continue;
			parsed++;
			const { msg, sig } = r.value as ReturnType<typeof parseSignedMessage>;
			if (msg === "the original message") continue;
			expect(verifyBytes(alice.key, sig, utf8(msg))).toBe(false);
		}
		expect(parsed).toBeGreaterThan(0);
	});

	test("a wrong signer never verifies", () => {
		const { msg, sig } = parseSignedMessage(good);
		expect(verifyBytes(bob.key, sig, utf8(msg))).toBe(false);
	});
});

describe("mangled detached signatures", () => {
	const hash = new Uint8Array(64).fill(9);
	const good = armorDetachedSig(hash, "doc.txt", alice, "alice");

	test("never verify as valid, and never crash", () => {
		for (let i = 0; i < 200; i++) {
			const r = clean(() => parseDetachedSig(mutate(good)));
			if (r.threw || !r.value) continue;
			const { sig, signKey } = r.value as ReturnType<typeof parseDetachedSig>;
			const original = parseDetachedSig(good);
			expect(verifyFileHash(signKey, sig, hash)).toBe(
				Buffer.from(sig).equals(Buffer.from(original.sig)) &&
					Buffer.from(signKey).equals(Buffer.from(original.signKey)),
			);
		}
	});
});

describe("mangled ciphertext", () => {
	const plain = utf8("a secret worth protecting");
	const good = armorEncrypted(encryptBytes(plain, [alice.key]));

	test("never decrypts, and never crashes", () => {
		let attempted = 0;
		for (let i = 0; i < 150; i++) {
			const bad = mutate(good);
			if (bad === good) continue;
			const unarmored = clean(() => unarmorEncrypted(bad));
			if (unarmored.threw || !unarmored.value) continue;
			attempted++;
			const out = clean(
				() => decryptBytes(unarmored.value as Uint8Array, alice).data,
			);
			if (!out.threw)
				expect(
					Buffer.from(out.value as Uint8Array).equals(Buffer.from(plain)),
				).toBe(
					Buffer.from(unarmored.value as Uint8Array).equals(
						Buffer.from(unarmorEncrypted(good)),
					),
				);
		}
		expect(attempted).toBeGreaterThan(0);
	});

	test("a stranger never decrypts it", () => {
		expect(() => decryptBytes(unarmorEncrypted(good).data, bob)).toThrow();
	});
});

describe("mangled key material", () => {
	const good = armorBundle(alice.key, "np public key of alice");

	test("bundles either decode to the same key or fail cleanly", () => {
		let decoded = 0;
		for (let i = 0; i < 200; i++) {
			const str = clean(() => extractBundleString(mutate(good)));
			if (str.threw || !str.value) continue;
			const r = clean(() => decodeKey(str.value as string));
			if (r.threw) continue;
			decoded++;
			expect(Buffer.from(r.value as Uint8Array)).toEqual(
				Buffer.from(alice.key),
			);
		}
		expect(decoded).toBeGreaterThan(0);
	});

	test("a mangled key string never decodes to a different key", () => {
		const encoded = encodeKey(alice.key);
		for (let i = 0; i < 200; i++) {
			const bad = mutate(encoded);
			const r = clean(() => decodeKey(bad));
			if (!r.threw)
				expect(Buffer.from(r.value as Uint8Array)).toEqual(
					Buffer.from(alice.key),
				);
		}
	});
});

describe("mangled alias and rotation certificates", () => {
	const aliasBlock = armorAlias(
		"alice.example",
		signClaim(alice, "alice.example"),
	);
	const rotBlock = armorRotation(
		alice.key,
		bob.key,
		signRotation(alice, bob.key),
	);

	test("aliases never bind a name they did not sign", () => {
		let seen = 0;
		for (let i = 0; i < 150; i++) {
			const r = clean(() => parseAliases(mutate(aliasBlock)));
			for (const a of (r.value ?? []) as { name: string; sig: Uint8Array }[]) {
				seen++;
				const ok = verifyClaim(alice.key, a.name, a.sig);
				if (ok) expect(a.name).toBe("alice.example");
			}
		}
		expect(seen).toBeGreaterThan(0);
	});

	test("revocations never kill a key that did not sign them", () => {
		const revBlock = armorRevocation(
			alice.key,
			"lost it",
			signRevocation(alice, "lost it"),
		);
		let seen = 0;
		for (let i = 0; i < 150; i++) {
			const r = clean(() => parseRevocations(mutate(revBlock)));
			for (const rev of (r.value ?? []) as {
				id: string;
				reason: string;
				sig: Uint8Array;
			}[]) {
				seen++;
				const ok = verifyRevocation(alice.key, rev.id, rev.reason, rev.sig);
				if (ok) {
					expect(rev.id).toBe(alice.key);
					expect(rev.reason).toBe("lost it");
				}
			}
		}
		expect(seen).toBeGreaterThan(0);
	});

	test("rotations never prove a succession that was not signed", () => {
		let seen = 0;
		for (let i = 0; i < 150; i++) {
			const r = clean(() => parseRotations(mutate(rotBlock)));
			for (const c of (r.value ?? []) as {
				from: string;
				to: string;
				sig: Uint8Array;
			}[]) {
				seen++;
				const ok = verifyRotation(alice.key, c.from, c.to, c.sig);
				if (ok) {
					expect(c.from).toBe(alice.key);
					expect(c.to).toBe(bob.key);
				}
			}
		}
		expect(seen).toBeGreaterThan(0);
	});
});

describe("arbitrary junk", () => {
	test("every parser rejects random bytes without crashing", () => {
		for (let i = 0; i < 300; i++) {
			const len = Math.floor(rnd() * 400);
			const junk = Array.from({ length: len }, () =>
				String.fromCharCode(32 + Math.floor(rnd() * 95)),
			).join("");
			clean(() => parseSignedMessage(junk));
			clean(() => parseDetachedSig(junk));
			clean(() => unarmorEncrypted(junk));
			clean(() => extractBundleString(junk));
			clean(() => decodeKey(junk));
			clean(() => decodeKey(junk));
			clean(() => parseAliases(junk));
			clean(() => parseRotations(junk));
			clean(() => parseRevocations(junk));
		}
	});
});
