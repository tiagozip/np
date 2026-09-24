import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import {
	decryptBytes,
	encryptBytes,
	identityFromSeed,
	unarmorEncrypted,
} from "../src/core.ts";
import { installIdentity, np } from "./helpers.ts";
import {
	V1_ARMOR,
	V1_FILE_B64,
	V1_FILE_PLAIN,
	V1_MESSAGE,
	V1_SEED,
	V2_ARMOR,
	V2_MESSAGE,
	V2_SEED,
} from "./vectors.ts";

const root = join(import.meta.dir, ".tmp-compat");
const id = identityFromSeed(V1_SEED);

beforeAll(() => {
	rmSync(root, { recursive: true, force: true });
	mkdirSync(root, { recursive: true });
	installIdentity(root, id);
});
afterAll(() => rmSync(root, { recursive: true, force: true }));

const v1File = () => Buffer.from(V1_FILE_B64, "base64");

describe("format", () => {
	test("a v1 message still decrypts", () => {
		const plain = decryptBytes(unarmorEncrypted(V1_ARMOR), id).data;
		expect(new TextDecoder().decode(plain)).toBe(V1_MESSAGE);
	});

	test("a v1 file still decrypts through the cli", async () => {
		const path = join(root, "legacy.np");
		writeFileSync(path, v1File());
		const r = await np([path, "-o", "-"], root);
		expect(r.code).toBe(0);
		expect(r.out).toBe(V1_FILE_PLAIN);
	});

	test("a tampered v1 file is still rejected", async () => {
		const bytes = v1File();
		bytes[bytes.length - 20] ^= 0x40;
		const path = join(root, "tampered.np");
		writeFileSync(path, bytes);
		const r = await np([path, "-o", join(root, "nope")], root);
		expect(r.code).toBe(1);
		expect(r.err).toContain("corrupt or tampered");
	});

	test("new ciphertext is v4 and round-trips", () => {
		const bin = encryptBytes(new TextEncoder().encode("hello v3"), [id.key]);
		expect(new TextDecoder().decode(bin.slice(0, 4))).toBe("NPE4");
		expect(new TextDecoder().decode(decryptBytes(bin, id).data)).toBe(
			"hello v3",
		);
	});

	test("a v2 blob still decrypts", () => {
		const old = identityFromSeed(V2_SEED);
		const bin = unarmorEncrypted(V2_ARMOR);
		expect(new TextDecoder().decode(bin.slice(0, 4))).toBe("NPE2");
		expect(new TextDecoder().decode(decryptBytes(bin, old).data)).toBe(
			V2_MESSAGE,
		);
	});

	test("a tampered v2 blob is rejected", () => {
		const old = identityFromSeed(V2_SEED);
		const bin = unarmorEncrypted(V2_ARMOR);
		bin[bin.length - 5] ^= 0x20;
		expect(() => decryptBytes(bin, old)).toThrow();
	});

	test("v1 and v2 payload keys are separated", () => {
		const v1 = unarmorEncrypted(V1_ARMOR);
		const forged = new Uint8Array(v1);
		forged[3] = 0x32;
		expect(() => decryptBytes(forged, id)).toThrow();
	});

	test("cli files round-trip across a window boundary", async () => {
		const big = new Uint8Array(9_000_011);
		for (let i = 0; i < big.length; i += 7) big[i] = i & 0xff;
		const src = join(root, "big.bin");
		writeFileSync(src, big);
		const full = readFileSync(join(root, "identity"), "utf8")
			.split("\n")
			.find((l) => l.startsWith("# key: "))
			?.slice(7) as string;
		expect((await np([src, "-to", full, "--no-self"], root)).code).toBe(0);
		expect(
			(await np([`${src}.np`, "-o", join(root, "big.out")], root)).code,
		).toBe(0);
		expect(readFileSync(join(root, "big.out"))).toEqual(Buffer.from(big));
	});
});
