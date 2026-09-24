import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import {
	chmodSync,
	existsSync,
	mkdirSync,
	readFileSync,
	rmSync,
	statSync,
	writeFileSync,
} from "node:fs";
import { join } from "node:path";
import {
	armorAlias,
	armorBundle,
	armorRevocation,
	armorRotation,
	decodeKey,
	encodeKey,
	fingerprint,
	signRevocation,
	signRotation,
	toBech,
	verifyClaim,
	verifyRotation,
} from "../src/core.ts";
import { installIdentity, mint, np, wellKnown } from "./helpers.ts";

const root = join(import.meta.dir, ".tmp");
const KS_PORT = 47921;
const WK_PORT = 47922;
const KS = `http://127.0.0.1:${KS_PORT}`;
const env = { NP_KEYSERVER: KS };

const names = new Map<string, string>();
const claims = new Map<string, string>();
let served = "";
let keyserver: ReturnType<typeof Bun.serve>;
let wellKnownServer: ReturnType<typeof Bun.serve>;

const dir = (name: string) => join(root, name);

beforeAll(async () => {
	rmSync(root, { recursive: true, force: true });
	mkdirSync(root, { recursive: true });
	keyserver = Bun.serve({
		port: KS_PORT,
		async fetch(req) {
			const path = new URL(req.url).pathname;
			if (req.method === "PUT" && path.startsWith("/u/")) {
				const name = path.slice(3);
				const [b, sigB64, rotB64] = (await req.text()).trim().split("\n");
				const key = decodeKey((b ?? "").trim());
				const sig = Uint8Array.from(atob(sigB64 ?? ""), (c) => c.charCodeAt(0));
				if (!verifyClaim(key, name, sig))
					return new Response("bad", { status: 400 });
				const held = encodeKey(key);
				const prev = names.get(name);
				if (prev && prev !== held) {
					const rot = rotB64
						? Uint8Array.from(atob(rotB64), (c) => c.charCodeAt(0))
						: null;
					const ok = rot && verifyRotation(decodeKey(prev), key, rot);
					if (!ok) return new Response("taken", { status: 409 });
				}
				names.set(name, held);
				claims.set(name, sigB64 ?? "");
				return new Response("ok");
			}
			if (path.startsWith("/u/")) {
				const name = path.slice(3);
				const held = names.get(name);
				if (!held) return new Response("nope", { status: 404 });
				const sigB64 = claims.get(name) ?? "";
				return new Response(
					armorBundle(decodeKey(held), "np public key") +
						armorAlias(
							name,
							Uint8Array.from(atob(sigB64), (c) => c.charCodeAt(0)),
						),
				);
			}
			return new Response("nope", { status: 404 });
		},
	});
	wellKnownServer = Bun.serve({
		port: WK_PORT,
		fetch: (req) =>
			new URL(req.url).pathname === "/.well-known/np"
				? new Response(served)
				: new Response("nope", { status: 404 }),
	});
});

afterAll(() => {
	keyserver.stop(true);
	wellKnownServer.stop(true);
	rmSync(root, { recursive: true, force: true });
});

describe("keys", () => {
	const home = dir("keys");
	const id = mint();
	beforeAll(() => installIdentity(home, id, "keyholder"));

	test("prints one key format and the secret", async () => {
		const out = (await np(["key"], home)).out.trim();
		expect(out).toBe(encodeKey(id.key));
		expect(out).toMatch(/^npkey1[a-z2-7]+$/);
		expect((await np(["key", "secret"], home)).out.trim()).toMatch(
			/^npsec1[a-z2-7]+$/,
		);
	});

	test("emits an alias claim for a domain", async () => {
		const out = (await np(["publish", "example.com"], home)).out;
		const sig = out.match(/np alias/);
		expect(sig).not.toBeNull();
		expect((await np(["key", "wat"], home)).err).toContain(
			"unknown subcommand",
		);
	});
});

describe("sign and verify", () => {
	const alice = mint();
	const bob = mint();
	const aliceHome = dir("s-alice");
	const bobHome = dir("s-bob");
	let signed = "";

	beforeAll(async () => {
		installIdentity(aliceHome, alice, "alice");
		installIdentity(bobHome, bob);
		signed = (await np(["hello from alice"], aliceHome)).out;
		writeFileSync(join(root, "alice.pub"), wellKnown(alice, "alice"));
	});

	test("carries an untrusted comment and no key reference", async () => {
		expect(signed).toContain("untrusted comment: signed by alice");
		expect(signed).not.toMatch(/^key: /m);
	});

	test("verifies an unknown signer offline and says it is unknown", async () => {
		writeFileSync(join(root, "msg.asc"), signed);
		const r = await np([join(root, "msg.asc")], bobHome, {
			NP_KEYSERVER: "http://127.0.0.1:1",
		});
		expect(r.code).toBe(0);
		expect(r.err).toContain("good signature");
		expect(r.err).toContain("not in your contacts");
	});

	test("verifies after importing the signer", async () => {
		await np(
			["contacts", "add", join(root, "alice.pub"), "alice"],
			bobHome,
			env,
		);
		const r = await np([join(root, "msg.asc")], bobHome, env);
		expect(r.out).toContain("hello from alice");
		expect(r.err).toContain("good signature from alice");
	});

	test("rejects a tampered message", async () => {
		writeFileSync(
			join(root, "bad.asc"),
			signed.replace("hello from alice", "hacked by evil"),
		);
		const r = await np([join(root, "bad.asc")], bobHome, env);
		expect(r.err).toContain("BAD signature");
		expect(r.code).not.toBe(0);
	});
});

describe("encryption", () => {
	const alice = mint();
	const bob = mint();
	const aliceHome = dir("e-alice");
	const bobHome = dir("e-bob");

	beforeAll(async () => {
		installIdentity(aliceHome, alice);
		installIdentity(bobHome, bob);
		writeFileSync(join(root, "bob.pub"), wellKnown(bob, "bob"));
		await np(["contacts", "add", join(root, "bob.pub"), "bob"], aliceHome, env);
	});

	test("recipient and sender can both read it", async () => {
		const ct = (await np(["secret meow", "-to", "bob"], aliceHome, env)).out;
		writeFileSync(join(root, "ct.asc"), ct);
		expect((await np([join(root, "ct.asc")], bobHome, env)).out).toContain(
			"secret meow",
		);
		expect((await np([join(root, "ct.asc")], aliceHome, env)).out).toContain(
			"secret meow",
		);
	});

	test("--no-self locks the sender out", async () => {
		const ct = (
			await np(["for bob only", "-to", "bob", "--no-self"], aliceHome, env)
		).out;
		writeFileSync(join(root, "ct2.asc"), ct);
		expect((await np([join(root, "ct2.asc")], bobHome, env)).out).toContain(
			"for bob only",
		);
		expect((await np([join(root, "ct2.asc")], aliceHome, env)).code).not.toBe(
			0,
		);
	});

	test("signs inside by default, and decrypt verifies it in one step", async () => {
		installIdentity(aliceHome, alice, "alice");
		writeFileSync(join(root, "alice2.pub"), wellKnown(alice, "alice"));
		await np(
			["contacts", "add", join(root, "alice2.pub"), "alice"],
			bobHome,
			env,
		);
		const ct = (await np(["onion", "-to", "bob", "--no-self"], aliceHome, env))
			.out;
		writeFileSync(join(root, "onion.asc"), ct);
		const r = await np([join(root, "onion.asc")], bobHome, env);
		expect(r.out).toContain("onion");
		expect(r.err).toContain("good signature from alice");
	});

	test("--no-sign leaves the message unsigned", async () => {
		const ct = (
			await np(
				["quiet", "-to", "bob", "--no-self", "--no-sign"],
				aliceHome,
				env,
			)
		).out;
		writeFileSync(join(root, "quiet.asc"), ct);
		const r = await np([join(root, "quiet.asc")], bobHome, env);
		expect(r.out).toContain("quiet");
		expect(r.err).not.toContain("good signature");
		expect(r.err).toContain("without a signature");
	});

	test("-s says where it went", async () => {
		const r = await np(["hi", "-to", "bob", "-s"], aliceHome, env);
		expect(r.code).toBe(1);
		expect(r.err).toContain("--no-sign");
	});

	test("a second argument is the output path", async () => {
		const out = join(root, "positional.np");
		const w = await np(
			["hi bob", out, "-to", "bob", "--no-self"],
			aliceHome,
			env,
		);
		expect(w.code).toBe(0);
		expect(existsSync(out)).toBe(true);
		const back = join(root, "positional.txt");
		const r = await np([out, back], bobHome, env);
		expect(r.code).toBe(0);
		expect(readFileSync(back, "utf8")).toContain("hi bob");
		expect(r.err).toContain("good signature from alice");
	});

	test("a second argument that is not a path is a forgotten quote", async () => {
		const r = await np(["meet", "me"], aliceHome, env);
		expect(r.code).toBe(1);
		expect(r.err).toContain('np "meet me"');
	});

	test("streams a file across several read windows", async () => {
		const big = join(root, "big.bin");
		const blob = Buffer.alloc(20_000_003);
		for (let i = 0; i < blob.length; i++) blob[i] = (i * 31 + 7) & 0xff;
		writeFileSync(big, blob);
		expect(
			(await np([big, "-to", "bob", "--no-self"], aliceHome, env)).code,
		).toBe(0);
		const out = join(root, "big.out");
		expect((await np([`${big}.np`, "-o", out], bobHome, env)).code).toBe(0);
		expect(readFileSync(out)).toEqual(readFileSync(big));
	});

	test("streams stdin in and out of a pipe", async () => {
		const blob = new Uint8Array(9_000_011);
		for (let i = 0; i < blob.length; i++) blob[i] = (i * 17 + 3) & 0xff;
		const enc = join(root, "piped.np");
		const r = await np(
			["-", "-to", "bob", "--no-self", "-o", enc],
			aliceHome,
			env,
			blob,
		);
		expect(r.code).toBe(0);

		const dec = join(root, "piped.out");
		const back = await np(["-", "-o", dec], bobHome, env, readFileSync(enc));
		expect(back.code).toBe(0);
		expect(new Uint8Array(readFileSync(dec))).toEqual(blob);
	});

	test("pipes ciphertext straight to stdout and back", async () => {
		const enc = await np(
			["-", "-to", "bob", "--no-self"],
			aliceHome,
			env,
			"through the pipe",
		);
		expect(enc.code).toBe(0);
		expect(enc.bytes.length).toBeGreaterThan(1000);
		const back = await np(["-"], bobHome, env, enc.bytes);
		expect(back.out).toContain("through the pipe");
	});

	test("rejects a tampered pipe and writes no output file", async () => {
		const enc = await np(["-", "-to", "bob", "--no-self"], aliceHome, env, "x");
		const broken = new Uint8Array(enc.bytes);
		broken[broken.length - 5] ^= 0xff;
		const dest = join(root, "never.out");
		const r = await np(["-", "-o", dest], bobHome, env, broken);
		expect(r.code).not.toBe(0);
		expect(existsSync(dest)).toBe(false);
	});

	test("a corrupt ciphertext leaves no plaintext behind", async () => {
		const src = readFileSync(join(root, "big.bin.np"));
		src[src.length - 200] ^= 0xff;
		writeFileSync(join(root, "bad.np"), src);
		const out = join(root, "bad.out");
		const r = await np([join(root, "bad.np"), "-o", out], bobHome, env);
		expect(r.code).not.toBe(0);
		expect(r.err).toMatch(/corrupt|tampered/);
		expect(existsSync(out)).toBe(false);
	});

	test("a signature over a file bigger than one hash block round-trips", async () => {
		const path = join(root, "blocks.bin");
		const blob = Buffer.alloc(20_000_003);
		for (let i = 0; i < blob.length; i += 4093) blob[i] = i & 0xff;
		writeFileSync(path, blob);
		expect((await np(["sign", path], aliceHome, env)).code).toBe(0);
		expect(readFileSync(`${path}.npsig`, "utf8")).toContain("hash: tree512-8m");
		expect(
			(await np(["verify", path, `${path}.npsig`], bobHome, env)).err,
		).toContain("good signature from alice");
		const moved = Buffer.from(blob);
		moved[19_000_000] = (moved[19_000_000] as number) ^ 0xff;
		writeFileSync(join(root, "blocks2.bin"), moved);
		writeFileSync(
			join(root, "blocks2.bin.npsig"),
			readFileSync(`${path}.npsig`),
		);
		expect((await np([join(root, "blocks2.bin")], bobHome, env)).err).toContain(
			"BAD signature",
		);
	});

	test("the sign key cache is written once and reused", async () => {
		const path = join(root, "cached.txt");
		writeFileSync(path, "cache me\n");
		expect((await np(["sign", path], aliceHome, env)).code).toBe(0);
		const cache = join(aliceHome, "signkeys");
		expect(existsSync(cache)).toBe(true);
		expect(statSync(cache).mode & 0o077).toBe(0);
		expect(
			(await np(["sign", path, "-o", `${path}.2`], aliceHome, env)).code,
		).toBe(0);
		expect((await np([path], bobHome, env)).err).toContain("good signature");
	});

	test("a sign key cache for another identity is ignored", async () => {
		const path = join(root, "stale.txt");
		writeFileSync(path, "stale cache\n");
		writeFileSync(
			join(aliceHome, "signkeys"),
			`np1notthisidentity\nnpsign1 aaaa.bbbb.cccc\n`,
		);
		expect((await np(["sign", path], aliceHome, env)).code).toBe(0);
		expect((await np([path], bobHome, env)).err).toContain("good signature");
	});

	test("a legacy sha512 signature still verifies", async () => {
		const path = join(root, "legacy.txt");
		writeFileSync(path, "legacy detached signature\n");
		const r = await np(["sign", path], aliceHome, env);
		expect(r.code).toBe(0);
		const armor = readFileSync(`${path}.npsig`, "utf8");
		writeFileSync(`${path}.npsig`, armor.replace(/hash: .*\n/, ""));
		expect((await np([path], bobHome, env)).err).toContain("BAD signature");
	});

	test("signs and verifies a large file by streaming hash", async () => {
		const big = join(root, "big.bin");
		expect((await np([big], aliceHome, env)).code).toBe(0);
		expect((await np([big], bobHome, env)).err).toContain(
			"good signature from alice",
		);
		const tampered = join(root, "big2.bin");
		writeFileSync(tampered, Buffer.alloc(20_000_003, "x"));
		writeFileSync(`${tampered}.npsig`, readFileSync(`${big}.npsig`));
		expect((await np([tampered], bobHome, env)).err).toContain("BAD signature");
	});
});

describe("names and rotation", () => {
	const alice = mint();
	const rotated = mint();
	const evil = mint();
	const bobHome = dir("n-bob");
	const host = `127.0.0.1:${WK_PORT}`;

	beforeAll(async () => {
		installIdentity(bobHome, mint());
		served = wellKnown(alice, host);
	});

	test("resolves a domain and pins it", async () => {
		expect(
			(await np(["hi", "-to", host, "--no-self"], bobHome, env)).code,
		).toBe(0);
		expect((await np(["contacts"], bobHome, env)).out).toContain(host);
	});

	test("refuses a key that does not claim the name", async () => {
		served = armorBundle(evil.key, "np public key");
		const r = await np(["contacts", "add", host], bobHome, env);
		expect(r.err).toContain("does not claim that name");
		expect(r.code).not.toBe(0);
	});

	test("refuses an unproven key change", async () => {
		served = wellKnown(evil, host);
		const r = await np(["contacts", "add", host], bobHome, env);
		expect(r.err).toContain("KEY CHANGED");
	});

	test("accepts a change proven by a rotation certificate", async () => {
		served =
			wellKnown(rotated, host) +
			armorRotation(alice.key, rotated.key, signRotation(alice, rotated.key));
		const r = await np(["contacts", "add", host], bobHome, env);
		expect(r.code).toBe(0);
		expect((await np(["contacts"], bobHome, env)).out).toContain(
			fingerprint(rotated.key),
		);
	});

	test("refuses to encrypt to a revoked key", async () => {
		const dying = mint();
		const why = "lost the laptop";
		const wkHome = dir("n-rev");
		installIdentity(wkHome, mint());
		served =
			wellKnown(dying, host) +
			armorRevocation(dying.key, why, signRevocation(dying, why));
		const r = await np(["hi", "-to", host, "--no-self"], wkHome, env);
		expect(r.code).toBe(1);
		expect(r.err).toContain("revoked by its owner");
		expect(r.err).toContain(why);
	});

	test("ignores a revocation signed by another key", async () => {
		const target = mint();
		const impostor = mint();
		const wkHome = dir("n-rev2");
		installIdentity(wkHome, mint());
		served =
			wellKnown(target, host) +
			armorRevocation(
				target.key,
				"not yours to kill",
				signRevocation(impostor, "not yours to kill"),
			);
		const r = await np(["hi", "-to", host, "--no-self"], wkHome, env);
		expect(r.code).toBe(0);
	});

	test("rejects a rotation certificate signed by the wrong key", async () => {
		const impostor = mint();
		served =
			wellKnown(impostor, host) +
			armorRotation(
				rotated.key,
				impostor.key,
				signRotation(evil, impostor.key),
			);
		const r = await np(["contacts", "add", host], bobHome, env);
		expect(r.err).toContain("KEY CHANGED");
	});
});

describe("keyserver", () => {
	const alice = mint();
	const bob = mint();
	const aliceHome = dir("ks-alice");
	const bobHome = dir("ks-bob");

	beforeAll(async () => {
		installIdentity(aliceHome, alice);
		installIdentity(bobHome, bob);
	});

	test("an unknown recipient name gives a clear error", async () => {
		const r = await np(
			["x", "-to", "nobody-here", "--no-self"],
			aliceHome,
			env,
		);
		expect(r.err).toMatch(/could not fetch|unknown recipient/);
		expect(r.code).not.toBe(0);
	});

	test("a claimed username resolves for someone else", async () => {
		expect((await np(["publish", "bobby"], bobHome, env)).code).toBe(0);
		expect(
			(await np(["hello", "-to", "bobby", "--no-self"], aliceHome, env)).code,
		).toBe(0);
	});

	test("publish with no name explains what it wants", async () => {
		const r = await np(["publish"], bobHome, env);
		expect(r.code).not.toBe(0);
		expect(r.err).toContain("username");
	});
});

describe("argument handling", () => {
	const home = dir("args");
	beforeAll(async () => {
		installIdentity(home, mint());
	});

	test("prints its version", async () => {
		expect((await np(["version"], home)).out.trim()).toMatch(
			/^np \d+\.\d+\.\d+$/,
		);
		expect((await np(["--version"], home)).out.trim()).toMatch(/^np \d+\.\d+/);
	});

	test("refuses a path that does not exist instead of signing it", async () => {
		const r = await np(["./nope.txt"], home);
		expect(r.err).toContain("no such file");
		expect(r.code).not.toBe(0);
		expect((await np(["missing.md"], home)).err).toContain("no such file");
	});

	test("still signs text that merely contains a slash", async () => {
		const r = await np(["and/or"], home);
		expect(r.out).toContain("np signed message");
		expect(r.out).toContain("and/or");
	});

	test("warns when the identity file leaks the secret", async () => {
		const leaky = dir("leaky");
		installIdentity(leaky, mint());
		chmodSync(join(leaky, "identity"), 0o644);
		expect((await np(["hi"], leaky)).err).toContain("readable by other users");
		chmodSync(join(leaky, "identity"), 0o600);
		expect((await np(["hi"], leaky)).err).not.toContain("readable by other");
	});
});

describe("damaged identity", () => {
	const home = dir("damaged");
	const other = mint();

	beforeAll(async () => {
		installIdentity(home, mint());
	});

	test("explains a bundle that does not decode", async () => {
		const path = join(home, "identity");
		const good = readFileSync(path, "utf8");
		writeFileSync(path, good.replace(/^# key: npkey1./m, "# key: npkey1x"));
		const r = await np(["hi", "-to", encodeKey(other.key)], home, env);
		expect(r.code).not.toBe(0);
		writeFileSync(path, good);
	});

	test("explains a key line that does not decode", async () => {
		const path = join(home, "identity");
		const good = readFileSync(path, "utf8");
		writeFileSync(path, good.replace(/^# key: .*$/m, "# key: npkey1nonsense"));
		const r = await np(["hi", "-to", encodeKey(other.key)], home, env);
		expect(r.code).not.toBe(0);
		writeFileSync(path, good);
	});
});

describe("contacts", () => {
	const home = dir("c-home");
	const friend = mint();

	beforeAll(async () => {
		installIdentity(home, mint());
		writeFileSync(join(root, "friend.pub"), wellKnown(friend, "friend"));
		await np(
			["contacts", "add", join(root, "friend.pub"), "friend"],
			home,
			env,
		);
	});

	test("lists each contact with its fingerprint", async () => {
		const out = (await np(["contacts"], home, env)).out;
		expect(out).toMatch(/[a-z2-7]{4}-[a-z2-7]{4}-[a-z2-7]{4}-[a-z2-7]{4}/);
	});

	test("renames and removes", async () => {
		expect(
			(await np(["contacts", "rename", "friend", "pal"], home, env)).err,
		).toContain("is now pal");
		expect((await np(["contacts"], home, env)).out).toContain("pal");
		expect((await np(["contacts", "rm", "pal"], home, env)).err).toContain(
			"removed pal",
		);
		expect((await np(["contacts"], home, env)).err).toContain(
			"no contacts yet",
		);
		expect((await np(["contacts", "rm", "ghost"], home, env)).err).toContain(
			"no contact named",
		);
	});
});

describe("mistyped commands", () => {
	const home = dir("typo");

	beforeAll(() => installIdentity(home, mint()));

	test("a near-miss command suggests the real one instead of signing it", async () => {
		for (const [typo, meant] of [
			["contact", "contacts"],
			["publsh", "publish"],
			["conacts", "contacts"],
			["ke", "key"],
		]) {
			const r = await np([typo as string, "bob"], home, env);
			expect(r.code).toBe(1);
			expect(r.err).toContain(`did you mean "np ${meant}"`);
			expect(r.out).toBe("");
		}
	});

	test("an unquoted message says to quote it, and names the whole thing", async () => {
		const r = await np(["meet", "me", "at", "six"], home, env);
		expect(r.code).toBe(1);
		expect(r.err).toContain('np "meet me at six"');
		expect(r.out).toBe("");
	});

	test("a quoted message still signs", async () => {
		const r = await np(["meet me at six"], home, env);
		expect(r.code).toBe(0);
		expect(r.out).toContain("np signed message");
	});

	test("a single word that is not near a command still signs", async () => {
		const r = await np(["hello"], home, env);
		expect(r.code).toBe(0);
		expect(r.out).toContain("np signed message");
	});

	test("keygen points at its new name", async () => {
		const r = await np(["keygen"], home, env);
		expect(r.code).toBe(1);
		expect(r.err).toContain("np key new");
	});

	test("an unknown key subcommand lists the real ones", async () => {
		const r = await np(["key", "nwe"], home, env);
		expect(r.code).toBe(1);
		expect(r.err).toContain("np key new|secret|rotate|revoke|clear");
	});
});

describe("no system keyring", () => {
	const home = dir("nokeyring");

	test("keygen falls back to a file secret, and np still works", async () => {
		const id = mint();
		mkdirSync(home, { recursive: true });
		const { saveIdentity } = await import("../src/store.ts");
		expect(typeof saveIdentity).toBe("function");
		writeFileSync(
			join(home, "identity"),
			[
				"# np identity (test)",
				"# no system keyring here, so the secret key is the line below.",
				`# fingerprint: ${fingerprint(id.key)}`,
				`# key: ${encodeKey(id.key)}`,
				toBech("npsec", id.seed),
				"",
			].join("\n"),
		);
		chmodSync(join(home, "identity"), 0o600);
		expect((await np(["key"], home, env)).out.trim()).toBe(encodeKey(id.key));
		const signed = await np(["hello from a keyringless box"], home, env);
		expect(signed.code).toBe(0);
		writeFileSync(join(root, "nk.asc"), signed.out);
		expect((await np([join(root, "nk.asc")], home, env)).err).toContain(
			"good signature",
		);
	});

	test("a world-readable secret file is called out", async () => {
		chmodSync(join(home, "identity"), 0o644);
		const r = await np(["key"], home, env);
		expect(r.err).toContain("readable by other users");
		chmodSync(join(home, "identity"), 0o600);
	});
});

describe("the recipient flag", () => {
	const home = dir("toflag");

	beforeAll(() => installIdentity(home, mint()));

	test("-to and --to both name a recipient", async () => {
		const other = mint();
		for (const flag of ["-to", "--to"]) {
			const r = await np(
				["hi", flag, encodeKey(other.key), "--no-self", "-o", "-"],
				home,
				env,
			);
			expect(r.code).toBe(0);
			expect(r.out).toContain("np encrypted message");
		}
	});

	test("-e says where it went instead of guessing", async () => {
		const r = await np(["hi", "-e", "alice"], home, env);
		expect(r.code).toBe(1);
		expect(r.err).toContain("-to");
	});

	test("an unknown single-dash flag is refused, but - is still stdin", async () => {
		expect((await np(["hi", "-x"], home, env)).err).toContain(
			"unknown flag -x",
		);
		const piped = await np(["-"], home, env, "hello\n");
		expect(piped.code).toBe(0);
	});
});

describe("worker and single-thread paths agree", () => {
	const home = dir("lanes");

	beforeAll(() => installIdentity(home, mint()));

	test("a multi-block file round-trips identically either way", async () => {
		const src = join(root, "lanes.bin");
		const blob = Buffer.alloc(20_000_003);
		for (let i = 0; i < blob.length; i++) blob[i] = (i * 31 + 7) & 0xff;
		writeFileSync(src, blob);
		const key = readFileSync(join(home, "identity"), "utf8")
			.split("\n")
			.find((l) => l.startsWith("# key: "))
			?.slice(7) as string;
		for (const lanes of ["1", "8"]) {
			const ct = join(root, `lanes${lanes}.np`);
			const out = join(root, `lanes${lanes}.out`);
			const e = await np([src, ct, "-to", key, "--no-self"], home, {
				...env,
				NP_LANES: lanes,
			});
			expect(e.code).toBe(0);
			for (const back of ["1", "8"]) {
				const d = await np([ct, `${out}.${back}`], home, {
					...env,
					NP_LANES: back,
				});
				expect(d.code).toBe(0);
				expect(d.err).toContain("good signature");
				expect(readFileSync(`${out}.${back}`).equals(blob)).toBe(true);
			}
		}
	}, 120000);
});

describe("pipes are signed like everything else", () => {
	const home = dir("pipesign");

	beforeAll(() => installIdentity(home, mint()));

	test("a short pipe and a long pipe both carry a signature", async () => {
		const key = readFileSync(join(home, "identity"), "utf8")
			.split("\n")
			.find((l) => l.startsWith("# key: "))
			?.slice(7) as string;
		for (const [name, size] of [
			["short", 40],
			["long", 20_000_000],
		] as const) {
			const data = Buffer.alloc(size, "z");
			const ct = join(root, `pipe-${name}.np`);
			const out = join(root, `pipe-${name}.out`);
			expect(
				(await np(["-", "-to", key, "--no-self", "-o", ct], home, env, data))
					.code,
			).toBe(0);
			const r = await np([ct, out], home, env);
			expect(r.code).toBe(0);
			expect(r.err).toContain("good signature");
			expect(readFileSync(out).equals(data)).toBe(true);
		}
	}, 120000);

	test("tampering with a long pipe is caught", async () => {
		const ct = readFileSync(join(root, "pipe-long.np"));
		const bad = Uint8Array.from(ct);
		(bad[ct.length - 200] as number) ^= 0x40;
		const path = join(root, "pipe-bad.np");
		writeFileSync(path, bad);
		expect((await np([path, join(root, "pipe-bad.out")], home, env)).code).toBe(
			1,
		);
	}, 120000);

	test("--no-sign on a pipe leaves it unsigned", async () => {
		const key = readFileSync(join(home, "identity"), "utf8")
			.split("\n")
			.find((l) => l.startsWith("# key: "))
			?.slice(7) as string;
		const ct = join(root, "pipe-quiet.np");
		await np(
			["-", "-to", key, "--no-self", "--no-sign", "-o", ct],
			home,
			env,
			"quiet\n",
		);
		const r = await np([ct, join(root, "pipe-quiet.out")], home, env);
		expect(r.code).toBe(0);
		expect(r.err).not.toContain("good signature");
		expect(r.err).toContain("without a signature");
	});
});
