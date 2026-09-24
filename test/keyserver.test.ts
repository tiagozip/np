import { Database } from "bun:sqlite";
import { beforeEach, describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import worker from "../keyserver/src/index.ts";
import {
	armorBundle,
	encodeKey,
	extractBundleString,
	parseAliases,
	parseRevocations,
	signClaim,
	signRevocation,
	signRotation,
	verifyClaim,
	verifyRevocation,
} from "../src/core.ts";
import { mint } from "./helpers.ts";

const schema = readFileSync(
	join(import.meta.dir, "../keyserver/schema.sql"),
	"utf8",
);

let db: Database;
let allowed = true;

const env = {
	DB: {
		prepare: (sql: string) => ({
			bind: (...args: unknown[]) => ({
				first: async () => db.query(sql).get(...(args as never[])) ?? null,
				run: async () => db.query(sql).run(...(args as never[])),
			}),
		}),
		batch: async (stmts: { run: () => Promise<unknown> }[]) => {
			for (const s of stmts) await s.run();
		},
	},
	PUT_LIMITER: { limit: async () => ({ success: allowed }) },
} as never;

const call = (method: string, path: string, body?: string, ip = "10.0.0.1") =>
	worker.fetch(
		new Request(`https://np.example${path}`, {
			method,
			body,
			headers: { "cf-connecting-ip": ip },
		}),
		env,
	);

const claimBody = (
	id: ReturnType<typeof mint>,
	name: string,
	rotation?: Uint8Array,
) =>
	[
		encodeKey(id.key),
		Buffer.from(signClaim(id, name)).toString("base64"),
		...(rotation ? [Buffer.from(rotation).toString("base64")] : []),
	].join("\n");

beforeEach(() => {
	db = new Database(":memory:");
	db.run(schema);
	allowed = true;
});

describe("serving names", () => {
	test("serves a claimed name with cache headers", async () => {
		const id = mint();
		await call("PUT", "/u/meow", claimBody(id, "meow"));
		const got = await call("GET", "/u/meow");
		expect(got.status).toBe(200);
		expect(got.headers.get("cache-control")).toContain("max-age=60");
		expect(extractBundleString(await got.text())).toBe(encodeKey(id.key));
	});

	test("has no content-addressed route left", async () => {
		const id = mint();
		await call("PUT", "/u/meow", claimBody(id, "meow"));
		expect((await call("GET", `/${encodeKey(id.key)}`)).status).toBe(404);
		expect((await call("PUT", "/", encodeKey(id.key))).status).toBe(404);
	});

	test("rejects garbage and oversized bodies", async () => {
		expect((await call("PUT", "/u/meow", "npkey1nonsense")).status).toBe(400);
		expect((await call("PUT", "/u/meow", "x".repeat(20000))).status).toBe(413);
	});

	test("honours the rate limiter", async () => {
		allowed = false;
		const res = await call("PUT", "/u/meow", claimBody(mint(), "meow"));
		expect(res.status).toBe(429);
		expect(res.headers.get("retry-after")).toBe("10");
	});
});

describe("claiming a username", () => {
	test("stores the claim and serves key plus alias", async () => {
		const id = mint();
		expect((await call("PUT", "/u/meow", claimBody(id, "meow"))).status).toBe(
			200,
		);
		const res = await call("GET", "/u/meow");
		const body = await res.text();
		expect(extractBundleString(body)).toBe(encodeKey(id.key));
		const [alias] = parseAliases(body);
		expect(alias?.name).toBe("meow");
		expect(verifyClaim(id.key, "meow", alias.sig)).toBe(true);
	});

	test("refuses a signature that does not cover the name", async () => {
		const id = mint();
		const body = [
			encodeKey(id.key),
			Buffer.from(signClaim(id, "other")).toString("base64"),
		].join("\n");
		expect((await call("PUT", "/u/meow", body)).status).toBe(400);
	});

	test("refuses invalid names and malformed bodies", async () => {
		const id = mint();
		expect((await call("PUT", "/u/A", claimBody(id, "a"))).status).toBe(400);
		expect((await call("PUT", "/u/has.dot", claimBody(id, "x"))).status).toBe(
			400,
		);
		expect((await call("PUT", "/u/meow", "not-a-bundle")).status).toBe(400);
		expect((await call("GET", "/u/never-claimed")).status).toBe(404);
	});

	test("is idempotent for the holder", async () => {
		const id = mint();
		await call("PUT", "/u/meow", claimBody(id, "meow"));
		expect((await call("PUT", "/u/meow", claimBody(id, "meow"))).status).toBe(
			200,
		);
	});
});

describe("name takeover", () => {
	test("blocks a different key with no certificate", async () => {
		const owner = mint();
		const thief = mint();
		await call("PUT", "/u/meow", claimBody(owner, "meow"));
		expect(
			(await call("PUT", "/u/meow", claimBody(thief, "meow"))).status,
		).toBe(409);
	});

	test("blocks a certificate signed by the wrong key", async () => {
		const owner = mint();
		const next = mint();
		const impostor = mint();
		await call("PUT", "/u/meow", claimBody(owner, "meow"));
		const forged = signRotation(impostor, next.key);
		expect(
			(await call("PUT", "/u/meow", claimBody(next, "meow", forged))).status,
		).toBe(409);
	});

	test("blocks a certificate pointing at someone else", async () => {
		const owner = mint();
		const next = mint();
		const other = mint();
		await call("PUT", "/u/meow", claimBody(owner, "meow"));
		const wrongTarget = signRotation(owner, other.key);
		expect(
			(await call("PUT", "/u/meow", claimBody(next, "meow", wrongTarget)))
				.status,
		).toBe(409);
	});

	test("accepts the holder's own rotation and moves the name", async () => {
		const owner = mint();
		const next = mint();
		await call("PUT", "/u/meow", claimBody(owner, "meow"));
		const cert = signRotation(owner, next.key);
		expect(
			(await call("PUT", "/u/meow", claimBody(next, "meow", cert))).status,
		).toBe(200);
		const body = await (await call("GET", "/u/meow")).text();
		expect(extractBundleString(body)).toBe(encodeKey(next.key));
	});
});

describe("claim rate limit", () => {
	test("caps new names per ip per day but not updates", async () => {
		const id = mint();
		const codes: number[] = [];
		for (let i = 0; i < 7; i++)
			codes.push(
				(await call("PUT", `/u/name${i}`, claimBody(id, `name${i}`))).status,
			);
		expect(codes.filter((c) => c === 200).length).toBe(5);
		expect(codes.slice(5)).toEqual([429, 429]);

		const other = mint();
		expect(
			(await call("PUT", "/u/fresh", claimBody(other, "fresh"), "10.0.0.2"))
				.status,
		).toBe(200);
		expect(
			(await call("PUT", "/u/fresh", claimBody(other, "fresh"), "10.0.0.2"))
				.status,
		).toBe(200);
	}, 60000);
});

describe("revocation", () => {
	const revokeBody = (
		id: ReturnType<typeof mint>,
		reason: string,
		sig = signRevocation(id, reason),
	) =>
		[encodeKey(id.key), Buffer.from(sig).toString("base64"), reason].join("\n");

	test("takes a signed revocation and serves it with the key", async () => {
		const id = mint();
		await call("PUT", "/u/meow", claimBody(id, "meow"));
		expect(
			(await call("PUT", "/revoke", revokeBody(id, "stolen"))).status,
		).toBe(200);

		const body = await (await call("GET", "/u/meow")).text();
		const [rev] = parseRevocations(body);
		expect(rev?.key).toEqual(id.key);
		expect(rev?.reason).toBe("stolen");
		expect(verifyRevocation(id.key, "stolen", rev.sig)).toBe(true);
	}, 60000);

	test("refuses a forged or mismatched revocation", async () => {
		const id = mint();
		const impostor = mint();
		expect(
			(
				await call(
					"PUT",
					"/revoke",
					revokeBody(id, "nope", signRevocation(impostor, "nope")),
				)
			).status,
		).toBe(400);
		expect(
			(
				await call(
					"PUT",
					"/revoke",
					[
						encodeKey(impostor.key),
						Buffer.from(signRevocation(id, "nope")).toString("base64"),
						"nope",
					].join("\n"),
				)
			).status,
		).toBe(400);
		expect((await call("PUT", "/revoke", "garbage")).status).toBe(400);
	}, 60000);

	test("a reason cannot be swapped after the fact", async () => {
		const id = mint();
		const sig = signRevocation(id, "stolen");
		expect(
			(
				await call(
					"PUT",
					"/revoke",
					[
						encodeKey(id.key),
						Buffer.from(sig).toString("base64"),
						"actually fine, keep using it",
					].join("\n"),
				)
			).status,
		).toBe(400);
	}, 60000);

	test("honours the rate limiter", async () => {
		allowed = false;
		const id = mint();
		expect((await call("PUT", "/revoke", revokeBody(id, "x"))).status).toBe(
			429,
		);
	}, 60000);
});

describe("misc routes", () => {
	test("documents itself and 404s the rest", async () => {
		const root = await call("GET", "/");
		expect(await root.text()).toContain("np keyserver");
		expect((await call("GET", "/wat")).status).toBe(404);
		expect((await call("DELETE", "/u/meow")).status).toBe(404);
	});

	test("the served bundle is armored", async () => {
		const id = mint();
		await call("PUT", "/u/meow", claimBody(id, "meow"));
		const body = await (await call("GET", "/u/meow")).text();
		expect(body.startsWith(armorBundle(id.key).split("\n")[0] as string)).toBe(
			true,
		);
		for (const line of body.split("\n"))
			expect(line.length).toBeLessThanOrEqual(64);
	});
});

describe("revoked keys", () => {
	const revoke = (id: ReturnType<typeof mint>, reason: string) =>
		[
			encodeKey(id.key),
			Buffer.from(signRevocation(id, reason)).toString("base64"),
			reason,
		].join("\n");

	test("a revoked key cannot claim a name", async () => {
		const id = mint();
		await call("PUT", "/revoke", revoke(id, "stolen"));
		expect((await call("PUT", "/u/meow", claimBody(id, "meow"))).status).toBe(
			403,
		);
	}, 60000);

	test("a revoked key cannot hand its name to a rotation", async () => {
		const owner = mint();
		const thief = mint();
		await call("PUT", "/u/meow", claimBody(owner, "meow"));
		await call("PUT", "/revoke", revoke(owner, "laptop stolen"));
		const cert = signRotation(owner, thief.key);
		expect(
			(await call("PUT", "/u/meow", claimBody(thief, "meow", cert))).status,
		).toBe(403);
		const body = await (await call("GET", "/u/meow")).text();
		expect(extractBundleString(body)).toBe(encodeKey(owner.key));
	}, 60000);

	test("malformed rotation base64 is a 400, not a throw", async () => {
		const owner = mint();
		const next = mint();
		await call("PUT", "/u/meow", claimBody(owner, "meow"));
		const body = [
			encodeKey(next.key),
			Buffer.from(signClaim(next, "meow")).toString("base64"),
			"!!!not base64!!!",
		].join("\n");
		expect((await call("PUT", "/u/meow", body)).status).toBe(400);
	}, 60000);

	test("a reason with control characters or padding is refused", async () => {
		const id = mint();
		const nasty = `a${String.fromCharCode(13)}b${String.fromCharCode(0)}c`;
		expect((await call("PUT", "/revoke", revoke(id, nasty))).status).toBe(400);
		expect(
			(await call("PUT", "/revoke", revoke(id, "x".repeat(400)))).status,
		).toBe(400);
		expect(db.query("SELECT reason FROM revocations").get()).toBeNull();
		expect((await call("PUT", "/revoke", revoke(id, "stolen"))).status).toBe(
			200,
		);
	}, 60000);
});

describe("new name cap", () => {
	test("holds against a concurrent burst from one ip", async () => {
		const ids = Array.from({ length: 20 }, () => mint());
		const codes = await Promise.all(
			ids.map((id, i) =>
				call(
					"PUT",
					`/u/burst${i}`,
					claimBody(id, `burst${i}`),
					"10.9.9.9",
				).then((r) => r.status),
			),
		);
		expect(codes.filter((c) => c === 200).length).toBe(5);
	}, 60000);
});
