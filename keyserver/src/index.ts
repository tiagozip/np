import {
	armorAlias,
	armorBundle,
	armorRevocation,
	decodeKey,
	encodeKey,
	fingerprint,
	verifyClaim,
	verifyRevocation,
	verifyRotation,
} from "../../src/core.ts";

const USERNAME_RE = /^[a-z0-9][a-z0-9-]{1,31}$/;

type Env = {
	DB: D1Database;
	PUT_LIMITER: { limit(opts: { key: string }): Promise<{ success: boolean }> };
};

const text = (
	body: string,
	status = 200,
	headers: Record<string, string> = {},
) =>
	new Response(body, {
		status,
		headers: {
			"content-type": "text/plain; charset=utf-8",
			"x-content-type-options": "nosniff",
			...headers,
		},
	});

const SHORT_CACHE = { "cache-control": "public, max-age=60" };

const cleanReason = (reason: string) =>
	[...reason]
		.map((c) => (c.charCodeAt(0) < 0x20 || c.charCodeAt(0) === 0x7f ? " " : c))
		.join("")
		.trim()
		.slice(0, 200);

const isRevoked = async (env: Env, key: Uint8Array) =>
	!!(await env.DB.prepare("SELECT fp FROM revocations WHERE fp = ?")
		.bind(fingerprint(key))
		.first());

const unb64 = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const b64 = (b: Uint8Array) => Buffer.from(b).toString("base64");

const HELP = `np keyserver (np.tiago.zip)

GET  /u/<name>   the key that claims <name>
PUT  /u/<name>   claim a name (body: npkey1...\\n<base64 claim sig>\\n[rotation sig])
PUT  /revoke     retire a key for good (body: npkey1...\\n<base64 sig>\\n<reason>)

names are first-come, and only the holding key can update one. a key that
proves a signed rotation from the pinned key can take the name over.
np, and this server's source: https://github.com/tiagozip/np
`;

async function revocationFor(env: Env, key: Uint8Array) {
	const row = await env.DB.prepare(
		"SELECT reason, sig FROM revocations WHERE fp = ?",
	)
		.bind(fingerprint(key))
		.first<{ reason: string; sig: string }>();
	return row ? armorRevocation(key, row.reason, unb64(row.sig)) : "";
}

export default {
	async fetch(req: Request, env: Env): Promise<Response> {
		const path = new URL(req.url).pathname;
		const limited = async () =>
			!(
				await env.PUT_LIMITER.limit({
					key: req.headers.get("cf-connecting-ip") ?? "unknown",
				})
			).success;

		if (req.method === "PUT" && path === "/revoke") {
			if (await limited())
				return text("too many requests", 429, { "retry-after": "10" });
			const body = await req.text();
			if (body.length > 16384) return text("too big", 413);
			const [keyStr, sigB64, ...rest] = body.split("\n");
			const reason = rest.join(" ");
			if (reason !== cleanReason(reason))
				return text("reason must be plain text of at most 200 characters", 400);
			let key: Uint8Array;
			let sig: Uint8Array;
			try {
				key = decodeKey((keyStr ?? "").trim());
				sig = unb64((sigB64 ?? "").trim());
			} catch {
				return text("invalid revocation body", 400);
			}
			if (!verifyRevocation(key, reason, sig))
				return text("bad revocation signature", 400);
			await env.DB.prepare(
				"INSERT INTO revocations (fp, reason, sig) VALUES (?, ?, ?) ON CONFLICT(fp) DO NOTHING",
			)
				.bind(fingerprint(key), reason, b64(sig))
				.run();
			return text("revoked");
		}

		if (req.method === "PUT" && path.startsWith("/u/")) {
			if (await limited())
				return text("too many requests", 429, { "retry-after": "10" });
			const name = path.slice(3).toLowerCase();
			if (!USERNAME_RE.test(name)) return text("invalid username", 400);
			const body = await req.text();
			if (body.length > 16384) return text("too big", 413);
			const [keyStr, sigB64, rotB64] = body.trim().split("\n");
			let key: Uint8Array;
			let sig: Uint8Array;
			let rotation: Uint8Array | null;
			try {
				key = decodeKey((keyStr ?? "").trim());
				sig = unb64((sigB64 ?? "").trim());
				rotation = rotB64?.trim() ? unb64(rotB64.trim()) : null;
			} catch {
				return text("invalid claim body", 400);
			}
			if (!verifyClaim(key, name, sig)) return text("bad claim signature", 400);
			if (await isRevoked(env, key)) return text("that key is revoked", 403);
			const held = encodeKey(key);
			const existing = await env.DB.prepare(
				"SELECT key FROM names WHERE name = ?",
			)
				.bind(name)
				.first<{ key: string }>();
			if (existing && existing.key !== held) {
				const previous = decodeKey(existing.key);
				if (await isRevoked(env, previous))
					return text("the key holding that name is revoked", 403);
				if (!rotation || !verifyRotation(previous, key, rotation))
					return text("name taken", 409);
			}
			if (!existing) {
				const ip = req.headers.get("cf-connecting-ip") ?? "unknown";
				const day = Math.floor(Date.now() / 86400000);
				const taken = await env.DB.prepare(
					"INSERT INTO claim_rate (ip, day, count) VALUES (?, ?, 1) ON CONFLICT(ip, day) DO UPDATE SET count = count + 1 WHERE count < 5 RETURNING count",
				)
					.bind(ip, day)
					.first<{ count: number }>();
				if (!taken) return text("too many new names today, try tomorrow", 429);
			}
			await env.DB.prepare(
				"INSERT INTO names (name, key, sig) VALUES (?, ?, ?) ON CONFLICT(name) DO UPDATE SET key = excluded.key, sig = excluded.sig",
			)
				.bind(name, held, b64(sig))
				.run();
			return text(fingerprint(key));
		}

		if (req.method === "GET" && path.startsWith("/u/")) {
			const name = path.slice(3).toLowerCase();
			if (!USERNAME_RE.test(name)) return text("invalid username", 400);
			const row = await env.DB.prepare(
				"SELECT key, sig FROM names WHERE name = ?",
			)
				.bind(name)
				.first<{ key: string; sig: string | null }>();
			if (!row) return text("not found", 404);
			const key = decodeKey(row.key);
			return text(
				armorBundle(key, `np public key of ${name}`) +
					(row.sig ? armorAlias(name, unb64(row.sig)) : "") +
					(await revocationFor(env, key)),
				200,
				SHORT_CACHE,
			);
		}

		if (req.method === "GET" && path === "/") return text(HELP);
		return text("nope", 404);
	},
};
