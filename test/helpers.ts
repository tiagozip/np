import { chmodSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { concatBytes, randomBytes } from "@noble/hashes/utils.js";
import {
	armorAlias,
	armorBundle,
	encodeKey,
	fingerprint,
	type Identity,
	identityFromSeed,
	signClaim,
	toBech,
} from "../src/core.ts";

export const mint = () =>
	identityFromSeed(
		concatBytes(
			randomBytes(32),
			randomBytes(32),
			randomBytes(2),
			randomBytes(8),
		),
	);

export function installIdentity(dir: string, id: Identity, handle?: string) {
	mkdirSync(dir, { recursive: true });
	writeFileSync(
		join(dir, "identity"),
		[
			"# np identity (test)",
			...(handle ? [`# handle: ${handle}`] : []),
			`# fingerprint: ${fingerprint(id.key)}`,
			`# key: ${encodeKey(id.key)}`,
			toBech("npsec", id.seed),
			"",
		].join("\n"),
	);
	chmodSync(join(dir, "identity"), 0o600);
	return dir;
}

export const wellKnown = (id: Identity, name: string, extra = "") =>
	armorBundle(id.key, `np public key of ${name}`) +
	armorAlias(name, signClaim(id, name)) +
	extra;

export async function np(
	args: string[],
	dir: string,
	env: Record<string, string> = {},
	stdin?: string | Uint8Array,
) {
	const proc = Bun.spawn(
		[process.execPath, "run", `${import.meta.dir}/../src/np.ts`, ...args],
		{
			env: { ...process.env, NP_CONFIG_DIR: dir, ...env },
			stdout: "pipe",
			stderr: "pipe",
			stdin: stdin === undefined ? "ignore" : Buffer.from(stdin as string),
		},
	);
	const [bytes, err] = await Promise.all([
		new Response(proc.stdout).bytes(),
		new Response(proc.stderr).text(),
	]);
	return {
		code: await proc.exited,
		out: new TextDecoder().decode(bytes),
		bytes,
		err,
	};
}
