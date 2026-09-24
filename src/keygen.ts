import { mkdirSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import * as p from "@clack/prompts";
import { concatBytes, randomBytes } from "@noble/hashes/utils.js";
import {
	armorAlias,
	armorBundle,
	encodeKey,
	extractBundleString,
	fingerprint,
	identityFromSeed,
	signClaim,
} from "./core.ts";
import {
	hasIdentity,
	httpBase,
	IDENTITY_PATH,
	KEYSERVER,
	publishName,
	saveIdentity,
	setHandle,
	USERNAME_RE,
} from "./store.ts";
import { bold, cyan, dim, LOGO, pink } from "./ui.ts";

const bail = (msg: string) => {
	p.cancel(msg);
	process.exit(1);
};

export async function keygenWizard() {
	console.log(`\n${LOGO}\n`);
	p.intro(bold(pink("keygen")));

	if (hasIdentity()) {
		const sure = await p.confirm({
			message: `an identity already exists at ${IDENTITY_PATH}. replace it?`,
			initialValue: false,
		});
		if (p.isCancel(sure) || !sure) bail("keeping existing identity");
	}

	const id = identityFromSeed(
		concatBytes(
			randomBytes(32),
			randomBytes(32),
			randomBytes(2),
			randomBytes(8),
		),
	);
	p.log.success(`minted ${dim(fingerprint(id.key))}`);

	const reachable = await fetch(KEYSERVER)
		.then((r) => r.ok)
		.catch(() => false);

	const mode = await p.select({
		message: "how should people reach you?",
		options: [
			...(reachable
				? [
						{
							value: "name",
							label: "username on np.tiago.zip",
							hint: "-to meow",
						},
					]
				: []),
			{ value: "domain", label: "a domain i own", hint: "-to tiago.zip" },
			{
				value: "skip",
				label: `a raw ~${Math.round(armorBundle(id.key).length / 1024)}kb key`,
				hint: "np key prints it",
			},
		],
	});
	if (p.isCancel(mode)) bail("cancelled, nothing saved");

	let username = "";
	if (mode === "name") {
		const uname = await p.text({
			message: "pick your username",
			placeholder: "meow",
			validate: (v) =>
				v && USERNAME_RE.test(v.toLowerCase())
					? undefined
					: "a-z, 0-9, hyphens, 2-32 chars, no dots",
		});
		if (p.isCancel(uname)) bail("cancelled, nothing saved");
		username = (uname as string).toLowerCase();
	}

	let domainName = "";
	let domainVerified = false;
	if (mode === "domain") {
		const domain = await p.text({
			message: "which domain?",
			placeholder: "tiago.zip",
			validate: (v) =>
				(v && /^[a-z0-9-]+(\.[a-z0-9-]+)+$/i.test(v.trim())) ||
				/^(localhost|127\.0\.0\.1):[0-9]+$/.test(v?.trim() ?? "")
					? undefined
					: "that doesn't look like a domain",
		});
		if (p.isCancel(domain)) bail("cancelled, nothing saved");
		domainName = (domain as string).trim().toLowerCase();
		const dir = join(
			homedir(),
			"Downloads",
			`np-${new Date().toISOString().slice(0, 10).replaceAll("-", "")}`,
		);
		mkdirSync(dir, { recursive: true });
		const file = join(dir, "np");
		writeFileSync(
			file,
			armorBundle(id.key, `np public key of ${domainName}`) +
				armorAlias(domainName, signClaim(id, domainName)),
		);
		p.log.info(`wrote your key to ${file}`);
		while (true) {
			const act = await p.select({
				message: `upload it to ${httpBase(domainName)}/.well-known/np, then hit re-check`,
				options: [
					{ value: "check", label: "re-check" },
					{ value: "later", label: "i'll upload it later, continue" },
				],
			});
			if (p.isCancel(act)) bail("cancelled, nothing saved");
			if (act === "later") break;
			const live = await fetch(`${httpBase(domainName)}/.well-known/np`)
				.then(async (r) => (r.ok ? await r.text() : null))
				.catch(() => null);
			if (live && extractBundleString(live) === encodeKey(id.key)) {
				domainVerified = true;
				break;
			}
			p.log.warn(
				"couldn't find your key there yet. uploads and cdn caches can lag, give it a moment and re-check",
			);
		}
	}

	const keyring = await saveIdentity(id.seed, id);
	if (!keyring)
		p.log.warn(
			`no system keyring here, so your secret key is written into ${IDENTITY_PATH} at mode 600.\n  that file is the only copy. back it up.`,
		);

	if (username) {
		await publishName(username, id.key, signClaim(id, username))
			.then(() =>
				p.log.success(
					`claimed "${username}", people can now use -to ${username}`,
				),
			)
			.catch((e) => {
				p.log.warn(`claim failed: ${(e as Error).message}`);
				username = "";
			});
	}

	if (username) setHandle(username);
	else if (domainName) setHandle(domainName);

	if (domainName) {
		if (domainVerified)
			p.log.success(
				`${domainName} serves your key, people can use -to ${domainName}`,
			);
		else p.log.info(`np will use ${domainName} once the key is live there`);
	}

	const handles = [
		username && cyan(username),
		domainName && cyan(domainName),
		dim(fingerprint(id.key)),
	]
		.filter(Boolean)
		.join(dim(" · "));
	p.log.warn(
		`your key exists in exactly one place: this login keychain.\nback it up now, there is no recovery:  ${bold("np key secret")}`,
	);
	p.outro(`you are ${handles}`);
}
