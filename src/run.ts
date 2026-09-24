import {
	existsSync,
	lstatSync,
	readFileSync,
	renameSync,
	unlinkSync,
	writeFileSync,
} from "node:fs";
import { basename, resolve } from "node:path";
import { concatBytes, randomBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import {
	armorAlias,
	armorBundle,
	armorDetachedSig,
	armorEncrypted,
	armorSignedMessage,
	decodeKey,
	decryptBytes,
	ENC_BEGIN,
	encodeKey,
	encryptBytes,
	encryptHeader,
	fingerprint,
	identityFromSeed,
	isEncrypted,
	openHeader,
	openInner,
	PUB_BEGIN,
	padTo,
	parseDetachedSig,
	parseSignedMessage,
	SIG_BEGIN,
	SIGNED_BEGIN,
	STANZA_LEN,
	signClaim,
	signInner,
	signRevocation,
	signRotation,
	TRAILER,
	UNPADDED,
	unarmorEncrypted,
	verifyBytes,
	verifyFileHash,
} from "./core.ts";
import { LANES, pool } from "./pool.ts";
import {
	addOwnRotation,
	checkContactName,
	cleanReason,
	deleteSecret,
	exposedSecretWarning,
	handles,
	hasIdentity,
	IDENTITY_PATH,
	loadContacts,
	loadIdentity,
	nameFor,
	nameForSigner,
	ownRevocation,
	ownRotations,
	publishName,
	publishRevocation,
	rememberSignKeys,
	removeContact,
	resolveRecipient,
	revokedNote,
	saveContact,
	saveIdentity,
	secretString,
	setHandle,
	USERNAME_RE,
	urlFor,
	writeOwnRevocation,
} from "./store.ts";
import { CHUNK, openChunk, runChunks, SEALED } from "./stream.ts";
import {
	BLOCK,
	rootOf,
	TREE_ALG,
	treeHasher,
	treeHashFile,
} from "./treehash.ts";
import { cyan, dim, green, HELP, red, yellow } from "./ui.ts";

const WINDOW = 128 * CHUNK;

function trailerReader(opened: {
	plainLen: bigint;
	signed: boolean;
	header: Uint8Array;
}) {
	const known = opened.plainLen !== UNPADDED;
	const len = known ? Number(opened.plainLen) : 0;
	let left = known ? len : Number.MAX_SAFE_INTEGER;
	let skip = known && opened.signed ? padTo(len) - len : 0;
	const hash = opened.signed ? treeHasher() : null;
	const leaves: Uint8Array[] = [];
	let tail = new Uint8Array(0);
	return {
		take(plain: Uint8Array) {
			if (opened.signed && !known) {
				const both = concatBytes(tail, plain);
				const keep = Math.min(TRAILER, both.length);
				tail = both.subarray(both.length - keep);
				const out = both.subarray(0, both.length - keep);
				if (out.length) hash?.update(out);
				return out;
			}
			const use = plain.length <= left ? plain : plain.subarray(0, left);
			left -= use.length;
			if (use.length && !leaves.length) hash?.update(use);
			if (opened.signed && tail.length < TRAILER) {
				const rest = plain.subarray(use.length);
				const drop = Math.min(skip, rest.length);
				skip -= drop;
				const want = TRAILER - tail.length;
				tail = concatBytes(tail, rest.subarray(drop, drop + want));
			}
			return use;
		},
		leaf(index: number, digest: Uint8Array) {
			leaves[index] = digest;
		},
		verify() {
			if (!opened.signed) return null;
			const root = leaves.length ? rootOf(leaves) : hash?.root();
			return root ? openInner(opened.header, tail, root) : null;
		},
	};
}

const looksLikePath = (s: string) =>
	!s.includes("\n") &&
	(/^(\.{1,2}|~)?\//.test(s) ||
		/^[\w.@-]+(\/[\w.@-]+)*\.[a-z0-9]{1,8}$/i.test(s));

const prompts = () => import("@clack/prompts");

const err = (s: string) => console.error(s);

const die = (msg: string): never => {
	err(red(`error: ${msg}`));
	process.exit(1);
};

const identity = () => loadIdentity().catch((e) => die(e.message));

const liveIdentity = async () => {
	const id = await identity();
	if (ownRevocation())
		die(
			"you revoked this key, it can't sign or receive anything.\n  make a new one with `np key new` (the old secret still decrypts old messages)",
		);
	return id;
};

async function publish(nameArg?: string) {
	const name = nameArg?.toLowerCase();
	const id = await liveIdentity();
	if (!name)
		die(
			"publish what? pass a username (np publish meow) or a domain you own (np publish tiago.zip)",
		);
	if (name.includes(".")) {
		setHandle(name);
		err(
			dim(`upload what follows to https://${name}/.well-known/np`) +
				dim("\n  np publish ") +
				dim(name) +
				dim(" > np && scp np ..."),
		);
		return process.stdout.write(
			armorBundle(id.key, `np public key of ${name}`) +
				armorAlias(name, signClaim(id, name)) +
				ownRotations() +
				ownRevocation(),
		);
	}
	if (!USERNAME_RE.test(name))
		die(
			`"${name}" is not a valid username (a-z, 0-9, hyphens, 2-32 chars) or domain`,
		);
	await publishName(name, id.key, signClaim(id, name)).catch((e) =>
		die((e as Error).message),
	);
	setHandle(name);
	return err(
		green(`✓ claimed "${name}"`) +
			dim(` people can now use: np "msg" -to ${name}`),
	);
}

async function revokeIdentity(reasonArg?: string) {
	const p = await prompts();
	const id = await identity();
	if (ownRevocation()) return err(dim("already revoked."));
	err(yellow("revoking this key tells everyone to stop using it."));
	err(yellow("it cannot be undone, and this key can never be used again."));
	err(
		dim(
			"your secret stays in the keychain so you can still read old messages.\n",
		),
	);
	const answer =
		reasonArg ??
		(await p.text({
			message: "why? (shown to anyone who tries to use the key)",
			placeholder: "lost the laptop",
		}));
	if (p.isCancel(answer)) return err(dim("cancelled, nothing revoked."));
	const reason = cleanReason(String(answer ?? ""));
	const sure = await p.confirm({
		message: `revoke ${fingerprint(id.key)} forever?`,
		initialValue: false,
	});
	if (p.isCancel(sure) || !sure) return err(dim("kept."));

	const sig = signRevocation(id, reason);
	writeOwnRevocation(id.key, reason, sig);
	err(green(`✓ revoked ${fingerprint(id.key)}`));
	await publishRevocation(id.key, sig, reason).catch((e) =>
		err(
			yellow(
				`keyserver did not take it (${(e as Error).message}), run \`np key revoke\` again when you're online`,
			),
		),
	);
	for (const name of handles().filter((h) => h.includes(".")))
		err(
			dim(
				`serve the new block from https://${name}/.well-known/np too: np publish ${name}`,
			),
		);
	err(dim("make a new identity with: np key new"));
}

async function rotateIdentity() {
	const p = await prompts();
	const old = await liveIdentity();
	const mine = handles();
	err(yellow("rotating mints a NEW key and retires the current one."));
	err(
		yellow(
			"anything encrypted to the old key stays readable ONLY with the old secret:",
		),
	);
	err((await secretString()) ?? "");
	err(dim("save that line somewhere safe before continuing.\n"));
	const sure = await p.confirm({
		message: "rotate to a new key?",
		initialValue: false,
	});
	if (p.isCancel(sure) || !sure) return err(dim("kept."));

	const next = identityFromSeed(
		concatBytes(
			randomBytes(32),
			randomBytes(32),
			randomBytes(2),
			randomBytes(8),
		),
	);
	const cert = signRotation(old, next.key);
	await saveIdentity(next.seed, next);
	addOwnRotation(old.key, next.key, cert);
	for (const name of mine) setHandle(name);
	err(green(`✓ rotated to ${fingerprint(next.key)}`));

	for (const name of mine) {
		if (USERNAME_RE.test(name)) {
			await publishName(name, next.key, signClaim(next, name), cert)
				.then(() => err(green(`✓ "${name}" now points at the new key`)))
				.catch((e) =>
					err(yellow(`could not move "${name}": ${(e as Error).message}`)),
				);
			continue;
		}
		err(
			yellow(
				`re-upload your key so ${name} serves the new one:\n  np publish ${name} > np && upload it to /.well-known/np`,
			),
		);
	}
	err(
		dim(
			"contacts who pinned your old key will accept the new one automatically,\nthe rotation certificate proves it came from you.",
		),
	);
}

async function clearIdentity() {
	const p = await prompts();
	if (!hasIdentity()) die("no identity to clear");
	const secret = await secretString();
	err(
		yellow("this permanently deletes your identity. anything encrypted to it"),
	);
	err(
		yellow("becomes unreadable forever. your secret key, save it if unsure:"),
	);
	if (secret) err(secret);
	const sure = await p.confirm({
		message: "delete this identity?",
		initialValue: false,
	});
	if (p.isCancel(sure) || !sure) return err(dim("kept."));
	await deleteSecret().catch(() => {
		if (process.platform === "darwin")
			Bun.spawnSync([
				"security",
				"delete-generic-password",
				"-s",
				"np",
				"-a",
				IDENTITY_PATH,
			]);
		else
			err(
				yellow(
					`could not remove the secret from your keyring, delete it by hand:\n  service "np", account ${IDENTITY_PATH}`,
				),
			);
	});
	unlinkSync(IDENTITY_PATH);
	err(green("✓ identity cleared"));
}

const identityFileLine = (marker: string) =>
	hasIdentity()
		? (readFileSync(IDENTITY_PATH, "utf8")
				.split("\n")
				.find((l) => l.includes(marker))
				?.split(marker)[1]
				?.trim() ?? null)
		: null;

async function gatherRecipients(
	specs: string[],
	includeSelf: boolean,
	acceptNew = false,
) {
	const contacts = loadContacts();
	const recipients = new Map<string, Uint8Array>();
	for (const spec of specs) {
		try {
			const key = await resolveRecipient(spec, contacts, { acceptNew });
			const gone = revokedNote(key);
			if (gone)
				die(
					`${spec}: ${gone}.\n  ask them for a new key, np won't encrypt to a revoked one`,
				);
			recipients.set(encodeKey(key), key);
		} catch (e) {
			die((e as Error).message);
		}
	}
	if (includeSelf) {
		if (ownRevocation())
			die(
				"you revoked your own key, so you could not read this.\n  make a new one with `np key new`, or pass --no-self",
			);
		const self = identityFileLine("# key: ");
		if (self) {
			const key = (() => {
				try {
					return decodeKey(self);
				} catch {
					return die(
						`${IDENTITY_PATH} is damaged: its key does not decode.\n  restore it from a backup, or run \`np key new\` for a new identity`,
					);
				}
			})();
			recipients.set(encodeKey(key), key);
		} else if (!specs.length)
			die("no identity and no recipients, run `np key new` or pass -to");
		else
			err(
				dim(
					"note: no own identity, you won't be able to decrypt this (`np key new`)",
				),
			);
	}
	if (!recipients.size)
		die("no recipients (pass -to <key|contact> or create an identity)");
	return [...recipients.values()];
}

function reportSignature(signKey: Uint8Array, valid: boolean) {
	const contacts = loadContacts();
	const name = nameForSigner(signKey, contacts);
	if (!valid) {
		err(red(`✗ BAD signature claiming ${name ?? "an unknown key"}`));
		process.exit(1);
	}
	const owner = [...contacts].find(([, k]) =>
		nameForSigner(signKey, new Map([["x", k]])),
	);
	const gone = owner ? revokedNote(owner[1]) : null;
	if (gone)
		err(
			yellow(
				`note: ${gone}\n  the signature is still good, but it may predate the revocation`,
			),
		);
	if (name) err(green(`✓ good signature from ${name}`));
	else
		err(
			yellow(
				"✓ good signature, but this key is not in your contacts\n  add them with: np contacts add <their key, domain or username>",
			),
		);
}

const removeIfOurs = (dest: string | null) => {
	const ours = !!dest && !existsSync(dest);
	return () => {
		if (dest && ours && existsSync(dest)) unlinkSync(dest);
	};
};

const present = (path: string) => {
	try {
		lstatSync(path);
		return true;
	} catch {
		return false;
	}
};

function outPath(
	requested: string | undefined,
	fallback: string,
	input?: string,
) {
	const path = requested ?? fallback;
	if (input && path !== "-" && resolve(path) === resolve(input))
		die(`-o ${path} is the input file, that would destroy it`);
	if (requested) return requested;
	if (!present(fallback)) return fallback;
	return die(`${fallback} already exists, pass -o`);
}

const SUBCOMMAND_OF: Record<string, string> = {
	new: "key new",
	gen: "key new",
	keygen: "key new",
	secret: "key secret",
	rotate: "key rotate",
	revoke: "key revoke",
	clear: "key clear",
	add: "contacts add",
	import: "contacts add",
	rm: "contacts rm",
	remove: "contacts rm",
	rename: "contacts rename",
	list: "contacts",
};

const COMMANDS = [
	"key",
	"keygen",
	"publish",
	"contacts",
	"sign",
	"verify",
	"encrypt",
	"decrypt",
	"version",
	"help",
];

const oneEditApart = (a: string, b: string) => {
	if (Math.abs(a.length - b.length) > 1) return false;
	let i = 0;
	let j = 0;
	let edits = 0;
	while (i < a.length && j < b.length) {
		if (a[i] === b[j]) {
			i++;
			j++;
			continue;
		}
		if (++edits > 1) return false;
		if (a.length > b.length) i++;
		else if (a.length < b.length) j++;
		else {
			i++;
			j++;
		}
	}
	return edits + (a.length - i) + (b.length - j) <= 1;
};

const nearestCommand = (words: string[]) =>
	`to sign this as a message, quote it: np "${words.join(" ")}"`;

export type Opts = {
	recipients: string[];
	out?: string;
	noSelf: boolean;
	acceptNew: boolean;
	noSign: boolean;
};

async function encryptText(text: string, opts: Opts) {
	const signer = opts.noSign ? null : await liveIdentity();
	const recipients = await gatherRecipients(
		opts.recipients,
		!opts.noSelf,
		opts.acceptNew,
	);
	const bin = (() => {
		try {
			return encryptBytes(
				utf8ToBytes(text),
				recipients,
				signer ?? undefined,
				true,
			);
		} catch (e) {
			return die(`could not encrypt to that key: ${(e as Error).message}`);
		}
	})();
	if (signer) await rememberSignKeys(signer);
	const armor = armorEncrypted(bin);
	const dest = opts.out && opts.out !== "-" ? opts.out : null;
	if (!dest) return void process.stdout.write(armor);
	writeFileSync(dest, armor);
	err(green(`✓ encrypted to ${dest}`));
}

async function encryptFile(path: string, opts: Opts) {
	const recipients = await gatherRecipients(
		opts.recipients,
		!opts.noSelf,
		opts.acceptNew,
	);
	const out = outPath(opts.out, `${path}.np`, path);
	const file = Bun.file(path);
	const signer = opts.noSign ? null : await liveIdentity();
	const hash = signer ? await treeHashFile(path) : null;
	const { key, header, padded } = encryptHeader(
		recipients,
		file.size,
		!!signer,
	);
	const trailer =
		signer && hash ? signInner(signer, header, hash) : new Uint8Array(0);
	if (signer) await rememberSignKeys(signer);
	const target = padded ?? file.size + trailer.length;
	const writer = Bun.file(out).writer({ highWaterMark: BLOCK });
	writer.write(header);
	const blocks = Math.max(1, Math.ceil(target / BLOCK));
	if (Math.min(blocks, LANES) < 2) {
		const slab = async (at: number) => {
			const buf = new Uint8Array(Math.min(WINDOW, target - at));
			if (at < file.size)
				buf.set(
					new Uint8Array(
						await file
							.slice(at, Math.min(at + buf.length, file.size))
							.arrayBuffer(),
					),
				);
			const base = padTo(file.size);
			for (let i = 0; i < trailer.length; i++) {
				const at2 = base + i - at;
				if (at2 >= 0 && at2 < buf.length) buf[at2] = trailer[i] as number;
			}
			return buf;
		};
		const total = Math.max(1, Math.ceil(target / CHUNK));
		let index = 0;
		let pending = slab(0);
		while (index < total) {
			const buf = await pending;
			const done = index + Math.max(1, Math.ceil(buf.length / CHUNK));
			if (done < total) pending = slab(done * CHUNK);
			writer.write(runChunks("seal", key, index, done >= total, buf));
			index = done;
			await writer.flush();
		}
	} else {
		const jobs = pool(blocks);
		try {
			for (let at = 0; at < blocks; at += jobs.lanes) {
				const wave = await jobs.wave(at, (index) => ({
					op: "seal",
					path,
					index,
					key,
					size: target,
					real: file.size,
					trailerAt: padTo(file.size),
					trailer,
					offset: 0,
					final: index === blocks - 1,
					version: 4,
				}));
				for (const r of wave) writer.write(new Uint8Array(r.data));
				await writer.flush();
			}
		} finally {
			jobs.close();
		}
	}
	await writer.end();
	err(
		green(`✓ encrypted to ${out}`) +
			dim(
				` (${recipients.length} recipient${recipients.length > 1 ? "s" : ""})`,
			),
	);
}

function chunker(reader: AsyncIterator<Uint8Array>, head?: Uint8Array) {
	const pending: Uint8Array[] = head?.length ? [head] : [];
	let held = head?.length ?? 0;
	let drained = false;
	const scratch = new Uint8Array(CHUNK + 16);
	return {
		get held() {
			return held;
		},
		get drained() {
			return drained;
		},
		async fill(want: number) {
			while (held < want && !drained) {
				const { value, done } = await reader.next();
				if (done || !value) drained = true;
				else {
					pending.push(value);
					held += value.length;
				}
			}
			return held;
		},
		take(n: number) {
			const out = n === scratch.length ? scratch : new Uint8Array(n);
			let off = 0;
			while (off < n) {
				const first = pending[0] as Uint8Array;
				const need = n - off;
				if (first.length <= need) {
					out.set(first, off);
					off += first.length;
					pending.shift();
				} else {
					out.set(first.subarray(0, need), off);
					pending[0] = first.subarray(need);
					off = n;
				}
			}
			held -= n;
			return out.subarray(0, n);
		},
	};
}

type Sink = {
	write: (b: Uint8Array) => void;
	flush: () => Promise<unknown>;
	end: () => Promise<unknown>;
	abandon?: () => Promise<unknown>;
};

const HOLD = 64 * 1024 * 1024;
const LATE_VERDICT = `note: over ${HOLD >> 20} MiB, so the signature is checked only after the data is written.\n  check the exit code, not just the output`;

const sinkFor = (dest: string | null, verifying = false): Sink => {
	if (!dest && !verifying)
		return {
			write: (b) => process.stdout.write(b),
			flush: async () => {},
			end: async () => {},
		};
	if (!dest) {
		let held: Uint8Array[] | null = [];
		let size = 0;
		return {
			write: (b) => {
				if (!held) return void process.stdout.write(b);
				held.push(b);
				size += b.length;
				if (size <= HOLD) return;
				err(yellow(LATE_VERDICT));
				for (const part of held) process.stdout.write(part);
				held = null;
			},
			flush: async () => {},
			end: async () => {
				if (!held) return;
				for (const part of held) process.stdout.write(part);
				held = null;
			},
			abandon: async () => {
				held = null;
			},
		};
	}
	const part = `${dest}.np-part`;
	const w = Bun.file(part).writer({ highWaterMark: WINDOW });
	return {
		write: (b) => w.write(b),
		flush: () => w.flush(),
		end: async () => {
			await w.end();
			renameSync(part, dest);
		},
		abandon: async () => {
			await w.end().catch(() => {});
			if (existsSync(part)) unlinkSync(part);
		},
	};
};

async function encryptStdin(opts: Opts) {
	const signer = opts.noSign ? null : await liveIdentity();
	const recipients = await gatherRecipients(
		opts.recipients,
		!opts.noSelf,
		opts.acceptNew,
	);
	const dest = opts.out && opts.out !== "-" ? opts.out : null;
	if (!dest && process.stdout.isTTY)
		die("refusing to write binary to the terminal, pass -o <file> or pipe it");
	const input = chunker(Bun.stdin.stream()[Symbol.asyncIterator]());
	await input.fill(WINDOW + 1);
	const whole = input.drained ? input.held : undefined;
	const { key, header, padded } = encryptHeader(recipients, whole, !!signer);
	const sink = sinkFor(dest);
	sink.write(header);
	const hash = signer ? treeHasher() : null;
	const seal = (i: number, final: boolean, buf: Uint8Array) =>
		sink.write(runChunks("seal", key, i, final, buf, 4));
	let index = 0;
	if (whole !== undefined && padded !== undefined) {
		const data = input.take(whole);
		hash?.update(data);
		const full = new Uint8Array(padded);
		full.set(data);
		if (signer && hash)
			full.set(signInner(signer, header, hash.root()), padTo(whole));
		seal(0, true, full);
	} else {
		while (true) {
			await input.fill(WINDOW + 1);
			const ready = Math.floor(Math.max(input.held - 1, 0) / CHUNK);
			if (ready <= 0) break;
			const piece = input.take(ready * CHUNK);
			hash?.update(piece);
			seal(index, false, piece);
			index += ready;
			await sink.flush();
		}
		const rest = input.take(input.held);
		hash?.update(rest);
		const tail =
			signer && hash
				? concatBytes(rest, signInner(signer, header, hash.root()))
				: rest;
		seal(index, true, tail);
	}
	if (signer) await rememberSignKeys(signer);
	await sink.end();
	if (dest)
		err(
			green(`✓ encrypted to ${dest}`) +
				dim(
					` (${recipients.length} recipient${recipients.length > 1 ? "s" : ""})`,
				),
		);
}

async function decryptStdin(
	head: Uint8Array,
	reader: AsyncIterator<Uint8Array>,
	opts: Opts,
) {
	const id = await identity();
	const dest = opts.out && opts.out !== "-" ? opts.out : null;
	const sealed = CHUNK + 16;
	const input = chunker(reader, head);
	await input.fill(14);
	const start = head[3] === 0x34 ? 14 : head[3] === 0x33 ? 13 : 5;
	const headerLen = start + (head[4] ?? 0) * STANZA_LEN;
	await input.fill(headerLen);
	const opened = (() => {
		try {
			return openHeader(input.take(Math.min(headerLen, input.held)), id);
		} catch (e) {
			return die((e as Error).message);
		}
	})();
	const discard = removeIfOurs(dest);
	const sink = sinkFor(dest, opened.signed);
	const seen = trailerReader(opened);
	const put = (plain: Uint8Array) => {
		const use = seen.take(plain);
		if (use.length) sink.write(use);
	};
	let index = 0;
	try {
		while (true) {
			await input.fill(WINDOW + 1);
			const whole = Math.floor(Math.max(input.held - 1, 0) / sealed);
			if (whole <= 0) break;
			put(
				runChunks(
					"open",
					opened.key,
					index,
					false,
					input.take(whole * sealed),
					opened.v,
				),
			);
			index += whole;
			await sink.flush();
		}
		put(openChunk(opened.key, index, true, input.take(input.held), opened.v));
	} catch (e) {
		await (sink.abandon?.() ?? sink.end());
		discard();
		return die(`corrupt or tampered ciphertext: ${(e as Error).message}`);
	}
	const signKey = seen.verify();
	if (opened.signed && !signKey) {
		await (sink.abandon?.() ?? sink.end());
		discard();
		return die("the signature inside does not match the message");
	}
	await sink.end();
	if (dest) err(green(`✓ decrypted to ${dest}`));
	if (signKey) reportSignature(signKey, true);
	else err(dim("note: this was encrypted without a signature"));
}

async function decryptFile(path: string, opts: Opts) {
	const id = await identity();
	const file = Bun.file(path);
	const probe = new Uint8Array(
		await file.slice(0, 14 + 255 * STANZA_LEN).arrayBuffer(),
	);
	const opened = (() => {
		try {
			return openHeader(probe, id);
		} catch (e) {
			return die((e as Error).message);
		}
	})();
	const fallback = path.endsWith(".np") ? path.slice(0, -3) : `${path}.out`;
	const dest = opts.out === "-" ? null : outPath(opts.out, fallback, path);
	const discard = removeIfOurs(dest);
	const body = file.size - opened.bodyOffset;
	const total = Math.max(1, Math.ceil(body / SEALED));
	const windowSize = 128 * SEALED;
	const part = dest ? `${dest}.np-part` : null;
	const writer = part
		? Bun.file(part).writer({ highWaterMark: windowSize })
		: null;
	const slab = (at: number) =>
		file.slice(at, Math.min(at + windowSize, file.size)).arrayBuffer();
	const span = (BLOCK / CHUNK) * SEALED;
	const blocks = Math.max(1, Math.ceil(body / span));
	const seen = trailerReader(opened);
	const stdout = writer ? null : sinkFor(null, opened.signed);
	const emit = (raw: Uint8Array) => {
		const plain = seen.take(raw);
		if (!plain.length) return;
		if (writer) writer.write(plain);
		else stdout?.write(plain);
	};
	try {
		if (Math.min(blocks, LANES) < 2) {
			let index = 0;
			let pending = slab(opened.bodyOffset);
			while (index < total) {
				const buf = new Uint8Array(await pending);
				const done = index + Math.max(1, Math.ceil(buf.length / SEALED));
				if (done < total) pending = slab(opened.bodyOffset + done * SEALED);
				emit(
					runChunks("open", opened.key, index, done >= total, buf, opened.v),
				);
				index = done;
				await writer?.flush();
			}
		} else {
			const jobs = pool(blocks);
			try {
				for (let at = 0; at < blocks; at += jobs.lanes) {
					const wave = await jobs.wave(at, (index) => ({
						op: "open",
						path,
						index,
						key: opened.key,
						size: file.size,
						plain:
							opened.plainLen === UNPADDED
								? undefined
								: Number(opened.plainLen),
						offset: opened.bodyOffset,
						final: index === blocks - 1,
						version: opened.v,
					}));
					for (const r of wave) {
						if (r.leaf) seen.leaf(r.index, new Uint8Array(r.leaf));
						emit(new Uint8Array(r.data));
					}
					await writer?.flush();
				}
			} finally {
				jobs.close();
			}
		}
	} catch (e) {
		await writer?.end();
		if (part && existsSync(part)) unlinkSync(part);
		discard();
		return die(`corrupt or tampered ciphertext: ${(e as Error).message}`);
	}
	await writer?.end();
	const signKey = seen.verify();
	if (opened.signed && !signKey) {
		if (part && existsSync(part)) unlinkSync(part);
		await stdout?.abandon?.();
		discard();
		return die("the signature inside does not match the file");
	}
	await stdout?.end();
	if (part && dest) renameSync(part, dest);
	if (dest) err(green(`✓ decrypted to ${dest}`));
	if (signKey) reportSignature(signKey, true);
	else err(dim("note: this was encrypted without a signature"));
}

async function decryptToStdoutOrFile(
	bin: Uint8Array,
	opts: Opts,
	sourcePath?: string,
) {
	const {
		data: plain,
		signKey,
		message,
	} = await (async () => {
		try {
			return decryptBytes(bin, await identity());
		} catch (e) {
			return die((e as Error).message);
		}
	})();
	const named = () => {
		if (signKey) reportSignature(signKey, true);
		else err(dim("note: this was encrypted without a signature"));
	};
	if ((message || !sourcePath) && !opts.out) {
		process.stdout.write(plain);
		if (
			process.stdout.isTTY &&
			!new TextDecoder().decode(plain.slice(-1)).endsWith("\n")
		)
			process.stdout.write("\n");
		return named();
	}
	const fallback = sourcePath?.endsWith(".np")
		? sourcePath.slice(0, -3)
		: `${sourcePath ?? "np"}.out`;
	const out =
		opts.out === "-"
			? null
			: outPath(opts.out, fallback, sourcePath ?? undefined);
	if (!out) {
		process.stdout.write(plain);
		return named();
	}
	writeFileSync(out, plain);
	err(green(`✓ decrypted to ${out}`));
	named();
}

async function verifySignedText(text: string, dest?: string | null) {
	try {
		const { msg, signKey, sig } = parseSignedMessage(text);
		const valid = verifyBytes(signKey, sig, utf8ToBytes(msg));
		const body = msg.endsWith("\n") ? msg : `${msg}\n`;
		if (valid && dest) {
			writeFileSync(dest, body);
			err(green(`✓ decrypted to ${dest}`));
		} else if (valid) process.stdout.write(body);
		reportSignature(signKey, valid);
	} catch (e) {
		die((e as Error).message);
	}
}

async function verifyDetached(sigPath: string, filePath: string) {
	if (!existsSync(filePath)) die(`signed file ${filePath} not found`);
	try {
		const { signKey, sig, alg } = parseDetachedSig(
			readFileSync(sigPath, "utf8"),
		);
		const hashing =
			alg === TREE_ALG ? treeHashFile(filePath) : hashFile(filePath);
		if (Bun.file(filePath).size >= WARM_ABOVE)
			verifyFileHash(signKey, sig, new Uint8Array(64));
		const hash = await hashing;
		err(dim(`${filePath}:`));
		reportSignature(signKey, verifyFileHash(signKey, sig, hash));
	} catch (e) {
		die((e as Error).message);
	}
}

const ownHandle = () => identityFileLine("# handle: ") ?? undefined;

async function signText(text: string) {
	const id = await liveIdentity();
	process.stdout.write(armorSignedMessage(text, id, ownHandle()));
	await rememberSignKeys(id);
}

const SLAB = 32 * 1024 * 1024;

const hashFile = async (path: string) => {
	const file = Bun.file(path);
	const size = file.size;
	const h = new Bun.CryptoHasher("sha512");
	const slab = (at: number) =>
		file.slice(at, Math.min(at + SLAB, size)).arrayBuffer();
	let pending = slab(0);
	for (let at = 0; at < size; at += SLAB) {
		const buf = await pending;
		if (at + SLAB < size) pending = slab(at + SLAB);
		h.update(buf);
	}
	return new Uint8Array(h.digest().buffer);
};

const WARM_ABOVE = 64 * 1024 * 1024;

async function signFile(path: string, opts: Opts) {
	const id = await liveIdentity();
	const hashing = treeHashFile(path);
	const hash = await hashing;
	const out = outPath(opts.out, `${path}.npsig`, path);
	const armor = armorDetachedSig(
		hash,
		basename(path),
		id,
		ownHandle(),
		TREE_ALG,
	);
	writeFileSync(out, armor);
	await rememberSignKeys(id);
	err(green(`✓ signature written to ${out}`));
}

async function autoFile(path: string, opts: Opts, forced?: string) {
	if (forced === "encrypt") return encryptFile(path, opts);
	const head = new Uint8Array(
		await Bun.file(path).slice(0, 4096).arrayBuffer(),
	);
	if (isEncrypted(head)) return decryptFile(path, opts);
	const text = new TextDecoder().decode(head);
	if (text.startsWith(PUB_BEGIN) && !opts.recipients.length)
		return die(
			`that's a public key, trust it with: np contacts add ${path} <name>`,
		);
	if (text.startsWith(ENC_BEGIN))
		return decryptToStdoutOrFile(
			unarmorEncrypted(readFileSync(path, "utf8")),
			opts,
		);
	if (text.startsWith(SIGNED_BEGIN))
		return verifySignedText(readFileSync(path, "utf8"));
	if (text.startsWith(SIG_BEGIN))
		return verifyDetached(path, path.replace(/\.(npsig|sig)$/, ""));
	if (forced === "decrypt") return die(`${path} is not an np encrypted file`);
	if (opts.recipients.length) return encryptFile(path, opts);
	if (forced !== "sign" && existsSync(`${path}.npsig`))
		return verifyDetached(`${path}.npsig`, path);
	if (forced === "verify")
		return die(`no signature found for ${path} (expected ${path}.npsig)`);
	return signFile(path, opts);
}

async function autoText(text: string, opts: Opts, forced?: string) {
	const t = text.trim();
	if (forced === "encrypt") return encryptText(text, opts);
	if (t.startsWith(PUB_BEGIN))
		return die(
			"that's a public key, trust it with: np contacts add <key|file> <name>",
		);
	if (t.startsWith(ENC_BEGIN))
		return decryptToStdoutOrFile(unarmorEncrypted(t), opts);
	if (t.startsWith(SIGNED_BEGIN)) return verifySignedText(t);
	if (t.startsWith(SIG_BEGIN))
		return die("detached signature needs its file: np <file>");
	if (forced === "decrypt") return die("input is not an np encrypted message");
	if (forced === "verify") return die("input is not an np signed message");
	if (opts.recipients.length) return encryptText(text, opts);
	return signText(text);
}

const usableName = (name: string) => {
	try {
		return checkContactName(name.trim());
	} catch (e) {
		return die((e as Error).message);
	}
};

async function addKey(source?: string, nameArg?: string, acceptNew = false) {
	let from = source;
	if (!from) {
		const p = await prompts();
		const answer = await p.text({
			message: "their npkey1... , a domain, a username, or a file path",
		});
		if (p.isCancel(answer)) process.exit(1);
		from = answer as string;
	}
	const spec = from.trim();
	const key = await resolveRecipient(spec, loadContacts(), {
		refresh: true,
		acceptNew,
	}).catch((e) => die((e as Error).message));
	const gone = revokedNote(key);
	if (gone) err(yellow(`warning: ${gone}`));
	const looksNamed =
		!existsSync(spec) && !spec.toLowerCase().startsWith("npkey1");
	const implied =
		looksNamed && urlFor(spec.toLowerCase()) ? spec.toLowerCase() : undefined;
	let name = nameArg ?? implied;
	if (!name) {
		const p = await prompts();
		const answer = await p.text({
			message: "name for this contact",
			validate: (v) =>
				!v?.trim() || /\s/.test(v) ? "one word, non-empty" : undefined,
		});
		if (p.isCancel(answer)) process.exit(1);
		name = (answer as string).trim();
	}
	const existing = nameFor(key, loadContacts());
	saveContact(usableName(name), key);
	err(green(`✓ added ${name} ${dim(fingerprint(key))}`));
	if (existing && existing !== name)
		err(yellow(`note: the same key is also saved as "${existing}"`));
}

async function contacts(args: string[], opts: Opts) {
	const [sub, who, to] = args;
	if (sub === "add") return addKey(who, to, opts.acceptNew);
	if (sub === "rm" || sub === "remove") {
		if (!who) die("usage: np contacts rm <name>");
		return err(
			removeContact(who)
				? green(`✓ removed ${who}`)
				: yellow(`no contact named "${who}"`),
		);
	}
	if (sub === "rename") {
		const key = who ? loadContacts().get(who.toLowerCase()) : undefined;
		if (!who || !to || who === to) die("usage: np contacts rename <old> <new>");
		if (!key) die(`no contact named "${who}"`);
		saveContact(usableName(to), key);
		removeContact(who);
		return err(green(`✓ ${who} is now ${to}`));
	}
	if (sub) die(`unknown subcommand "np contacts ${sub}"`);
	const contacts = [...loadContacts()];
	if (!contacts.length)
		return err(
			dim("no contacts yet, add one with: np contacts add <key|domain|name>"),
		);
	for (const [name, key] of contacts)
		console.log(`${cyan(name.padEnd(20))} ${dim(fingerprint(key))}`);
}

export async function run(positional: string[], opts: Opts) {
	const [cmd, ...rest] = positional;
	const exposed = exposedSecretWarning();
	if (exposed) err(yellow(`warning: ${exposed}`));

	if (cmd === "key") {
		const sub = rest[0];
		if (sub === "new" || sub === "gen") {
			const { keygenWizard } = await import("./keygen.ts");
			return keygenWizard();
		}
		if (sub === "rotate") return rotateIdentity();
		if (sub === "revoke")
			return revokeIdentity(rest.slice(1).join(" ") || undefined);
		if (sub === "clear") return clearIdentity();
		if (!hasIdentity()) die("no identity yet, run: np key new");
		if (sub === "secret") {
			const secret =
				(await secretString()) ?? die("secret missing from keychain");
			return console.log(secret);
		}
		if (sub !== undefined)
			die(
				`unknown subcommand "np key ${sub}", try: np key new|secret|rotate|revoke|clear`,
			);
		return console.log(
			identityFileLine("# key: ") ?? die(`no key line in ${IDENTITY_PATH}`),
		);
	}
	if (cmd === "publish") return publish(rest[0]);
	if (cmd === "contacts") return contacts(rest, opts);

	const forced = ["sign", "verify", "encrypt", "decrypt"].includes(cmd ?? "")
		? cmd
		: undefined;
	const inputs = forced ? rest : positional;
	const bare =
		inputs.length === 1 && !opts.recipients.length && !opts.out && !opts.noSelf;
	if (!forced && cmd !== undefined && !existsSync(cmd)) {
		const near = COMMANDS.find((c) => oneEditApart(cmd, c));
		const full = SUBCOMMAND_OF[cmd];
		if (inputs.length > 1) {
			if (near) die(`unknown command "${cmd}", did you mean "np ${near}"?`);
			if (full) die(`"${cmd}" alone is not a command, you want: np ${full}`);
		}
		if (bare && full)
			die(`"${cmd}" on its own does nothing, you want: np ${full}`);
		if (bare && near)
			die(`unknown command "${cmd}", did you mean "np ${near}"?`);
	}
	if (!forced && inputs.length > 2) die(nearestCommand(inputs));
	if (!forced && inputs.length === 2) {
		const where = inputs[1] as string;
		if (!/[./\\]/.test(where) && where !== "-") die(nearestCommand(inputs));
		if (opts.out)
			die("you gave an output path twice, positionally and with -o");
		opts.out = where;
	}

	if (
		forced === "verify" &&
		inputs.length === 2 &&
		existsSync(inputs[1] as string)
	)
		return verifyDetached(inputs[1] as string, inputs[0] as string);

	const input = inputs[0];
	if (
		input !== undefined &&
		input !== "-" &&
		!existsSync(input) &&
		looksLikePath(input)
	)
		die(`no such file: ${input}`);
	if (input === "-" || (input === undefined && !process.stdin.isTTY)) {
		if (opts.recipients.length && forced !== "sign") return encryptStdin(opts);
		const reader = Bun.stdin.stream()[Symbol.asyncIterator]();
		let head = (await reader.next()).value ?? new Uint8Array(0);
		while (head.length < 6) {
			const more = await reader.next();
			if (more.done) break;
			head = concatBytes(head, more.value);
		}
		if (isEncrypted(head)) return decryptStdin(head, reader, opts);
		const decoder = new TextDecoder();
		let all = decoder.decode(head, { stream: true });
		while (true) {
			const { value, done } = await reader.next();
			if (done) break;
			all += decoder.decode(value, { stream: true });
		}
		all += decoder.decode();
		if (!all.trim()) die("empty stdin");
		return autoText(all, opts, forced);
	}
	if (input === undefined) return console.log(HELP);
	if (existsSync(input)) return autoFile(input, opts, forced);
	return autoText(input, opts, forced);
}
