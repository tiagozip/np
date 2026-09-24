import {
	chmodSync,
	existsSync,
	mkdirSync,
	readFileSync,
	statSync,
	unlinkSync,
	writeFileSync,
} from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { concatBytes } from "@noble/hashes/utils.js";
import { secrets } from "bun";
import {
	armorRevocation,
	armorRotation,
	decodeKey,
	encodeKey,
	extractBundleString,
	fingerprint,
	fromBech,
	type Identity,
	identityFromSeed,
	KEM_PK,
	PUB_BEGIN,
	parseAliases,
	parseRevocations,
	parseRotations,
	SALT_LEN,
	SIGN_PK,
	type SignKeys,
	signerKey,
	toBech,
	verifyClaim,
	verifyRevocation,
	verifyRotation,
} from "./core.ts";

export const CONFIG_DIR =
	process.env.NP_CONFIG_DIR ?? join(homedir(), ".config", "np");
export const IDENTITY_PATH = join(CONFIG_DIR, "identity");
const CONTACTS_PATH = join(CONFIG_DIR, "contacts");
const REVOKED_PATH = join(CONFIG_DIR, "revoked");
const ROTATION_PATH = join(CONFIG_DIR, "rotations");
const OWN_REVOCATION_PATH = join(CONFIG_DIR, "revocation");
const SIGNKEYS_PATH = join(CONFIG_DIR, "signkeys");
const KEYCHAIN = { service: "np", name: IDENTITY_PATH };
const KEYCHAIN_SIGN = { service: "np", name: `${IDENTITY_PATH}#sign` };

export const KEYSERVER = process.env.NP_KEYSERVER ?? "https://np.tiago.zip";

export const USERNAME_RE = /^[a-z0-9][a-z0-9-]{1,31}$/;

const printable = (s: string) =>
	[...s].every((c) => {
		const code = c.charCodeAt(0);
		return code > 0x20 && code !== 0x7f;
	});

export function checkContactName(name: string) {
	if (!name || !printable(name) || name.length > 64)
		throw new Error(
			`"${[...name].map((c) => (c.charCodeAt(0) <= 0x20 ? "·" : c)).join("")}" is not a usable contact name (one word, no spaces, up to 64 characters)`,
		);
	return name;
}

export const hasIdentity = () => existsSync(IDENTITY_PATH);

export async function saveIdentity(seed: Uint8Array, id: Identity) {
	mkdirSync(CONFIG_DIR, { recursive: true });
	await forgetSignKeys();
	const secret = toBech("npsec", seed);
	const keyring = await secrets
		.set({ ...KEYCHAIN, value: secret })
		.then(() => true)
		.catch(() => false);
	const lines = [
		`# np identity, created ${new Date().toISOString().slice(0, 10)}`,
		keyring
			? "# secret key is in the login keychain, view with: np key secret"
			: "# no system keyring here, so the secret key is the line below.",
		...(keyring ? [] : ["# this file is the only copy, keep it at mode 600."]),
		`# fingerprint: ${fingerprint(id.key)}`,
		`# key: ${encodeKey(id.key)}`,
		...(keyring ? [] : [secret]),
		"",
	];
	writeFileSync(IDENTITY_PATH, lines.join("\n"), { mode: 0o600 });
	chmodSync(IDENTITY_PATH, 0o600);
	return keyring;
}

export function exposedSecretWarning() {
	if (!hasIdentity()) return null;
	const inFile = readFileSync(IDENTITY_PATH, "utf8")
		.split("\n")
		.some((l) => l.trim().startsWith("npsec1"));
	if (!inFile || (statSync(IDENTITY_PATH).mode & 0o077) === 0) return null;
	return `${IDENTITY_PATH} holds your secret key and is readable by other users.\n  fix it with: chmod 600 ${IDENTITY_PATH}`;
}

const SIGN_TAG = "npsign1 ";

let signKeysCached = false;

const b64 = (b: Uint8Array) => Buffer.from(b).toString("base64");

export const packSignKeys = (keys: SignKeys) =>
	`${SIGN_TAG}${b64(keys.publicKey)}.${b64(keys.falconSecret)}.${b64(keys.edSecret)}`;

export function unpackSignKeys(stored: string): SignKeys | undefined {
	const line = stored
		.split("\n")
		.find((l) => l.startsWith(SIGN_TAG))
		?.slice(SIGN_TAG.length);
	if (!line) return undefined;
	const [pk, falcon, ed] = line.split(".");
	if (!pk || !falcon || !ed) return undefined;
	const publicKey = Uint8Array.from(Buffer.from(pk, "base64"));
	const falconSecret = Uint8Array.from(Buffer.from(falcon, "base64"));
	const edSecret = Uint8Array.from(Buffer.from(ed, "base64"));
	return publicKey.length === SIGN_PK && falconSecret.length && edSecret.length
		? { publicKey, falconSecret, edSecret }
		: undefined;
}

const secretIsInFile = () =>
	hasIdentity() &&
	readFileSync(IDENTITY_PATH, "utf8")
		.split("\n")
		.some((l) => l.trim().startsWith("npsec1"));

export async function secretString() {
	const fileLine = hasIdentity()
		? readFileSync(IDENTITY_PATH, "utf8")
				.split("\n")
				.map((l) => l.trim())
				.find((l) => l.startsWith("npsec1"))
		: undefined;
	return fileLine ?? (await secrets.get(KEYCHAIN));
}

export async function loadIdentity(): Promise<Identity> {
	if (!hasIdentity())
		throw new Error("no identity found, run `np key new` first");
	const secret = await secretString();
	if (!secret)
		throw new Error(
			`identity file exists but the secret is missing from the keychain (service "np", account ${IDENTITY_PATH})`,
		);
	const line = readFileSync(IDENTITY_PATH, "utf8")
		.split("\n")
		.find((l) => l.startsWith("# key: "))
		?.slice(7)
		.trim();
	const known = line
		? ((): Uint8Array | undefined => {
				try {
					return decodeKey(line);
				} catch {
					return undefined;
				}
			})()
		: undefined;
	const cached = known ? await signKeysFor(fingerprint(known)) : undefined;
	signKeysCached = !!cached;
	return identityFromSeed(fromBech("npsec", secret), known, cached);
}

export const deleteSecret = async () => {
	await forgetSignKeys();
	return secrets.delete(KEYCHAIN);
};

export async function rememberSignKeys(id: Identity) {
	if (signKeysCached) return;
	const publicKey = id.bundle.slice(
		SALT_LEN + KEM_PK,
		SALT_LEN + KEM_PK + SIGN_PK,
	);
	const value = `${fingerprint(id.key)}\n${packSignKeys({ ...id.signKeys, publicKey })}\n`;
	if (secretIsInFile()) {
		if (existsSync(SIGNKEYS_PATH)) return;
		mkdirSync(CONFIG_DIR, { recursive: true });
		writeFileSync(SIGNKEYS_PATH, value);
		chmodSync(SIGNKEYS_PATH, 0o600);
		return;
	}
	await secrets.set({ ...KEYCHAIN_SIGN, value }).catch(() => {});
}

export function forgetSignKeys() {
	if (existsSync(SIGNKEYS_PATH)) unlinkSync(SIGNKEYS_PATH);
	return secrets.delete(KEYCHAIN_SIGN).catch(() => false);
}

async function signKeysFor(fp: string) {
	const text = secretIsInFile()
		? existsSync(SIGNKEYS_PATH)
			? readFileSync(SIGNKEYS_PATH, "utf8")
			: null
		: await secrets.get(KEYCHAIN_SIGN).catch(() => null);
	if (!text || text.split("\n")[0]?.trim() !== fp) return undefined;
	return unpackSignKeys(text);
}

export function handles() {
	if (!hasIdentity()) return [];
	return readFileSync(IDENTITY_PATH, "utf8")
		.split("\n")
		.filter((l) => l.startsWith("# handle: "))
		.map((l) => l.slice(10).trim())
		.filter(Boolean);
}

export function setHandle(name: string) {
	if (!hasIdentity() || handles().includes(name)) return;
	const lines = readFileSync(IDENTITY_PATH, "utf8").split("\n");
	const at = lines.findIndex((l) => l.startsWith("# fingerprint: "));
	lines.splice(at < 0 ? lines.length : at, 0, `# handle: ${name}`);
	writeFileSync(IDENTITY_PATH, lines.join("\n"));
	chmodSync(IDENTITY_PATH, 0o600);
}

export const ownRevocation = () =>
	existsSync(OWN_REVOCATION_PATH)
		? readFileSync(OWN_REVOCATION_PATH, "utf8")
		: "";

export function writeOwnRevocation(
	key: Uint8Array,
	reason: string,
	sig: Uint8Array,
) {
	mkdirSync(CONFIG_DIR, { recursive: true });
	writeFileSync(OWN_REVOCATION_PATH, armorRevocation(key, reason, sig));
	writeFileSync(
		REVOKED_PATH,
		(existsSync(REVOKED_PATH) ? readFileSync(REVOKED_PATH, "utf8") : "") +
			armorRevocation(key, reason, sig),
	);
}

export const ownRotations = () =>
	existsSync(ROTATION_PATH) ? readFileSync(ROTATION_PATH, "utf8") : "";

export function addOwnRotation(
	from: Uint8Array,
	to: Uint8Array,
	sig: Uint8Array,
) {
	mkdirSync(CONFIG_DIR, { recursive: true });
	writeFileSync(ROTATION_PATH, ownRotations() + armorRotation(from, to, sig));
}

export const cleanReason = (reason: string) =>
	[...reason]
		.map((c) => (c.charCodeAt(0) < 0x20 || c.charCodeAt(0) === 0x7f ? " " : c))
		.join("")
		.trim()
		.slice(0, 200);

const LOCAL = /^(localhost|127\.0\.0\.1|\[::1\])(:[0-9]+)?$/;

export const httpBase = (host: string) =>
	LOCAL.test(host) ? `http://${host}` : `https://${host}`;

export async function publishName(
	name: string,
	key: Uint8Array,
	sig: Uint8Array,
	rotation?: Uint8Array,
) {
	const lines = [encodeKey(key), Buffer.from(sig).toString("base64")];
	if (rotation) lines.push(Buffer.from(rotation).toString("base64"));
	const res = await fetch(`${KEYSERVER}/u/${name}`, {
		method: "PUT",
		body: lines.join("\n"),
	});
	if (res.status === 409)
		throw new Error(`"${name}" is already taken by a different key`);
	if (!res.ok)
		throw new Error(
			`keyserver rejected the claim: ${res.status} ${await res.text()}`,
		);
}

export async function publishRevocation(
	key: Uint8Array,
	sig: Uint8Array,
	reason: string,
) {
	const res = await fetch(`${KEYSERVER}/revoke`, {
		method: "PUT",
		body: [encodeKey(key), Buffer.from(sig).toString("base64"), reason].join(
			"\n",
		),
	});
	if (!res.ok)
		throw new Error(
			`keyserver rejected the revocation: ${res.status} ${await res.text()}`,
		);
}

const sameKey = (a: Uint8Array, b: Uint8Array) =>
	a.length === b.length && a.every((v, i) => v === b[i]);

const readRevocations = () =>
	existsSync(REVOKED_PATH)
		? parseRevocations(readFileSync(REVOKED_PATH, "utf8"))
		: [];

export function learnRevocations(text: string, key: Uint8Array) {
	for (const r of parseRevocations(text)) {
		if (!sameKey(r.key, key) || !verifyRevocation(r.key, r.reason, r.sig))
			continue;
		if (revocationOf(key)) return r;
		mkdirSync(CONFIG_DIR, { recursive: true });
		writeFileSync(
			REVOKED_PATH,
			(existsSync(REVOKED_PATH) ? readFileSync(REVOKED_PATH, "utf8") : "") +
				armorRevocation(r.key, r.reason, r.sig),
		);
		return r;
	}
	return null;
}

export const revocationOf = (key: Uint8Array) =>
	readRevocations().find((r) => sameKey(r.key, key)) ?? null;

export const revokedNote = (key: Uint8Array) => {
	const rev = revocationOf(key);
	if (!rev) return null;
	const why = cleanReason(rev.reason);
	return `that key was revoked by its owner${why ? `: ${why}` : ""}`;
};

const MAX_KEY_BODY = 1 << 20;
const FETCH_TIMEOUT = 10_000;
const PRIVATE_HOST =
	/^(localhost|127\.|0\.|10\.|169\.254\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|\[?::1\]?)/i;

async function readCapped(res: Response, url: string) {
	const declared = Number(res.headers.get("content-length") ?? 0);
	if (declared > MAX_KEY_BODY)
		throw new Error(`the key served at ${url} is absurdly large`);
	const reader = res.body?.getReader();
	if (!reader) return "";
	const parts: Uint8Array[] = [];
	let size = 0;
	while (true) {
		const { done, value } = await reader.read();
		if (done) break;
		size += value.length;
		if (size > MAX_KEY_BODY) {
			await reader.cancel();
			throw new Error(`the key served at ${url} is absurdly large`);
		}
		parts.push(value);
	}
	return new TextDecoder().decode(concatBytes(...parts));
}

export async function fetchKey(url: string, source: string) {
	let at = url;
	let res: Response | null = null;
	for (let hop = 0; hop < 4; hop++) {
		res = await fetch(at, {
			redirect: "manual",
			signal: AbortSignal.timeout(FETCH_TIMEOUT),
			headers: { accept: "text/plain, */*" },
		}).catch(() => null);
		const next = res?.headers.get("location");
		if (!res || res.status < 300 || res.status >= 400 || !next) break;
		at = new URL(next, at).toString();
		const host = new URL(at).hostname;
		if (PRIVATE_HOST.test(host) && !PRIVATE_HOST.test(new URL(url).hostname))
			throw new Error(
				`${source} redirected to ${host}, which is on your own network`,
			);
	}
	if (!res?.ok)
		throw new Error(
			`could not fetch a key for ${source}${res ? ` (http ${res.status})` : " (unreachable)"}`,
		);
	const text = await readCapped(res, at);
	const str = extractBundleString(text);
	if (!str) throw new Error(`no np key found at ${url}`);
	const key = decodeKey(str);
	if (
		!parseAliases(text).some(
			(a) => a.name === source && verifyClaim(key, source, a.sig),
		)
	)
		throw new Error(
			`the key served for ${source} does not claim that name, so it may be someone else's key re-hosted`,
		);
	learnRevocations(text, key);
	return { key, text };
}

export function urlFor(name: string) {
	if (/^https?:\/\//i.test(name)) return name;
	if (name.includes(".")) return `${httpBase(name)}/.well-known/np`;
	if (USERNAME_RE.test(name)) return `${KEYSERVER}/u/${name}`;
	return null;
}

type Contacts = Map<string, Uint8Array>;

export function loadContacts(): Contacts {
	const out: Contacts = new Map();
	if (!existsSync(CONTACTS_PATH)) return out;
	for (const line of readFileSync(CONTACTS_PATH, "utf8").split("\n")) {
		const [name, key] = line.trim().split(/\s+/);
		if (!name || !key?.startsWith("npkey1")) continue;
		try {
			out.set(name.toLowerCase(), decodeKey(key));
		} catch {}
	}
	return out;
}

function writeContacts(contacts: Contacts) {
	mkdirSync(CONFIG_DIR, { recursive: true });
	const lines = [...contacts].map(([n, k]) => `${n} ${encodeKey(k)}`);
	writeFileSync(CONTACTS_PATH, `${lines.join("\n")}\n`);
}

export function saveContact(name: string, key: Uint8Array) {
	const id = checkContactName(name).toLowerCase();
	const contacts = loadContacts();
	contacts.set(id, key);
	writeContacts(contacts);
}

export function removeContact(name: string) {
	const contacts = loadContacts();
	if (!contacts.delete(name.toLowerCase())) return false;
	writeContacts(contacts);
	return true;
}

export function nameFor(key: Uint8Array, contacts: Contacts) {
	for (const [name, k] of contacts) if (sameKey(k, key)) return name;
	return null;
}

export function nameForSigner(signKey: Uint8Array, contacts: Contacts) {
	for (const [name, k] of contacts)
		if (sameKey(signerKey(k), signKey)) return name;
	return null;
}

export async function provenRotation(
	text: string,
	pinned: Uint8Array,
	served: Uint8Array,
) {
	const certs = parseRotations(text);
	let current = pinned;
	for (let hop = 0; hop < 8 && !sameKey(current, served); hop++) {
		if (revocationOf(current)) return false;
		const cert = certs.find((c) => sameKey(c.from, current));
		if (!cert || !verifyRotation(cert.from, cert.to, cert.sig)) return false;
		current = cert.to;
	}
	return sameKey(current, served) && !revocationOf(served);
}

export async function resolveRecipient(
	input: string,
	contacts: Contacts,
	opts: { refresh?: boolean; acceptNew?: boolean } = {},
): Promise<Uint8Array> {
	const s = input.trim();
	if (s.toLowerCase().startsWith("npkey1") || s.startsWith(PUB_BEGIN)) {
		const key = decodeKey(extractBundleString(s) ?? s);
		learnRevocations(s, key);
		return key;
	}
	const fromFile = (path: string) => {
		const text = readFileSync(path, "utf8");
		const str = extractBundleString(text);
		if (!str) throw new Error(`no np key found in file ${path}`);
		const key = decodeKey(str);
		learnRevocations(text, key);
		return key;
	};
	const spelledAsPath =
		!/^https?:\/\//i.test(s) && (/[/\\]/.test(s) || s.startsWith("~"));
	if (spelledAsPath) {
		if (!existsSync(s)) throw new Error(`no such file: ${s}`);
		return fromFile(s);
	}
	const name = s.toLowerCase();
	const pinned = contacts.get(name);
	if (pinned && !opts.refresh) return pinned;
	if (!pinned && existsSync(s)) return fromFile(s);
	const url = urlFor(name);
	if (!url) {
		if (pinned) return pinned;
		throw new Error(
			`unknown recipient "${s}" (not a key, a contact, a domain, a username, or a key file)`,
		);
	}
	const { key, text } = await fetchKey(url, name);
	if (
		pinned &&
		!sameKey(pinned, key) &&
		!opts.acceptNew &&
		!(await provenRotation(text, pinned, key))
	)
		throw new Error(
			`KEY CHANGED for ${name}!\n  pinned: ${fingerprint(pinned)}\n  served: ${fingerprint(key)}\n  no rotation certificate signed by the pinned key.\n  if you trust this change anyway: np contacts add ${name} --accept-new-key`,
		);
	saveContact(name, key);
	return key;
}
