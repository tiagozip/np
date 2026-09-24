import { createCipheriv, createDecipheriv } from "node:crypto";

type Chacha = typeof import("@noble/ciphers/chacha.js");
const xchacha = () =>
	(require("@noble/ciphers/chacha.js") as Chacha).xchacha20poly1305;

export const CHUNK = 65536;
export const SEALED = CHUNK + 16;
export const TAG = 16;

export type Version = 1 | 2 | 3 | 4;

export const MAX_CHUNKS = 2 ** 32;

function nonce(counter: number, final: boolean, v: Version) {
	if (counter >= MAX_CHUNKS)
		throw new Error(
			"stream is longer than 256 TiB, which would reuse a chunk nonce",
		);
	const n = new Uint8Array(v === 1 ? 24 : 12);
	new DataView(n.buffer).setUint32(v === 1 ? 19 : 7, counter);
	n[n.length - 1] = final ? 1 : 0;
	return n;
}

export function sealChunk(
	key: Uint8Array,
	i: number,
	final: boolean,
	data: Uint8Array,
	v: Version = 2,
) {
	if (v === 1) return xchacha()(key, nonce(i, final, 1)).encrypt(data);
	const c = createCipheriv("aes-256-gcm", key, nonce(i, final, 2));
	const body = c.update(data);
	c.final();
	const out = new Uint8Array(body.length + TAG);
	out.set(body);
	out.set(c.getAuthTag(), body.length);
	return out;
}

export function openChunk(
	key: Uint8Array,
	i: number,
	final: boolean,
	data: Uint8Array,
	v: Version = 2,
) {
	if (v === 1) return xchacha()(key, nonce(i, final, 1)).decrypt(data);
	if (data.length < TAG) throw new Error("chunk is too short to be sealed");
	const d = createDecipheriv("aes-256-gcm", key, nonce(i, final, 2));
	d.setAuthTag(data.subarray(data.length - TAG));
	const body = d.update(data.subarray(0, data.length - TAG));
	d.final();
	return new Uint8Array(body.buffer, body.byteOffset, body.byteLength);
}

export function runChunks(
	mode: "seal" | "open",
	key: Uint8Array,
	index: number,
	final: boolean,
	data: Uint8Array,
	v: Version = 2,
) {
	const unit = mode === "seal" ? CHUNK : SEALED;
	const n = Math.max(1, Math.ceil(data.length / unit));
	const out = new Uint8Array(
		mode === "seal" ? data.length + TAG * n : data.length - TAG * n,
	);
	let off = 0;
	for (let i = 0; i < n; i++) {
		const part = data.subarray(i * unit, Math.min((i + 1) * unit, data.length));
		const last = final && i === n - 1;
		const piece =
			mode === "seal"
				? sealChunk(key, index + i, last, part, v)
				: openChunk(key, index + i, last, part, v);
		out.set(piece, off);
		off += piece.length;
	}
	return out.subarray(0, off);
}
