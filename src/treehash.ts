import { closeSync, openSync, read } from "node:fs";
import { LANES, pool } from "./pool.ts";

export const BLOCK = 8 * 1024 * 1024;
const READ = 4 * 1024 * 1024;
const DEPTH = 3;
export const TREE_ALG = "tree512-8m";

const LEAF_CTX = "np/v2/leaf";
const ROOT_CTX = "np/v2/root";

const counter = (n: number) => {
	const b = new Uint8Array(8);
	new DataView(b.buffer).setBigUint64(0, BigInt(n));
	return b;
};

export const leafOf = (index: number, bytes: ArrayBuffer | Uint8Array) => {
	const h = new Bun.CryptoHasher("sha512");
	h.update(LEAF_CTX);
	h.update(counter(index));
	h.update(bytes);
	return new Uint8Array(h.digest().buffer);
};

const blockOf = (path: string, index: number) => {
	const file = Bun.file(path);
	const from = index * BLOCK;
	return file.slice(from, Math.min(from + BLOCK, file.size)).arrayBuffer();
};

export const leafDigest = async (path: string, index: number) =>
	leafOf(index, await blockOf(path, index));

export const rootOf = (leaves: Uint8Array[]) => {
	const h = new Bun.CryptoHasher("sha512");
	h.update(ROOT_CTX);
	h.update(counter(leaves.length));
	for (const leaf of leaves) h.update(leaf);
	return new Uint8Array(h.digest().buffer);
};

const newLeaf = (index: number) => {
	const h = new Bun.CryptoHasher("sha512");
	h.update(LEAF_CTX);
	h.update(counter(index));
	return h;
};

export function treeHasher() {
	const leaves: Uint8Array[] = [];
	let index = 0;
	let filled = 0;
	let h = newLeaf(0);
	return {
		update(bytes: Uint8Array) {
			let off = 0;
			while (off < bytes.length) {
				const take = Math.min(bytes.length - off, BLOCK - filled);
				h.update(bytes.subarray(off, off + take));
				off += take;
				filled += take;
				if (filled < BLOCK) continue;
				leaves.push(new Uint8Array(h.digest().buffer));
				h = newLeaf(++index);
				filled = 0;
			}
		},
		root() {
			if (filled > 0 || !leaves.length)
				leaves.push(new Uint8Array(h.digest().buffer));
			return rootOf(leaves);
		},
	};
}

export async function treeHashFile(path: string) {
	const size = Bun.file(path).size;
	const blocks = Math.max(1, Math.ceil(size / BLOCK));
	const lanes = Math.min(blocks, LANES);
	if (lanes < 2) {
		const fd = openSync(path, "r");
		const free: Buffer[] = [];
		const queue: { buf: Buffer; read: Promise<number> }[] = [];
		let nextAt = 0;
		const pump = () => {
			while (queue.length < DEPTH && nextAt < size) {
				const buf = free.pop() ?? Buffer.allocUnsafe(READ);
				const len = Math.min(READ, size - nextAt);
				const at = nextAt;
				queue.push({
					buf,
					read: new Promise<number>((resolve, reject) =>
						read(fd, buf, 0, len, at, (err, bytesRead) =>
							err ? reject(err) : resolve(bytesRead),
						),
					),
				});
				nextAt += len;
			}
		};
		const leaves: Uint8Array[] = [];
		try {
			pump();
			let index = 0;
			let filled = 0;
			let h = newLeaf(0);
			while (queue.length) {
				const job = queue.shift() as (typeof queue)[number];
				const bytesRead = await job.read;
				pump();
				let off = 0;
				while (off < bytesRead) {
					const take = Math.min(bytesRead - off, BLOCK - filled);
					h.update(job.buf.subarray(off, off + take));
					off += take;
					filled += take;
					if (filled === BLOCK) {
						leaves.push(new Uint8Array(h.digest().buffer));
						h = newLeaf(++index);
						filled = 0;
					}
				}
				free.push(job.buf);
			}
			if (filled > 0 || !leaves.length)
				leaves.push(new Uint8Array(h.digest().buffer));
		} finally {
			closeSync(fd);
		}
		return rootOf(leaves);
	}

	const leaves: Uint8Array[] = new Array(blocks);
	const jobs = pool(blocks);
	try {
		for (let at = 0; at < blocks; at += jobs.lanes)
			for (const r of await jobs.wave(at, (index) => ({
				op: "leaf",
				path,
				index,
			})))
				leaves[r.index] = new Uint8Array(r.digest);
	} finally {
		jobs.close();
	}
	return rootOf(leaves);
}
