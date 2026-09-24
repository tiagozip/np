import { CHUNK, runChunks, SEALED, type Version } from "./stream.ts";
import { BLOCK, leafDigest, leafOf } from "./treehash.ts";

declare const self: Worker;

const slice = async (path: string, from: number, to: number) =>
	new Uint8Array(await Bun.file(path).slice(from, to).arrayBuffer());

self.onmessage = async (e: MessageEvent) => {
	const { op, path, index } = e.data;
	try {
		if (op === "leaf") {
			const digest = await leafDigest(path, index);
			return self.postMessage(
				{ index, digest: digest.buffer },
				{ transfer: [digest.buffer] },
			);
		}
		const {
			key,
			size,
			real,
			plain,
			trailerAt,
			trailer,
			offset,
			final,
			version,
		} = e.data as {
			key: Uint8Array;
			size: number;
			real?: number;
			plain?: number;
			trailerAt?: number;
			trailer?: Uint8Array;
			offset: number;
			final: boolean;
			version: Version;
		};
		const unit = op === "seal" ? CHUNK : SEALED;
		const span = (BLOCK / CHUNK) * unit;
		const from = offset + index * span;
		const to = Math.min(from + span, size);
		const read = await slice(path, from, Math.min(to, real ?? size));
		const data =
			read.length === to - from && !trailer?.length
				? read
				: (() => {
						const buf = new Uint8Array(to - from);
						buf.set(read);
						const base = trailerAt ?? real ?? size;
						for (let i = 0; i < (trailer?.length ?? 0); i++) {
							const at = base + i - from;
							if (at >= 0 && at < buf.length)
								buf[at] = (trailer as Uint8Array)[i] as number;
						}
						return buf;
					})();
		const out = runChunks(
			op,
			key,
			index * (BLOCK / CHUNK),
			final,
			data,
			version,
		);
		const copy = out.slice();
		const plainAt = index * BLOCK;
		const covered = op === "open" && plain !== undefined && plainAt < plain;
		const leaf = covered
			? leafOf(index, copy.subarray(0, Math.min(BLOCK, plain - plainAt)))
			: null;
		self.postMessage(
			{ index, data: copy.buffer, leaf: leaf?.buffer ?? null },
			{ transfer: leaf ? [copy.buffer, leaf.buffer] : [copy.buffer] },
		);
	} catch (err) {
		self.postMessage({ index, error: (err as Error).message });
	}
};
