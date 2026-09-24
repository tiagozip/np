import { loadavg } from "node:os";

const cores = Math.max(1, navigator.hardwareConcurrency);

export const LANES = (() => {
	const forced = Number(process.env.NP_LANES);
	if (forced) return Math.max(1, Math.min(forced, cores));
	return (loadavg()[0] ?? 0) / cores > 0.6 ? 1 : Math.min(8, cores);
})();

type Job = Record<string, unknown>;

export function pool(count: number) {
	const lanes = Math.min(count, LANES);
	const workers = Array.from(
		{ length: lanes },
		() =>
			new Worker(new URL("./file-worker.js", import.meta.url), {
				type: "module",
			}),
	);
	const call = (w: Worker, job: Job) =>
		new Promise<MessageEvent["data"]>((resolve, reject) => {
			w.onmessage = (e: MessageEvent) =>
				e.data.error ? reject(new Error(e.data.error)) : resolve(e.data);
			w.onerror = (e: ErrorEvent) =>
				reject(new Error(e.message ?? "worker failed"));
			w.postMessage(job);
		});
	return {
		lanes,
		async wave(from: number, make: (index: number) => Job) {
			const jobs: Promise<MessageEvent["data"]>[] = [];
			for (let i = 0; i < lanes && from + i < count; i++)
				jobs.push(call(workers[i] as Worker, make(from + i)));
			return Promise.all(jobs);
		},
		close() {
			for (const w of workers) w.terminate();
		},
	};
}
