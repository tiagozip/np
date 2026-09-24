#!/usr/bin/env bun
import type { Opts } from "./run.ts";
import { HELP, red, VERSION } from "./ui.ts";

const die = (msg: string): never => {
	console.error(red(`error: ${msg}`));
	process.exit(1);
};

const argv = process.argv.slice(2);
const opts: Opts = {
	recipients: [],
	noSelf: false,
	acceptNew: false,
	noSign: false,
};
const positional: string[] = [];

for (let i = 0; i < argv.length; i++) {
	const a = argv[i] as string;
	if (a === "-to" || a === "--to")
		opts.recipients.push(argv[++i] ?? die("missing recipient after -to"));
	else if (a === "-o" || a === "--out")
		opts.out = argv[++i] ?? die("missing path after -o");
	else if (a === "--no-self") opts.noSelf = true;
	else if (a === "--accept-new-key") opts.acceptNew = true;
	else if (a === "--no-sign") opts.noSign = true;
	else if (a === "-h" || a === "--help") {
		console.log(HELP);
		process.exit(0);
	} else if (a === "-v" || a === "--version") {
		console.log(`np ${VERSION}`);
		process.exit(0);
	} else if (a === "-s" || a === "--sign")
		die(
			"np signs inside the encryption by default now, --no-sign turns it off",
		);
	else if (a === "-e" || a === "--encrypt")
		die('np uses -to for recipients now, as in: np "msg" -to alice');
	else if (a.startsWith("-") && a !== "-" && !a.startsWith("-----"))
		die(`unknown flag ${a}`);
	else positional.push(a);
}

const cmd = positional[0];
if (cmd === "version") console.log(`np ${VERSION}`);
else if (cmd === "help" || (cmd === undefined && process.stdin.isTTY))
	console.log(HELP);
else
	import("./run.ts").then(
		(m) => m.run(positional, opts),
		(e: Error) => die(e.message),
	);
