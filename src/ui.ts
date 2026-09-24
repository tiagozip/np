export const VERSION = "0.1.0";

const fg = (r: number, g: number, b: number) => (s: string) =>
	`\x1b[38;2;${r};${g};${b}m${s}\x1b[0m`;

export const red = (s: string) => `\x1b[31m${s}\x1b[0m`;
export const green = (s: string) => `\x1b[32m${s}\x1b[0m`;
export const yellow = (s: string) => `\x1b[33m${s}\x1b[0m`;
export const cyan = (s: string) => `\x1b[36m${s}\x1b[0m`;
export const dim = (s: string) => `\x1b[2m${s}\x1b[0m`;
export const bold = (s: string) => `\x1b[1m${s}\x1b[0m`;

export const pink = fg(255, 143, 214);
export const orchid = fg(213, 143, 255);
export const violet = fg(157, 152, 255);
export const sky = fg(133, 190, 255);

export const LOGO = [
	pink("  ╭─╮╭─╮"),
	`${orchid("  │ ││ │")}   ${bold(pink("np"))}${dim(", nicer privacy")}  ${orchid("ᓚ₍^. ̫.^₎")}`,
	`${violet("  ╵ ╵├─╯")}   ${dim("post-quantum signatures + encryption")}`,
	sky("     ╵"),
].join("\n");

const row = (usage: string, desc: string) =>
	`  ${cyan(usage.padEnd(36))}${dim(desc)}`;

export const HELP = [
	LOGO,
	"",
	pink("  your key"),
	row("np key new", "create your identity (guided setup)"),
	row("np key", "print your key"),
	row("np key secret", "print your secret key, back it up"),
	row("np key rotate|revoke|clear", "replace, retire or delete it"),
	row("np publish [name]", "publish, claim a username, or serve a domain"),
	"",
	pink("  other people"),
	row("np contacts", "list the keys you trust"),
	row("np contacts add <key|domain|file>", "trust one, optionally [as name]"),
	row("np contacts rm|rename <name>", "drop or rename one"),
	"",
	pink("  do things"),
	row('np "some message"', "sign a message (armored, to stdout)"),
	row('np "msg" note.np', "or write it somewhere"),
	row("np file.txt", "sign a file -> file.txt.npsig"),
	row('np "msg" -to <contact>', "sign and encrypt (repeat -to for more)"),
	row("np file.txt -to alice", "sign and encrypt -> file.txt.np"),
	row("tar c dir | np - -to alice -o d.np", "stream a pipe in or out"),
	row("np <anything np made>", "auto: decrypt or verify"),
	row("np decrypt|verify|sign|encrypt", "explicit forms of the above"),
	row("np version", "what you're running"),
	"",
	pink("  flags"),
	row("-to <recipient>", "who can open it, repeatable"),
	row("-o, --out <path>", "same as the second argument, - for stdout"),
	row("--no-sign", "encrypt without signing"),
	row("--no-self", "don't add yourself as a recipient"),
	row("--accept-new-key", "allow a pinned name to change key"),
	"",
	pink("  environment"),
	row("NP_CONFIG_DIR", "where your key and contacts live"),
	row("NP_KEYSERVER", "where usernames resolve"),
	"",
	dim(
		"  hybrid post-quantum: ml-kem-768 + x25519 for encryption, falcon-512 +",
	),
	dim("  ed25519 for signatures, aes-256-gcm for payloads."),
].join("\n");
