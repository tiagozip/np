# np, nicer privacy

a mix of minisign and age as one really simple cli. post-quantum, with usernames and domains as keys, and without passphrases or keyrings to manage.

```sh
bun install -g @tiagozip/np
np key new # create your first key
np "hello" # sign something
```

## signing and encrypting

```console
~ np contacts add bob.pub bob
✓ added bob 7or3-zihe-a77r-c3yq

~ np "hi bob" note.np -to bob
✓ encrypted to note.np
```

```console
~ np contacts add alice.pub alice
✓ added alice w3vd-5aaz-3yth-ub3v

~ np note.np
hi bob
✓ good signature from alice
```

use `-to` to encrypt something instead of just signing it. by default, everything you encrypt is signed too, so the person opening it finds out who sent it. if you'd rather stay anonymous, use `--no-sign`.

run `np <file>` to sign a file, and again to verify it once it has a signature.

your secret key can't be recovered if you lose it. please run `np key secret` and back up the output somewhere safe.

## usernames and domains

`np key new` asks how people should reach you, and you pick a username on the keyserver or a domain you own. Either way people encrypt to you by name and never paste a key.

```console
~ np "hi" -to tiago.zip # reads https://tiago.zip/.well-known/np
~ np "hi" -to meow      # reads https://np.tiago.zip/u/meow
```

np remembers the key the first time it fetches one, and refuses to send to a different key later unless the owner signed the change.

## performance

200 MB on M3, signing and verifying included:

|         | np     | age    | minisign |
| ------- | ------ | ------ | -------- |
| encrypt | 235 ms | 264 ms |          |
| decrypt | 213 ms | 266 ms |          |
| sign    | 111 ms |        | 209 ms   |
| verify  | 82 ms  |        | 216 ms   |

## license

AGPL-3.0-only, in [LICENSE](LICENSE).
