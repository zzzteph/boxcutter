# crack-js — hash cracking inside boxcutter

[crack-js](https://github.com/zzzteph/crack-js) is a pure-JavaScript, hashcat-mode hash library
(verify / identify / generate / benchmark, ~330 hash modes, only dependency `crypto-js`). boxcutter's
**full** image ships it as a Node library at `/usr/share/crack-js` plus a thin CLI wrapper so an operator can
crack a **recovered** hash — a SQLi credential dump, a leaked `shadow`/`.htpasswd` line, an HS256 JWT secret
guess — against the on-disk password wordlists and feed the plaintext into a credential-reuse chain.

## The CLI wrapper (what you normally use)

crack-js has no CLI of its own; boxcutter adds one at `docker/crack.js` → `/usr/share/crack-js/crack.js`.

```sh
node /usr/share/crack-js/crack.js <hash> <wordlist-file> [mode]
```

- `hash` — the hash string to crack.
- `wordlist-file` — a path that exists on disk. The shipped password lists:
  - `/opt/boxcutter/boxcutter/data/passwords_10k.txt` — ignis 10k, fast first pass.
  - `/opt/boxcutter/boxcutter/data/passwords.txt` — hashmob 2025, broad but slower.
- `mode` *(optional)* — a hashcat **mode number** (`0`=MD5, `100`=SHA1, `1400`=SHA256, `1000`=NTLM,
  `3200`=bcrypt, …) **or** a name (`md5`, `ntlm`, `bcrypt`). **Omit it** to auto-detect candidate types from
  the hash shape and try each.

It streams the wordlist (a multi-GB file is fine — it is not loaded into memory) and prints exactly one JSON
line:

```json
{"cracked":true,"hash":"5d41402abc4b2a76b9719d911017c592","mode":0,"plaintext":"hello"}
```

Exit codes: `0` cracked, `1` wordlist exhausted (no match), `2` bad usage / missing file, `3` runtime error.

### Examples

```sh
# MD5, let it auto-detect the mode
node /usr/share/crack-js/crack.js 5d41402abc4b2a76b9719d911017c592 \
     /opt/boxcutter/boxcutter/data/passwords_10k.txt

# bcrypt (mode must be given — bcrypt is not guessable from length alone)
node /usr/share/crack-js/crack.js '$2b$12$....' \
     /opt/boxcutter/boxcutter/data/passwords.txt 3200

# NTLM by name
node /usr/share/crack-js/crack.js 8846f7eaee8fb117ad06bdd830b7586c \
     /opt/boxcutter/boxcutter/data/passwords_10k.txt ntlm
```

From a joseph run this is the natural next hop after a SQLi dump: `write_script` a shell script that pipes each
dumped hash through the wrapper, then reuse any recovered plaintext to log in.

## The library API (if you script against it directly)

`require('crack-js')` resolves from any Node script because the image sets
`NODE_PATH=/usr/share/crack-js/node_modules`.

```js
const crack = require('crack-js');

// in-memory wordlist — returns the matched plaintext, or null. Synchronous.
crack.crackWordlist('5d41402abc4b2a76b9719d911017c592', 0, ['hello', 'world']); // 'hello'

// identify candidate types from the hash shape
crack.getPossibleHashTypes(hash);        // ['md5', 'ntlm', ...]

// verify one guess; mode by number or name
crack.verifyHash('hello', hash, 0);      // true / false
crack.verifyHash('hello', hash, 'md5');

// generate (for building your own comparisons)
crack.generateHash(0, 'hello');          // mode 0 = MD5

// file-backed, memory-safe streaming (what the wrapper uses)
const fs = require('fs');
const { streamShardLines } = require('crack-js/src/wordlist-fs');
const size = fs.statSync(file).size;
for await (const word of streamShardLines(file, 0, size))
  if (crack.verifyHash(word, hash, mode)) { /* found */ }
```

## How it is built into the image

`Dockerfile` (full stage): `apk add nodejs npm`, `npm install crack-js` into `/usr/share/crack-js`, `COPY`
the wrapper, and `ENV NODE_PATH=…/node_modules`. node exists **only** in the full image (the one
`podman run boxcutter …` uses), not the lean base engine.
