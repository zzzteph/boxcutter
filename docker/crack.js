#!/usr/bin/env node
// Thin CLI over crack-js (https://github.com/zzzteph/crack-js) so an operator (a joseph script, a shell
// one-liner) can crack a RECOVERED hash - a SQLi credential dump, a leaked shadow/htpasswd line, an HS256 JWT
// secret guess - against a wordlist FILE and feed the plaintext into a credential-reuse chain. crack-js is a
// pure-JS library (no CLI of its own); this wrapper is the missing command line.
//
//   node /usr/share/crack-js/crack.js <hash> <wordlist-file> [mode]
//
// mode is a hashcat mode NUMBER (0=MD5, 100=SHA1, 1400=SHA256, 1000=NTLM, 3200=bcrypt, ...) or a NAME
// ('md5','ntlm','bcrypt'). Omit it to auto-detect candidate types from the hash shape and try each.
// Prints one JSON line: {"cracked":true,"plaintext":"...","mode":...} on success (exit 0),
// {"cracked":false,...} if the wordlist is exhausted (exit 1). Streams the file, so a multi-GB list is fine.
'use strict';

const fs = require('fs');
const crack = require('crack-js');
const { streamShardLines } = require('crack-js/src/wordlist-fs');

async function main() {
  const [hash, wordlist, modeArg] = process.argv.slice(2);
  if (!hash || !wordlist) {
    console.error('usage: node crack.js <hash> <wordlist-file> [hashcat-mode-number|name]');
    process.exit(2);
  }
  if (!fs.existsSync(wordlist)) {
    console.error('crack-js :: no such wordlist file: ' + wordlist);
    process.exit(2);
  }

  let modes;
  if (modeArg !== undefined && modeArg !== '') {
    modes = [/^\d+$/.test(modeArg) ? parseInt(modeArg, 10) : modeArg];
  } else {
    modes = crack.getPossibleHashTypes(hash) || [];
    if (!modes.length) modes = ['md5', 'sha1', 'sha256', 'ntlm'];  // fall back to the common shapes
    console.error('crack-js :: no mode given; trying candidate type(s): ' + modes.join(', '));
  }

  const size = fs.statSync(wordlist).size;
  for (const mode of modes) {
    for await (const word of streamShardLines(wordlist, 0, size)) {
      if (crack.verifyHash(word, hash, mode)) {
        console.log(JSON.stringify({ cracked: true, hash, mode, plaintext: word }));
        process.exit(0);
      }
    }
  }
  console.log(JSON.stringify({ cracked: false, hash, modes_tried: modes }));
  process.exit(1);
}

main().catch((e) => {
  console.error('crack-js :: error: ' + ((e && e.message) || e));
  process.exit(3);
});
