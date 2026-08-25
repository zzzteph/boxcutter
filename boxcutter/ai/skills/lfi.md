# Path traversal / local file inclusion

**Trigger:** a param names a file or path the server reads - `file`/`path`/`doc`/`template`/`page`/`include`/`download`/`view`/`dir`/`report`, or a download/preview/export feature.

**Action:**
- Traverse to a known file: `../../../../etc/passwd`, `..\..\..\windows\win.ini`. Contents back = traversal.
- Bypasses: URL-/double-encoding (`%2e%2e%2f`, `%252e`), a null byte, an absolute path (`/etc/passwd`), nested traversal (`....//`), or a leading legitimate prefix the filter expects.
- If the file is INCLUDED (not just read), escalate to LFI->RCE: log poisoning, `php://filter` to read source, session files, or `/proc/self/environ`.
- Try writing/overwriting via a traversal in an upload filename.

**Confirm:** contents of a file outside the intended directory (a system file, app source, a config with secrets) = path traversal; execution via inclusion is critical.
