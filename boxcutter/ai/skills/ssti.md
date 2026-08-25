# Server-side template injection (SSTI)

**Trigger:** a server-side template engine is in play (Jinja2/Twig/Freemarker/Velocity/Smarty/Thymeleaf/Mako fingerprinted) AND user input reaches a rendered template - a name/subject/message/label reflected into a server-rendered page or email.

**Action:**
- Send a math probe unique to templates, not HTML: `${7*7}`, `{{7*7}}`, `#{7*7}`, `<%= 7*7 %>`. A response containing the PRODUCT (`49`), not your literal, = evaluation.
- Confirm with a random product each time (e.g. `{{31*29}}` -> `899`) so a coincidental `49` on the page never fools you - the `fuzz` tool already does this two-shot confirmation.
- Identify the engine from which syntax evaluates, then escalate to command execution with the engine-specific gadget (Jinja `{{config.__class__...}}` / `cycler`, Twig `_self`, Freemarker `Execute`).

**Confirm:** the arithmetic evaluates server-side = SSTI; reaching OS command execution is critical. A reflection that does NOT evaluate the math is just XSS-surface, not SSTI.
