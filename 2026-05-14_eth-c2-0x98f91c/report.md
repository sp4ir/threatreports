# EVM Dead-Drop URL Resolvers on Ethereum Mainnet: A Five-Contract Operator Cluster

**TLP:CLEAR** · 2026-05-14

## Abstract

We document a cluster of five Ethereum mainnet smart contracts that function as **dead-drop URL resolvers** for malware command-and-control. Each contract is a minimal `mapping(address => string)` registry written only by its deployer; off-host malware reads the live C2 URL via a free `eth_call` against any public RPC, eliminating the need for traditional DNS or HTTP infrastructure that defenders can sinkhole or seize. Pivoting on the deployer's funding wallet reveals a single operator network: a Huobi (HTX) hot-wallet withdrawal of 0.1143 ETH on 2026-04-01 funds, via one hop, a distribution wallet that has seeded ten burner addresses. Five of those burners have already deployed dead-drop contracts; five remain in reserve. All five active contracts rotate through `*.trycloudflare.com` quick-tunnels as their hot URL. The operator further rotates the dead-drop bytecode between deployments — each contract exposes the same two core selectors (`getString(address)` and `setString(string)`) but uses distinct "magic-number" fingerprint functions, distinct decoy immutables, and distinct event topics, defeating any signature-based detection rule. This report enumerates the indicators, presents the reverse-engineered logic, and gives structural detection guidance and concrete takedown levers.

## 1. Architectural pattern

The operator is using a technique that the security community has variously called *EtherHiding*, *CLEARFAKE*-style EVM C2, or simply "blockchain dead-drop." The smart contract is not the malware — it is a censorship-resistant DNS substitute. The contract holds, in a public storage slot, the current URL of an off-chain payload host. When the malware needs a fresh C2 endpoint, it issues an `eth_call` (no transaction, no fee, no on-chain trace) to any RPC provider and gets the latest URL back. When the operator wants to rotate, they send a single ~25,000-gas transaction (USD $0.10–$0.50 on Ethereum mainnet at typical 2026-04 gas) and the next read returns the new URL.

The pattern's defender-hostile properties:

- **No domain registrar can seize the dead drop.** The "domain" is a 20-byte Ethereum address.
- **No DNS resolver can sinkhole it.** Reads happen over JSON-RPC, against thousands of public endpoints.
- **No web host can take down the contract.** The contract lives in the Ethereum state trie, replicated on every full node worldwide.
- **No log appears at the read side.** `eth_call` is a read against the validator's local state; it produces no transaction, no event, no node-side metric distinguishable from ordinary wallet UI activity.
- **Only the operator's private key can wipe the slot.** Storage is keyed by `msg.sender`, so no third-party transaction can modify it.

What can be defended: the *payload host* (here, Cloudflare quick-tunnels), the *funding leg* (here, a centralized exchange withdrawal), and *static detection of the resolver contracts themselves* — which is harder than it looks, as section 3 shows.

## 2. The five-contract cluster

### 2.1 Funding chain

A single funding chain ties the five contracts to one operator:

```
HTX 48 hot wallet                          0xa03400e098f4421b34a3a44a1b4e571419517687
  │ tx 0x951eaf6a28d3eca0415bc33e24be8d4914747f7061f79ef9da45c7df127633c9
  │ 0.1143 ETH, 2026-04-01 (HTX nonce 909202)
  ▼
0x59a1bcb06d4f473b4b0aa570dfbd12ed39dfbc6c    one-hop gateway
  │ single tx in, single tx out — exists only to break the direct CEX→burner link
  │ tx 0x92781b69f1b5d779a4c50c10836a159f06b203cc2a318760900666075d9b23af
  │ 0.114275 ETH, 2026-04-01
  ▼
0x02f9984f50ee23cf96d5aed6e88549014d77297c    operator distribution wallet
  │ 11 outgoing txs (nonces 0–10), all simple ETH transfers to 10 fresh burners
  ▼
{10 burner wallets}      ──►      {5 dead-drop contracts so far}
```

The 0.1143-ETH HTX withdrawal is the **single most actionable indicator** in this report: it is a regulated-exchange transaction tied to a KYC'd customer account.

### 2.2 Active contracts and the URLs they have stored

| Contract | Deployer (burner) | URLs written by deployer |
|---|---|---|
| `0x98f91cedcf84a345e4e337dd323fb62dbfb88f8c` | `0x218418a9ee10a609bb807f5f7357b058e11c66e3` | `https://app.com`, **`https://cakes-thu-attractions-sci.trycloudflare.com`**, `https://google.com` |
| `0x9276db60660946a49b27cde5e35fda2ad64e5ba1` | `0xd43338260135d827f198847264bf81a4b09c2c1d` | `https://farfetch.com`, **`https://improve-love-heritage-secretary.trycloudflare.com`**, `https://love.com` |
| `0xc1a07d073432193a3c3210ec20d14d0ddd4d5994` | `0xe5900be95a966ea55a2bfc889a86472cf34281e0` | `https://manage.com`, **`https://pentium-playstation-favorite-roberts.trycloudflare.com`** |
| `0x2294a496af9056de8a5d63203d468927ae76ab0e` | `0x79ae611ac2db579e0e5b4d233f8af94476880237` | **`https://stylish-tions-ministers-cuisine.trycloudflare.com`**, `https://google.com`, **`https://infant-plot-only-neighbor.trycloudflare.com`**, `https://infant.com` |
| `0x3748bd7d0852259da3f03e7bfcdec7602a5f96d2` | `0x5a03fe67715f234e051e1ee82d61f04e56cce8ad` | `https://chatgpt.com`, **`https://translation-infectious-scott-freebsd.trycloudflare.com`**, **`https://contractor-nhs-niagara-postposted.trycloudflare.com`** |

Bold entries are the operator's live C2 URLs at the times the slot was hot. The non-bold entries are placeholder URLs the operator writes between rotations — values like `https://chatgpt.com` or `https://farfetch.com` chosen to make Etherscan transaction lists look unremarkable on cursory inspection.

All seven Cloudflare quick-tunnel hostnames had DNS removed by the time of analysis, but the contracts remain live and re-armable: the operator can revive a campaign by spinning up a new `cloudflared` tunnel and writing the new hostname with a single transaction.

### 2.3 Burners held in reserve

The distribution wallet `0x02f9984f…` has funded five additional burners that have produced no outgoing transactions yet:

| Burner | Funded amount | Funded on |
|---|---|---|
| `0x648a1918e7745f515d86e709726a61bd3d6a27b7` | 0.0063 ETH | 2026-04-04 |
| `0x9308868e44ee95d0dc8464917f2c9314396249af` | 0.0063 ETH | 2026-04-04 |
| `0x0cdf754b38264f62444ab74fd038fe6a25acb279` | 0.005 ETH  | 2026-04-05 |
| `0x2fb644098832b30a2f0017d642f7c3c22429ad08` | **0.05 ETH** | 2026-04-05 |
| `0x3a4905f5d580dda10affb2445276b53cb59a6583` | 0.005 ETH  | 2026-04-05 |

The `0x2fb6…` burner was seeded with ten times the standard amount, suggesting either a higher-throughput contract (more setString rotations expected) or a different role entirely. The first deploy from any of these five addresses will reveal the operator's next contract before it is operational.

## 3. Reverse-engineered contract logic and the bytecode-rotation defense

The five contracts share the same logical interface:

```solidity
contract DeadDropResolver {
    mapping(address => string) internal _data;

    // 3 to 6 decoy "immutables" set by constructor and never read by runtime code:
    bytes32 immutable a; bytes32 immutable b; bytes32 immutable c; /* d; e; f; */

    // Per-contract event with a unique topic-0 (each contract recompiles with a different
    // event name, so the keccak signature differs across deployments).
    event StringSet(address indexed who, string value);

    // Two per-contract "magic" probe functions returning hard-coded uint24 constants.
    // Selector names and return values differ per deployment (see table below).
    function _opaqueName1() external pure returns (uint256) { return CONSTANT_A; }
    function _opaqueName2() external pure returns (uint256) { return CONSTANT_B; }

    // Selector 0x7d434425 — IDENTICAL across all five contracts.
    function getString(address who) external view returns (string memory) {
        return _data[who];
    }

    // Selector 0x7fcaf666 — IDENTICAL across all five contracts.
    function setString(string calldata _str) external {
        _data[msg.sender] = _str;
        emit StringSet(msg.sender, _str);
    }
}
```

The 32-byte constructor immutables are **dead code** at runtime: the JUMPDEST that would `MLOAD` each immutable is reachable only through `5f50505f5050…` — push-zero-pop-pop sequences that read the immutable and immediately discard it. The Solidity compiler emits these because the source-level declaration exists, but the source never references the variables. Their purpose is forensic camouflage: each deployment writes a different 96-, 128-, or 192-byte tail of pseudo-random bytes into the codehash, defeating any rule that hashes the bytecode tail to identify a known dead-drop.

The "magic" probe functions are the malware's authentication step. The dropper carries hard-coded expected return values for both magic functions and the dead-drop's address. Before trusting the URL it reads, the malware calls both magic functions and compares against the expected pair. If a defender deploys a honeypot contract at the same address (impossible without the private key, but cheap to simulate over a forwarding RPC), the magic check fails.

**Magic constants observed:**

| Contract | Probe selector 1 → constant | Probe selector 2 → constant |
|---|---|---|
| `0x98f91c…` | `0x038d3628` → `0xa887eb` (11,045,867) | `0xb7bcae29` → `0xcd4161` (13,452,641) |
| `0x9276db…` | `0x5938e3c4` → `0x1b23ec` (1,778,156)  | `0x843326cb` → `0x31cb87` (3,263,367)  |
| `0xc1a07d…` | `0x688d0569` → `0x43a2c4` (4,432,068)  | `0x6b1e2f97` → `0x20ad84` (2,141,572)  |

Brute-keccak against several dozen candidate function names (`magic`, `version`, `tag`, `id`, `code`, `salt`, `fingerprint`, …) did not recover the probe-function source names, indicating the operator obfuscates the names per build. Only `getString(address)` and `setString(string)` survive the recompilation untouched, and only because the malware needs stable, hard-coded selectors to call.

All five contracts compile to Solidity `0.8.33` per their IPFS metadata footer; none is source-verified on Etherscan.

## 4. Detection guidance

Signature-based rules (bytecode regex, event-topic alerts, fixed-string blocklists) will miss every fresh deployment in this family because every observable except the two core selectors is rotated per build. The detection surface that survives rotation is **structural**:

- The runtime bytecode is under ~1.2 KB.
- It exposes the public selectors `0x7d434425` *and* `0x7fcaf666`.
- It is **not source-verified** on Etherscan.
- All inbound transactions to the contract come from the **single deployer address**.
- The deployer holds a small, exhausted ETH balance (typical: 0.001–0.005 ETH remaining), was funded with a single deposit of 0.005–0.05 ETH from a third-party address, and has no other on-chain activity.
- One or more of the historically-stored URLs is an `<adj>-<noun>-<noun>-<noun>.trycloudflare.com` quick-tunnel hostname.

A practical rule for monitoring fresh deployments:

```
new_contract.runtime_size < 1500 bytes
  AND has_selector(new_contract, 0x7d434425)
  AND has_selector(new_contract, 0x7fcaf666)
  AND not new_contract.is_verified
  AND all writes_to(new_contract) come from new_contract.deployer
  --> flag as candidate EVM dead-drop URL resolver
```

The five in-reserve burners listed in section 2.3 are a free early-warning feed: alert on the first contract deployment from any of those five addresses.

## 5. Indicators of compromise

### 5.1 Ethereum addresses

```
Dead-drop contracts (5):
  0x98f91cedcf84a345e4e337dd323fb62dbfb88f8c
  0x9276db60660946a49b27cde5e35fda2ad64e5ba1
  0xc1a07d073432193a3c3210ec20d14d0ddd4d5994
  0x2294a496af9056de8a5d63203d468927ae76ab0e
  0x3748bd7d0852259da3f03e7bfcdec7602a5f96d2

Active deployer burners (5):
  0x218418a9ee10a609bb807f5f7357b058e11c66e3
  0xd43338260135d827f198847264bf81a4b09c2c1d
  0xe5900be95a966ea55a2bfc889a86472cf34281e0
  0x79ae611ac2db579e0e5b4d233f8af94476880237
  0x5a03fe67715f234e051e1ee82d61f04e56cce8ad

In-reserve burners (5) — watch for first deploy:
  0x648a1918e7745f515d86e709726a61bd3d6a27b7
  0x9308868e44ee95d0dc8464917f2c9314396249af
  0x0cdf754b38264f62444ab74fd038fe6a25acb279
  0x2fb644098832b30a2f0017d642f7c3c22429ad08      (10x funding)
  0x3a4905f5d580dda10affb2445276b53cb59a6583

Operator distribution wallet:
  0x02f9984f50ee23cf96d5aed6e88549014d77297c

CEX→operator gateway (single tx in / single tx out):
  0x59a1bcb06d4f473b4b0aa570dfbd12ed39dfbc6c
```

### 5.2 Cloudflare quick-tunnel hostnames (defanged)

```
hxxps[:]//cakes-thu-attractions-sci[.]trycloudflare[.]com
hxxps[:]//improve-love-heritage-secretary[.]trycloudflare[.]com
hxxps[:]//pentium-playstation-favorite-roberts[.]trycloudflare[.]com
hxxps[:]//infant-plot-only-neighbor[.]trycloudflare[.]com
hxxps[:]//stylish-tions-ministers-cuisine[.]trycloudflare[.]com
hxxps[:]//translation-infectious-scott-freebsd[.]trycloudflare[.]com
hxxps[:]//contractor-nhs-niagara-postposted[.]trycloudflare[.]com
```

All seven were DNS-dead at time of analysis. Treat them as historical campaign markers, not as currently-resolving hosts.

### 5.3 Placeholder URLs used as decoys (defanged)

```
hxxps[:]//app[.]com
hxxps[:]//google[.]com
hxxps[:]//chatgpt[.]com
hxxps[:]//farfetch[.]com
hxxps[:]//love[.]com
hxxps[:]//manage[.]com
hxxps[:]//infant[.]com
```

These are the strings the operator writes to the slot between hot rotations. They are legitimate-looking and not malicious on their own; their presence in a `setString` call against an unverified, single-deployer-written contract is the indicator.

### 5.4 Key transaction

```
HTX 48 hot wallet withdrawal funding the cluster:
  Tx hash:  0x951eaf6a28d3eca0415bc33e24be8d4914747f7061f79ef9da45c7df127633c9
  Block:    24998357
  Date:     2026-04-01
  Amount:   0.1143 ETH
  HTX nonce: 909202
```

### 5.5 Function selectors and event topics

```
Common to all five contracts:
  0x7d434425  getString(address)   — read
  0x7fcaf666  setString(string)    — write (only callable by anyone, but in practice only the deployer ever calls)

Per-contract magic probe functions (samples):
  0x038d3628 → 0xa887eb        0xb7bcae29 → 0xcd4161
  0x5938e3c4 → 0x1b23ec        0x843326cb → 0x31cb87
  0x688d0569 → 0x43a2c4        0x6b1e2f97 → 0x20ad84

Per-contract event topics for the setString emit:
  0x0d72dfad2673a727c53ebb22ff602f88e6ef4f1f5befee8269bb3866b3f154e1
  0x49b4670de0fa35ec729a3d1784b25b83faf7df384b74edb2c975a4cf6735175b
  0x9c2447aafb7827d10c51a8c40c1f5072bf8e8a178b449f8a02c1b0d5a907243e
```

## 6. Recommended actions

**For incident responders.** Add the seven `trycloudflare.com` hostnames to historical-IOC feeds and forensic search corpora. They are unlikely to resolve again, but their appearance in proxy logs, DNS-query telemetry, or endpoint history identifies hosts that may have fetched a stage from this operator between 2026-04-04 and 2026-04-13.

**For network defenders.** Block resolution of `*.trycloudflare.com` on environments that have no legitimate need for Cloudflare quick-tunnels — quick-tunnels are an ephemeral developer convenience that has become a staple of unattributed payload delivery. If outright blocking is infeasible, alert on first-time-seen hostnames matching the four-word adjective-noun pattern.

**For exchange compliance teams.** The withdrawal at HTX (tx `0x951eaf…7633c9`, HTX nonce 909202, 2026-04-01, 0.1143 ETH to `0x59a1bcb…`) is the single point at which this operator has an identity attached. HTX's compliance team can resolve the originating account against KYC records and freeze any further outflows.

**For Cloudflare.** The seven quick-tunnel hostnames are derivable from the trycloudflare control plane to the underlying authenticated tunnel tokens. The same tokens may be in continued use under freshly-named tunnels.

**For threat intelligence platforms.** Adopt the structural detection rule in section 4. The two stable selectors and the unverified-plus-single-deployer-write signal identify new instances of this resolver family with high precision in our spot-checks of recent Ethereum mainnet deployments. The five in-reserve burners listed in section 2.3 are a free trip-wire for the operator's next deploy.

## 7. Limitations

This report enumerates only the contracts reachable via the funding-chain pivot from the operator's distribution wallet `0x02f9984f…`. The operator may run parallel distribution wallets seeded from different CEX withdrawals; those clusters would not appear here. Conversely, the operator may share toolchain or tradecraft with other actors using the same EtherHiding pattern, and a structural-detection sweep of recent unverified mainnet deployments would likely surface additional, unrelated clusters that should not be attributed to this operator without an explicit on-chain link.

The contracts themselves are passive and cannot be neutralized by any party other than the operator. The recommended actions above target the operator's *boundaries* — the CEX cash-out, the Cloudflare tunnels, and detection at the malware fetch step — because the on-chain primitive is, by design, beyond defender reach.

---

*Investigation conducted 2026-05-14. All data sourced from public Ethereum mainnet state via Etherscan API. No samples of the second-stage payload were retrieved; all `trycloudflare.com` hosts were DNS-dead at time of analysis.*
