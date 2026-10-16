# @conet.project/chat-sdk

Beamio CoNET Chat SDK — **runs the gossip transport entirely inside a Web Worker** (zero main-thread `openpgp` decrypt/encrypt, zero `ethers.verifyMessage`), plus **fragmented, symmetrically-encrypted IPFS history**. UI-agnostic, reusable across SilentPassUI / bizSite / Alliance / POS.

> Motivation: running `openpgp.decrypt` + `ethers.verifyMessage` on the main thread caused a "UI freeze for tens of seconds after startup". This SDK moves all inbound decryption, outbound encryption, signing, and SSE connect/reconnect into a Worker. The main thread only orchestrates `postMessage` and dispatches events.

---

## Features

- **Worker-first**: every heavy crypto operation runs inside the Worker; the UI never blocks.
- **UI-agnostic**: pure TS/ESM + `.d.ts`, no React and no app-specific imports. The host injects private keys, RPC, node discovery, IPFS, and persistence.
- **Zero-trust routing built in**: send via entry A, listen via entry C (≠ mailbox B), `listenKind:'chat'` + `algorithm:'aes-256-cbc'` + `Securitykey`, business messages encrypted to the recipient's **EOA user PGP**, delivery ACK encrypted to the route B key. Each POST wraps inner armor to **that entry's** route public key. Clients never set `X-CoNET-Hop-Sigs`.
- **Encrypted fragmented history**: HKDF domain separation + ratcheting fragment keys + AES-256-GCM fragments + encrypted index manifest + server-side `point-` pointers + IndexedDB local-first.
- **Private keys never persist inside the SDK**: keys are used only in Worker memory to derive an `ethers.Wallet` and the history master. The host decides whether to persist locally (consumers/POS may store; bizSite keeps session memory only).

---

## Architecture

```
┌────────────────────────── Main thread (host UI) ──────────────────────────┐
│  BeamioChatClient                                                          │
│   • init() → getNodes() → postMessage(init)                               │
│   • sendMessage / queryPresence / setRoutes / setNodes                    │
│   • on('message'|'delivery'|'presence'|'status'|'log'|historyBuffer)      │
│   • history.load / history.read / history.append / history.onBuffer       │
│   ▲ plaintext env.line → host's existing addNewMessage serial queue       │
└──────────────┬───────────────────────────────▲───────────────────────────┘
        postMessage(Command)                  postMessage(Event/Receipt)
┌──────────────▼───────────────────────────────┴───────────────────────────┐
│  Web Worker (worker/entry.ts)                                             │
│   • GossipCore: SSE connect/reconnect, openpgp decrypt/encrypt,           │
│                 EIP-191 sign, presence wallet_online_query, delivery ACK  │
│   • HistoryStore: master + HKDF + ratcheting fragments + AES-GCM + IPFS   │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## Installation

Install as a dependency (per `src-subprojects-are-independent`: each sub-project owns formal dependencies; never cross-`../..` import).

```bash
npm install @conet.project/chat-sdk
```

Peer dependencies (provided by the host):

| Package | Version |
|---|---|
| `ethers` | `^6.0.0` |
| `openpgp` | `^5.0.0 \|\| ^6.0.0` |

Runtime: a browser / WebView with `Worker` + `crypto.subtle` (PWA inside iOS/Android native shells is supported). Node `>=18` for build/test only.

---

## Quick start

The host creates the Worker (the SDK does not hardcode a worker URL, to stay bundler-agnostic):

```ts
import { createBeamioChatClient, type BeamioChatConfig } from '@conet.project/chat-sdk'

const config: BeamioChatConfig = {
  identity: {
    eoaAddress,                 // 0x… (SDK normalizes internally)
    privateKeyHex,              // raw EOA private key hex, used only inside the Worker
    pgpPrivateKeyArmored,       // armored PGP private key (decrypt inbound)
    pgpPassphrase: '',
    pgpPublicKeyArmored,        // armored PGP public key (keyID / diagnostics)
    ownRouteArmoredPublicKey,   // your mailbox B route public key
  },
  conetRpcUrl: 'https://rpc1.conet.network',
  addressPgpContractAddress: CONET_ADDRESS_PGP,
  getNodes: async () => fetchHealthyNodes(),   // host owns node discovery/caching
  ipfsBaseUrl: 'https://ipfs.conet.network/api',
  chainId: 224422,             // chainId used in the history-master derivation domain (default 224422 CoNET L1)
}

const client = createBeamioChatClient(config, {
  workerFactory: () =>
    new Worker(new URL('@conet.project/chat-sdk/worker', import.meta.url), { type: 'module' }),
})

await client.init()                 // start Worker + inject keys/nodes; the Worker begins listening

// inbound plaintext lines → hand to the host's existing serial checkSign/parse queue
const off = client.on('message', (env) => {
  addNewMessage(env.line)           // env.line already carries _beamioPgpArmorHash for delivery ACK
})

// later, update the contacts to listen for / probe
client.setRoutes(myContactRoutes)
```

### Worker creation per bundler

| Environment | `workerFactory` |
|---|---|
| **Vite** | `() => new Worker(new URL('@conet.project/chat-sdk/worker', import.meta.url), { type: 'module' })` |
| **Webpack 5 / CRA (Craco)** | same as above; Webpack 5 statically recognizes `new Worker(new URL(...))` and emits a separate worker chunk |
| **Vendored (see below)** | `() => new Worker(new URL('../vendor/beamio-chat-sdk/worker/entry.ts', import.meta.url), { type: 'module', name: 'beamio-chat-gossip' })` |

---

## Configuration: `BeamioChatConfig`

| Field | Type | Description |
|---|---|---|
| `identity` | `ChatIdentity` | see below |
| `conetRpcUrl` | `string` | CoNET DePIN RPC (reads AddressPGP, etc.) |
| `addressPgpContractAddress` | `string` | AddressPGP contract address |
| `getNodes` | `() => Promise<NodeInfo[]>` | returns a snapshot of currently healthy nodes (host owns discovery/caching) |
| `ipfsBaseUrl` | `string` | IPFS fragment gateway base, e.g. `https://ipfs.conet.network/api` |
| `ipfsWriteBaseUrl?` | `string` | IPFS write base (defaults to `ipfsBaseUrl`) |
| `persistence?` | `PersistenceAdapter` | IndexedDB adapter (optional; history is memory-only without it) |
| `runtime?` | `ChatRuntimeOptions` | `sendFanout` (default 3), `reconnectBaseMs` (4000), `reconnectMaxMs` (30000), `outerWrap` (default `true`) |
| `chainId?` | `number` | chainId in the history-master derivation domain (default `224422` CoNET L1) |

### `ChatIdentity` (key injection)

| Field | Description |
|---|---|
| `eoaAddress` | EOA address |
| `privateKeyHex` | raw private key hex (with or without `0x`). **Used only inside the Worker** for EIP-191 signing and history-master derivation |
| `pgpPrivateKeyArmored` | armored PGP private key, decrypts inbound |
| `pgpPassphrase?` | PGP private key passphrase (if any) |
| `pgpPublicKeyArmored?` | armored PGP public key |
| `ownRouteArmoredPublicKey?` | your mailbox B route public key (listen encryption target) |

> One-time key generation + `registerChatRoute` route registration stay on the host (curve25519 generation is fast and not a freeze source). Inject the generated keys via `identity`.

### `ChatRoute` (contact routes)

| Field | Description |
|---|---|
| `address` | contact EOA (lowercase) |
| `userPublicKeyArmored` | recipient's **user PGP** public key — business-message encryption target |
| `routerArmoredPublicKey?` | recipient's mailbox B route public key — listen / ACK encryption target |
| `routePgpKeyID?` | route keyID (optional) |

---

## API reference

### `BeamioChatClient`

| Method | Description |
|---|---|
| `init(): Promise<void>` | start Worker, inject config/nodes; the Worker begins listening. Idempotent (no-op if already running) |
| `sendMessage(to, payload, opts?)` | encrypt and send a business payload to a contact via entry A ≠ B. `opts.beamioNoPush` wraps `{ data, NoPush: true }` to the contact mailbox route key (sender receipts). HTTP stays `{ data }` only. Returns `{ sendId }` |
| `queryPresence(contacts)` | probe mailbox listen-pool presence; returns `Record<addrLower, boolean>` (only `ok:true` counts) |
| `setRoutes(routes)` | update the set of contacts to listen for / probe |
| `setNodes(nodes)` | push a refreshed node snapshot (host owns discovery) |
| `postMailboxCommand(routerArmoredPublicKey, command)` | encrypt an arbitrary mailbox command (e.g. `gossip_delivery_ack`) to route B, sent via entry C ≠ B |
| `on(event, cb): Unsubscribe` | subscribe to events (below); returns an unsubscribe function |
| `history` | `BeamioChatHistory` (below) |
| `pause()` / `resume()` | pause/resume Worker listening |
| `destroy()` | tear down the Worker and all listeners (idempotent) |

### Events (`client.on(...)`)

| Event | Payload | Description |
|---|---|---|
| `message` | `InboundEnvelope` | `env.line` = host-ready JSON plaintext line (carries `_beamioPgpArmorHash`), handed to the host's serial checkSign/parse queue |
| `delivery` | `DeliveryReceiptEvent` | delivery receipt (`sendId` / `deliveredAt` / `from`); host marks its own bubble as delivered |
| `presence` | `PresenceEvent` | `online: Record<addr, boolean>`, reliable results only |
| `status` | `StatusEvent` | `idle`/`connecting`/`listening`/`reconnecting`/`paused`/`error`; `listening` fires on each heartbeat to refresh main-thread staleness |
| `log` | `ChatLogEvent` | structured log (never contains private keys / plaintext / full ciphertext) |
| `historyBuffer` | `HistoryBufferEvent` | incremental batches during history restore/append, fed to the UI incrementally |

### `client.history`

| Method | Description |
|---|---|
| `load(options?)` | restore encrypted history: locate the chain head → decrypt missing fragments → emit `historyBuffer`. Default `emit: 'fresh'` publishes only fragments decrypted on this pass |
| `read(options?)` | return the local decrypted corpus. Does not contact the chain or IPFS. Filter by `peer`, AND-match `query` tokens, optional `limit` (newest) |
| `append(entry)` | write a newly received/sent entry to encrypted history and remember its plaintext in the local corpus |
| `onBuffer(cb): Unsubscribe` | subscribe to incremental batches during restore/append |

`HistoryLoadOptions`: `peer?`, `tailCount?` (default 60), `localOnly?`, `emit?: 'all' | 'fresh'` (default `'fresh'`).

`HistoryReadOptions`: `peer?` (EOA), `query?` (whitespace-separated tokens, all required, case-insensitive, matched against rendered message text), `limit?` (keep the newest matches).

Host bridges should expose `read` as `readDecryptedChatHistory` and `searchDecryptedChatHistory(query)`. When the Worker is not ready, return `null` (an untrusted miss). Do not treat `null` or a thrown read as an empty history. Do not log the query string or message bodies.

---

## Zero-trust routing (built into the SDK)

Follows `src/docs/gitbook/l0/si-developer-guide.md`, `conet-p2p-mailbox-routing-protocol`, and `beamio-conet-chat-protocol`:

- **POST `/post`**: body is **only** `{ data: "<OpenPGP armor>" }`. Never add sibling fields.
- **Send business messages**: encrypt to the recipient's **EOA user PGP**, POST to a healthy **entry A ≠ mailbox B**.
- **Mailbox work / `NoPush`**: if mailbox B must skip APNs, wrap `{ data: <user-PGP armor>, NoPush: true }` to **B route PGP**, then POST that armor as `{ data }` (optional entry wrap). Do not put `NoPush` on the HTTP JSON.
- **Recipient listen**: encrypt `{ command:'mining', listenKind:'chat', algorithm:'aes-256-cbc', Securitykey }` to the **mailbox B route key**, SSE-connect via **entry C ≠ B**. Omitting `listenKind` is treated as mining.
- **Delivery ACK / presence**: encrypt the SI command to the **mailbox B route key**, POST via **entry C ≠ B**.
- **Outer wrap (default `runtime.outerWrap: true`)**: after the inner armor is built, encrypt that **raw armor string** again to **this POST's entry** route public key. Each fan-out entry is wrapped separately. Skip wrap when the entry key equals the inner encryption key (SI same-node peel → `end`).
- **Hop-sigs**: clients **must not** set `X-CoNET-Hop-Sigs`. Only SI→SI HTTP `:80` appends it (max 3 hops).
- **SSE inbound**: live SI still writes plaintext JSON `{ data: pgpMessage }`. Keep sending `Securitykey` on listen; do not assume AES-CBC frames yet.
- Never connect directly to mailbox B; never target the recipient's AA (must be EOA user PGP).
- Client → entry may use HTTPS (PWA default). SI→SI is HTTP `:80` only.

---

## Encrypted fragmented history

```
master     = keccak256( EOA_sign("beamio.chat.history.v1|chainId|eoa") )   // private key never leaves the Worker
locator L  = HKDF(master, "index-locator")     // hidden in a hash ocean; server-side point-${L} points to the current index
indexKey   = HKDF(master, "index-enc")         // AES-256-GCM encrypts the ordered index manifest
fragment ratchet  k_i = HKDF(master, `frag|${seq}|${cid_{i-1}}`)   // cid_{-1}=HKDF(master,"frag-genesis")
           cipher_i = AES-GCM(k_i, plaintext_i);  cid_i = keccak256(cipher_i)   // uploaded as a fragment
```

- Every `cid_{i-1}` is recorded in the index, so any `k_i` is O(1) to derive — enabling **newest-first** restore.
- **IndexedDB local-first**: ciphertext fragments and the encrypted index stay local. Network failures **do not overwrite** trusted local history.
- **Decrypted corpus**: after a fragment is decrypted, the Worker stores `{ entry, searchText }` in memory and in Worker IndexedDB under `beamio.chat.history.plain:{eoa}:{cid}`. Later reads hit memory, then that plaintext record, then the local ciphertext, and only then IPFS. A just-sent message is stored as plaintext at encrypt time, so the UI does not re-download it. An unchanged chain head hash skips the index download. UI code obtains history only through `history.read` (and `historyBuffer` for newly decrypted rows). Full-text search is `history.read({ query })` over the rendered text of the whole corpus.
- **Cross-device recover** still uses RPC `getPointer` plus IPFS when a `cid` has no local plaintext. The chain stores only the index hash.

---

## Integrating into SilentPassUI

Consumer PWA depends on the published package. Do not keep a second source tree under `src/vendor/`.

```ts
import { createBeamioChatClient } from '@conet.project/chat-sdk'

function makeGossipWorker(): Worker {
  return new Worker(new URL('@conet.project/chat-sdk/worker', import.meta.url), {
    type: 'module',
    name: 'beamio-chat-gossip',
  })
}

const client = createBeamioChatClient(config, { workerFactory: makeGossipWorker })
const history = await client.history.read()
const matches = await client.history.read({ query: 'invoice paid', peer: peerEoa })
```

The host bridge (`readDecryptedChatHistory` / `searchDecryptedChatHistory` / `onDecryptedChatHistory`) is the only UI entry. Pages do not fetch IPFS history themselves.

---

## Security & compliance

- Private keys / plaintext / full ciphertext **must never be logged**; `log` events emit structured summaries only.
- The history `master` lives only in Worker memory; consumers/POS may store keys locally, bizSite keeps session memory only (policy owned by the host; the SDK never self-persists).
- Always send `listenKind:'chat'` + `Securitykey`; never connect directly to mailbox B.
- Never set `X-CoNET-Hop-Sigs` on client `POST /post`.
- Sender receipts should use `sendMessage(..., { beamioNoPush: true })` (mailbox work wrap; requires the sender mailbox route key).
- `point-` has CoNET-private semantics; public-gateway retrieval relies on CIDv1 mapping and must be documented.

---

## Build / directory layout

```bash
npm run build       # tsc -p tsconfig.json → dist/ (ESM + .d.ts)
npm run typecheck   # tsc --noEmit
npm run clean       # rm -rf dist
```

```
src/
  index.ts          # public entry: createBeamioChatClient + types
  client.ts         # main-thread BeamioChatClient (starts worker + postMessage protocol)
  protocol.ts       # main ↔ worker postMessage protocol
  types.ts          # public types (UI-agnostic)
  crypto.ts         # WebCrypto + keccak/HKDF/AES-GCM (worker & main thread)
  envelope.ts       # POST body, route-command encrypt, per-entry outer wrap
  nodes.ts          # node probing + `postUrl` (worker & main thread)
  worker/
    entry.ts        # worker entry (imported only in a Worker context)
    gossip-core.ts  # SSE + openpgp decrypt/encrypt + sign + presence + ACK
    history.ts      # encrypted fragmented IPFS history + IndexedDB
```

Package exports:

| Entry | Usage |
|---|---|
| `@conet.project/chat-sdk` | main-thread API (`createBeamioChatClient` + types) |
| `@conet.project/chat-sdk/worker` | worker entry; **only** used as the target of `new Worker(...)` |

---

## Related rules / references

- `src/docs/gitbook/l0/si-developer-guide.md` — SI `/post` peel, outer wrap, hop-sigs
- `conet-p2p-mailbox-routing-protocol` / `beamio-conet-chat-protocol` — routing and envelopes
- `conet-depin-chat-app-dev` — app practices (receipts / presence / listenKind)
- `beamio-trusted-vs-untrusted-fetch` — failures never overwrite trusted local state
- `x402sdk/src/endpoint/fragmentClusterServer.ts` — `point-` pointer server
- `src-subprojects-are-independent` — sub-projects are independent; no cross-repo imports

## License

MIT (`publishConfig.access = public`).
