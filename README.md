# @conet-project/chat-sdk

Beamio CoNET Chat SDK —— **把 gossip 通讯全程放进 Web Worker**（主线程零 `openpgp` 加解密、零 `ethers.verifyMessage`），并内置**碎片化对称加密的 IPFS 历史存储**。UI 无关，可在 SilentPassUI / bizSite / Alliance / POS 之间复用。

> 设计动机:主线程跑 `openpgp.decrypt` + `ethers.verifyMessage` 会造成"启动十几秒后全局冻结"。本 SDK 把入站解密、出站加密、签名、SSE 连接/重连全部下沉到 Worker,主线程只做 `postMessage` 编排与事件分发。

---

## 特性

- **Worker 优先**:所有重加密在 Worker 内,主线程不阻塞。
- **UI 无关**:纯 TS/ESM + `.d.ts`,无 React、无 app 专属 import。host 通过依赖注入提供私钥、RPC、节点发现、IPFS、持久化。
- **零信任路由铁律**内建:send 经 entry A、listen 经 entry C(≠ mailbox B)、`listenKind:'chat'`、业务加密目标为收件人 **EOA user PGP**、delivery ACK 加密给 route B key。
- **加密碎片历史**:HKDF 域分隔 + 棘轮碎片密钥 + AES-256-GCM 碎片 + 加密 index 清单 + 服务端 `point-` 指针 + IndexedDB 本地优先。
- **私钥不落 SDK**:私钥只在 Worker 内存中派生 `ethers.Wallet` 与 history master;host 决定是否本地持久化(consumer/POS 可存、bizSite 仅会话内存)。

---

## 架构

```
┌────────────────────────── 主线程 (host UI) ──────────────────────────┐
│  BeamioChatClient                                                    │
│   • init() → getNodes() → postMessage(init)                          │
│   • sendMessage / queryPresence / setRoutes / setNodes               │
│   • on('message'|'delivery'|'presence'|'status'|'log'|historyBuffer) │
│   • history.load / history.append / history.onBuffer                 │
│   ▲ 明文行 env.line → host 现有 addNewMessage 串行队列(checkSign/解析)  │
└──────────────┬───────────────────────────────▲──────────────────────┘
        postMessage(命令)                  postMessage(事件/回执)
┌──────────────▼───────────────────────────────┴──────────────────────┐
│  Web Worker (worker/entry.ts)                                        │
│   • GossipCore: SSE 连/重连、openpgp 解密(入站)/加密(出站)、EIP-191 签名 │
│                 presence wallet_online_query、delivery ACK           │
│   • HistoryStore: master 派生 + HKDF + 棘轮碎片 + AES-GCM + IPFS + IDB │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 安装

作为私有依赖引入(遵循 `src-subprojects-are-independent`,各子项目正式依赖,勿跨 `../..` import)。

```bash
npm install @conet-project/chat-sdk
```

peerDependencies(host 需自带):

| 包 | 版本 |
|---|---|
| `ethers` | `^6.0.0` |
| `openpgp` | `^5.0.0 \|\| ^6.0.0` |

运行环境:浏览器 / 支持 `Worker` + `crypto.subtle` 的 WebView(iOS/Android 原生壳内 PWA 均可)。Node `>=18`(仅构建/测试)。

---

## 快速开始

host 负责创建 Worker(SDK 不写死 worker URL,以保持 bundler 无关):

```ts
import { createBeamioChatClient, type BeamioChatConfig } from '@conet-project/chat-sdk'

const config: BeamioChatConfig = {
  identity: {
    eoaAddress,                 // 0x… (SDK 内部会归一化)
    privateKeyHex,              // 原始私钥 hex,仅在 Worker 内使用
    pgpPrivateKeyArmored,       // armored PGP 私钥(解密入站)
    pgpPassphrase: '',
    pgpPublicKeyArmored,        // armored PGP 公钥(keyID / 诊断)
    ownRouteArmoredPublicKey,   // 自己的 mailbox B route 公钥
  },
  conetRpcUrl: 'https://rpc1.conet.network',
  addressPgpContractAddress: CONET_ADDRESS_PGP,
  getNodes: async () => fetchHealthyNodes(),   // host 拥有节点发现/缓存
  ipfsBaseUrl: 'https://ipfs.conet.network/api',
  chainId: 8453,               // 用于 history master 派生域(默认 8453 Base)
}

const client = createBeamioChatClient(config, {
  workerFactory: () =>
    new Worker(new URL('@conet-project/chat-sdk/worker', import.meta.url), { type: 'module' }),
})

await client.init()                 // 起 Worker + 注入 keys/nodes,Worker 自动 startListen

// 订阅入站明文行 → 交给 host 现有串行队列做 checkSign/业务解析
const off = client.on('message', (env) => {
  addNewMessage(env.line)           // env.line 已带 _beamioPgpArmorHash 供 delivery ACK
})

// 后续更新要监听/探测的联系人
client.setRoutes(myContactRoutes)
```

### 不同打包器创建 Worker

| 环境 | workerFactory |
|---|---|
| **Vite** | `() => new Worker(new URL('@conet-project/chat-sdk/worker', import.meta.url), { type: 'module' })` |
| **Webpack 5 / CRA(Craco)** | 同上;Webpack 5 静态识别 `new Worker(new URL(...))` 并产出独立 worker chunk |
| **Vendored(见下)** | `() => new Worker(new URL('../vendor/beamio-chat-sdk/worker/entry.ts', import.meta.url), { type: 'module', name: 'beamio-chat-gossip' })` |

---

## 配置:`BeamioChatConfig`

| 字段 | 类型 | 说明 |
|---|---|---|
| `identity` | `ChatIdentity` | 见下 |
| `conetRpcUrl` | `string` | CoNET DePIN RPC(读 AddressPGP 等) |
| `addressPgpContractAddress` | `string` | AddressPGP 合约地址 |
| `getNodes` | `() => Promise<NodeInfo[]>` | 返回当前健康节点快照(host 拥有发现/缓存) |
| `ipfsBaseUrl` | `string` | IPFS fragment 网关基址,如 `https://ipfs.conet.network/api` |
| `ipfsWriteBaseUrl?` | `string` | IPFS 写入基址(默认同 `ipfsBaseUrl`) |
| `persistence?` | `PersistenceAdapter` | IndexedDB 适配器(可选;无则历史仅在内存) |
| `runtime?` | `ChatRuntimeOptions` | `sendFanout`(默认 3)、`reconnectBaseMs`(4000)、`reconnectMaxMs`(30000) |
| `chainId?` | `number` | history master 派生域中的 chainId(默认 `8453`) |

### `ChatIdentity`(私钥注入)

| 字段 | 说明 |
|---|---|
| `eoaAddress` | EOA 地址 |
| `privateKeyHex` | 原始私钥 hex(带/不带 `0x`)。**仅在 Worker 内**用于 EIP-191 签名与 history master 派生 |
| `pgpPrivateKeyArmored` | armored PGP 私钥,解密入站 |
| `pgpPassphrase?` | PGP 私钥口令(如有) |
| `pgpPublicKeyArmored?` | armored PGP 公钥 |
| `ownRouteArmoredPublicKey?` | 自己的 mailbox B route 公钥(listen 加密目标) |

> **一次性密钥生成 + `regiestChatRoute` 路由注册留在 host 侧**(curve25519 生成很快,不是冻结源),把生成好的 keys 通过 `identity` 注入即可。

### `ChatRoute`(联系人路由)

| 字段 | 说明 |
|---|---|
| `address` | 联系人 EOA(小写) |
| `userPublicKeyArmored` | 收件人 **user PGP** 公钥 —— 业务消息加密目标 |
| `routerArmoredPublicKey?` | 收件人 mailbox B route 公钥 —— listen / ACK 加密目标 |
| `routePgpKeyID?` | route keyID(可选) |

---

## API 参考

### `BeamioChatClient`

| 方法 | 说明 |
|---|---|
| `init(): Promise<void>` | 起 Worker、注入 config/nodes、Worker 自动开始 listen。幂等(已起则 no-op) |
| `sendMessage(to, payload, opts?)` | 加密并发送业务 payload 给联系人,经 entry A ≠ B。返回 `{ sendId }` |
| `queryPresence(contacts)` | 探测 mailbox listen-pool 在线;返回 `Record<addrLower, boolean>`(仅 `ok:true` 计入) |
| `setRoutes(routes)` | 更新要监听/探测的联系人集合 |
| `setNodes(nodes)` | 推入刷新后的节点快照(host 拥有发现) |
| `postMailboxCommand(routerArmoredPublicKey, command)` | 加密任意 mailbox 命令(如 `gossip_delivery_ack`)给 route B,经 entry C ≠ B 发送 |
| `on(event, cb): Unsubscribe` | 订阅事件(见下),返回退订函数 |
| `history` | `BeamioChatHistory`(见下) |
| `pause()` / `resume()` | 暂停/恢复 Worker listen |
| `destroy()` | 拆除 Worker 与所有监听(幂等) |

### 事件(`client.on(...)`)

| 事件 | payload | 说明 |
|---|---|---|
| `message` | `InboundEnvelope` | `env.line` = host-ready JSON 明文行(带 `_beamioPgpArmorHash`),交 host 串行队列 checkSign/解析 |
| `delivery` | `DeliveryReceiptEvent` | 送达回执(`sendId` / `deliveredAt` / `from`),host 将己方气泡标 delivered |
| `presence` | `PresenceEvent` | `online: Record<addr, boolean>`,仅可信结果 |
| `status` | `StatusEvent` | `idle`/`connecting`/`listening`/`reconnecting`/`paused`/`error`;`listening` 每次心跳都会发,用于刷新主线程 staleness |
| `log` | `ChatLogEvent` | 结构化日志(不含私钥/明文/完整密文) |
| `historyBuffer` | `HistoryBufferEvent` | 历史恢复/追加时的增量批次,增量喂 UI |

### `client.history`

| 方法 | 说明 |
|---|---|
| `load(options?)` | 恢复加密历史:定位 index(`point-${L}` / IndexedDB) → 解密 → 优先解 tail → 后台回补;发 `historyBuffer` 增量 |
| `append(entry)` | 把新收/发条目写入加密历史 + 本地镜像 |
| `onBuffer(cb): Unsubscribe` | 订阅恢复/追加期间的增量批次 |

`HistoryLoadOptions`:`peer?`(单联系人或全部)、`tailCount?`(默认 60,即"最后 2 屏")、`localOnly?`(仅读 IndexedDB,秒开)。

---

## 零信任路由铁律(SDK 已内建)

遵守 `conet-p2p-mailbox-routing-protocol`、`beamio-conet-chat-protocol`:

- **发送业务**:加密给收件人 **EOA user PGP**,POST 到健康 **entry A ≠ mailbox B**。
- **收件 listen**:加密给 **mailbox B route key**,SSE 连 **entry C ≠ B**,且必带 `listenKind:'chat'`。
- **delivery ACK**:加密给 **mailbox B route key**。
- 绝不直连 mailbox B;绝不把收件人 AA 当作业务加密目标(须 EOA user PGP)。

---

## 加密碎片历史存储

```
master     = keccak256( EOA_sign("beamio.chat.history.v1|chainId|eoa") )   // 私钥不出 Worker
locator L  = HKDF(master, "index-locator")     // 藏于哈希海;服务端 point-${L} 指向当前 index
indexKey   = HKDF(master, "index-enc")         // AES-256-GCM 加密有序 index 清单
碎片棘轮    k_i = HKDF(master, `frag|${seq}|${cid_{i-1}}`)   // cid_{-1}=HKDF(master,"frag-genesis")
           cipher_i = AES-GCM(k_i, plaintext_i);  cid_i = keccak256(cipher_i)  // 上传为 fragment
```

- 所有 `cid_{i-1}` 记录在 index → 任意 `k_i` 可 O(1) 直算,支持**最新优先**恢复。
- **IndexedDB 本地优先**:`localOnly` 秒开;网络失败**不覆盖**已有可信本地历史(`beamio-trusted-vs-untrusted-fetch`)。
- **服务端 `point-` 指针**:内容仍以 `keccak(content)=hash1` 存,额外写别名 `point-${L}` → `hash1`,须 EOA 签名 + owner 绑定 + 单调时间戳(防劫持/防重放)。见 `x402sdk/src/endpoint/fragmentClusterServer.ts`。

---

## 接入 SilentPassUI(Vendored 示例)

由于各子项目为独立 Git 仓、远程构建不便用 `file:` 依赖,SilentPassUI 将 SDK 源码 **vendored** 到 `src/vendor/beamio-chat-sdk/`,通过 `services/chatWorkerBridge.ts` 桥接:

```ts
// services/chatWorkerBridge.ts (要点)
import { createBeamioChatClient } from '../vendor/beamio-chat-sdk'

function makeGossipWorker(): Worker {
  return new Worker(new URL('../vendor/beamio-chat-sdk/worker/entry.ts', import.meta.url), {
    type: 'module',
    name: 'beamio-chat-gossip',
  })
}

const client = createBeamioChatClient(config, { workerFactory: makeGossipWorker })
client.on('message', (env) => { if (env.line) onLine(env.line) })   // → App.tsx addNewMessage
client.on('status', (st) => { if (st.status === 'listening') noteGossipActivity() })
await client.init()
```

`services/chat.ts` 的 `connectToGossipNode` 只在主线程解析路由 + 健康 entry(供 delivery-ACK),入站 LISTEN 循环整体交给 Worker;解密明文行经 `onLine → newMessage → App.tsx addNewMessage` 串行队列不变。

> Vendored 拷贝须与本源码保持同步;修改本 SDK 后需镜像到 `src/SilentPassUI/src/vendor/beamio-chat-sdk/`。vendored 相对 import 去掉 `.js` 后缀以匹配 CRA `moduleResolution:"node"`。

---

## 安全与合规

- 私钥 / 明文 / 完整密文 **不得进日志**;`log` 事件只输出结构化摘要。
- history `master` 只在 Worker 内存;consumer/POS 可本地存私钥、bizSite 仅会话内存(由 host 注入策略决定,SDK 不自持久化)。
- 保持 `listenKind:'chat'`,不直连 mailbox B。
- `point-` 为 CoNET 私有语义;公共网关取回依赖 CIDv1 映射,需文档化。

---

## 构建 / 目录

```bash
npm run build       # tsc -p tsconfig.json → dist/ (ESM + .d.ts)
npm run typecheck   # tsc --noEmit
npm run clean       # rm -rf dist
```

```
src/
  index.ts          # 公共入口:createBeamioChatClient + 类型
  client.ts         # 主线程 BeamioChatClient(起 worker + postMessage 协议)
  protocol.ts       # 主 ↔ worker 的 postMessage 协议
  types.ts          # 公共类型(UI 无关)
  crypto.ts         # WebCrypto + keccak/HKDF/AES-GCM(worker & 主线程通用)
  nodes.ts          # 节点探测(worker/主线程通用)
  worker/
    entry.ts        # Worker 入口(仅在 Worker 上下文导入)
    gossip-core.ts  # SSE + openpgp 解/加密 + 签名 + presence + ACK
    history.ts      # 加密碎片 IPFS 历史 + IndexedDB
```

包导出:

| 入口 | 用途 |
|---|---|
| `@conet-project/chat-sdk` | 主线程 API(`createBeamioChatClient` + 类型) |
| `@conet-project/chat-sdk/worker` | Worker 入口,**仅**在 Worker 上下文中作为 `new Worker(...)` 目标导入 |

---

## 相关规则 / 参考

- `conet-p2p-mailbox-routing-protocol` / `beamio-conet-chat-protocol` —— 路由与信封
- `conet-depin-chat-app-dev` —— APP 实战(回执/presence/listenKind)
- `beamio-trusted-vs-untrusted-fetch` —— 失败不覆盖可信本地
- `x402sdk/src/endpoint/fragmentClusterServer.ts` —— `point-` 指针服务端
- `src-subprojects-are-independent` —— 子项目独立、勿跨仓 import

## License

MIT(私有发布,`publishConfig.access = restricted`)。
