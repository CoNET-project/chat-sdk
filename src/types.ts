/**
 * Beamio Chat SDK — public types.
 *
 * UI-agnostic. No React, no app-specific imports. Everything the SDK needs from
 * the host (private key material, RPC endpoints, node discovery, IPFS base URL,
 * local persistence) is injected through {@link BeamioChatConfig}.
 *
 * Routing rules (do not violate — see repo rules `conet-p2p-mailbox-routing-protocol`,
 * `beamio-conet-chat-protocol`, and `src/docs/gitbook/l0/si-developer-guide.md`):
 *  - Send business payloads encrypted to the recipient EOA *user* PGP, POSTed to an
 *    entry node A ≠ mailbox B.
 *  - Listen SSE is encrypted to mailbox B route key, connected via entry C ≠ B, and
 *    MUST carry `listenKind: 'chat'`.
 *  - Delivery ACK is encrypted to the mailbox B route key.
 *  - Each POST wraps that inner armor to **that entry's** route public key (peel at
 *    the entry). Clients never set `X-CoNET-Hop-Sigs`.
 */

/** A CoNET Guardian / entry / mailbox node descriptor. Mirrors the app `nodeInfo`. */
export interface NodeInfo {
	region: string
	ip_addr: string
	armoredPublicKey: string
	nftNumber: number
	domain: string
	lastEposh?: number
	owner?: string
}

/** Signing material + capabilities the host injects. The SDK never persists private keys itself. */
export interface ChatIdentity {
	/** EOA address (checksummed or lower — SDK normalises). */
	eoaAddress: string
	/**
	 * Raw ethers private key hex (with or without 0x). Used inside the worker to
	 * build an `ethers.Wallet` for EIP-191 signing and to derive the history master
	 * secret. Consumer/POS may inject a persisted key; bizSite injects a
	 * session-memory-only key. The SDK holds it only in the worker's memory.
	 */
	privateKeyHex: string
	/** Armored PGP private key for this identity's chat route (decrypts inbound). */
	pgpPrivateKeyArmored: string
	/** Passphrase for the armored PGP private key, if any. */
	pgpPassphrase?: string
	/** Armored PGP public key (for regiestChatRoute / diagnostics). */
	pgpPublicKeyArmored?: string
	/** This identity's own mailbox route armored public key (mailbox B). */
	ownRouteArmoredPublicKey?: string
}

/** Per-contact chat route metadata resolved from AddressPGP. */
export interface ChatRoute {
	/** Contact EOA address (lower-case). */
	address: string
	/** Recipient's user PGP public key — business payloads are encrypted to this. */
	userPublicKeyArmored: string
	/** Recipient mailbox B route armored public key — listen/ACK/mailbox work are encrypted to this. */
	routerArmoredPublicKey?: string
	routePgpKeyID?: string
}

/** Inbound decrypted line (still to be checkSign'd / parsed by the host). */
export interface InboundEnvelope {
	/**
	 * Host-ready JSON envelope string — exactly what the app's `addNewMessage`
	 * serial queue consumes today (outer `{ timestamp, text, from, signMessage }`
	 * with `_beamioPgpArmorHash` attached for mailbox ACK). Host still runs
	 * `checkSign` + business parse on this on the main thread.
	 */
	line: string
	/** keccak256 of the received PGP armor (matches SI saveLocal hash for delivery ACK). */
	armorHash?: string
	/** True when the inbound frame was a plaintext envelope (no PGP decrypt happened). */
	plain?: boolean
	/** Node domain that forwarded this (diagnostic only). */
	viaDomain?: string
	receivedAt: number
}

export interface DeliveryReceiptEvent {
	sendId: string
	deliveredAt: number
	/** Contact EOA that acknowledged. */
	from?: string
	armorHash?: string
}

export interface PresenceEvent {
	/** Map of contact address(lower) → online. Only trusted `ok:true` replies included. */
	online: Record<string, boolean>
}

export type ChatStatus =
	| 'idle'
	| 'connecting'
	| 'listening'
	| 'reconnecting'
	| 'paused'
	| 'error'

export interface StatusEvent {
	status: ChatStatus
	detail?: string
}

export interface ChatLogEvent {
	level: 'info' | 'warn' | 'error'
	message: string
}

/** History buffer increment fed to the UI during restore / append. */
export interface HistoryBufferEvent {
	/** Contact EOA (lower) this batch belongs to, or 'all' when global. */
	peer: string
	entries: HistoryEntry[]
	/** True when this batch is the tail (most recent) portion. */
	isTail?: boolean
}

/** A single stored history entry (decrypted). */
export interface HistoryEntry {
	seq: number
	ts: number
	/** Contact EOA (lower). */
	peer: string
	/** 'out' = sent by me, 'in' = received. */
	dir: 'in' | 'out'
	sendId?: string
	/** Decrypted plaintext body (the ChatMessage JSON string as the host stored it). */
	body: string
}

export interface ChatEventMap {
	message: InboundEnvelope
	delivery: DeliveryReceiptEvent
	presence: PresenceEvent
	status: StatusEvent
	log: ChatLogEvent
	historyBuffer: HistoryBufferEvent
}

export type ChatEventName = keyof ChatEventMap
export type ChatEventListener<K extends ChatEventName> = (payload: ChatEventMap[K]) => void
export type Unsubscribe = () => void

/**
 * IndexedDB-like persistence adapter (host supplies; SDK stays storage-agnostic).
 * Keys are opaque strings; values are JSON-serialisable.
 */
export interface PersistenceAdapter {
	get(key: string): Promise<unknown | undefined>
	set(key: string, value: unknown): Promise<void>
	delete(key: string): Promise<void>
	/** List keys under a prefix (used for local history fallback). */
	keys?(prefix: string): Promise<string[]>
}

/** How the host wants presence probing / listen scheduled. */
export interface ChatRuntimeOptions {
	/** Send business payload to N entry nodes in parallel (dedupe by sendId on UI). Default 3. */
	sendFanout?: number
	/** Reconnect backoff base ms. Default 4000. */
	reconnectBaseMs?: number
	/** Max reconnect backoff ms. Default 30000. */
	reconnectMaxMs?: number
	/**
	 * Encrypt already-built inner armor to each entry's route public key before
	 * `POST /post` (SI peel). Default `true`. One-layer user-PGP still works if false.
	 */
	outerWrap?: boolean
}

/** Options for {@link BeamioChatClient.sendMessage}. */
export interface SendMessageOptions {
	sendId?: string
	/**
	 * Skip APNs / offline push. SDK wraps the user-PGP armor as mailbox work
	 * `{ data, NoPush: true }` encrypted to the recipient mailbox route key.
	 * HTTP `POST /post` stays `{ data }` only.
	 */
	beamioNoPush?: boolean
}

export interface BeamioChatConfig {
	identity: ChatIdentity
	/** CoNET DePIN RPC endpoint (read AddressPGP etc.). */
	conetRpcUrl: string
	/** AddressPGP contract address. */
	addressPgpContractAddress: string
	/**
	 * Returns the current healthy CoNET node list. Host owns discovery/caching so the
	 * SDK never couples to a specific contract-read implementation.
	 */
	getNodes: () => Promise<NodeInfo[]>
	/** IPFS fragment gateway base, e.g. `https://ipfs.conet.network/api`. */
	ipfsBaseUrl: string
	/** Optional IPFS write base (defaults to `ipfsBaseUrl`). */
	ipfsWriteBaseUrl?: string
	/** Local persistence (IndexedDB adapter). Optional; history still works in-memory without it. */
	persistence?: PersistenceAdapter
	runtime?: ChatRuntimeOptions
	/** Chain id used in history master derivation domain string. Default 224422 (CoNET L1). */
	chainId?: number
	/**
	 * ChatIndexRegistry proxy (CoNET 224422) — on-chain head pointer to the encrypted
	 * history index (IPFS content hash). Read via RPC `getPointer(eoa)`; write via the
	 * gasless relay ({@link apiBaseUrl}/setChatIndexPointer). Default = canonical proxy.
	 */
	chatIndexRegistryAddress?: string
	/**
	 * Cluster API base for the gasless index-pointer relay, e.g. `https://beamio.app`.
	 * When absent, history still persists to IPFS + local mirror, but the on-chain head
	 * pointer is not updated (fresh-device recovery would be unavailable).
	 */
	apiBaseUrl?: string
}

/** History load options. */
export interface HistoryLoadOptions {
	/** Restore for a single contact, or all known contacts. */
	peer?: string
	/** How many most-recent entries to decrypt eagerly (the "last 2 screens"). Default 60. */
	tailCount?: number
	/** When true, skip network and only read the local IndexedDB mirror (instant open). */
	localOnly?: boolean
}

export interface BeamioChatHistory {
	/**
	 * Restore encrypted history: read the on-chain head pointer (RPC `getPointer(eoa)`) or the
	 * local IndexedDB mirror → fetch + decrypt the index → eagerly decrypt the tail → backfill
	 * older entries in the background. Emits `historyBuffer` increments as they become available.
	 */
	load(options?: HistoryLoadOptions): Promise<void>
	/** Append (persist) a new sent/received entry to encrypted history + local mirror. */
	append(entry: Omit<HistoryEntry, 'seq'>): Promise<void>
	/** Subscribe to incremental buffer batches during restore/append. */
	onBuffer(cb: (batch: HistoryBufferEvent) => void): Unsubscribe
}

export interface BeamioChatClient {
	init(): Promise<void>
	/** Encrypt & send a business payload to a contact via entry A ≠ mailbox B. */
	sendMessage(to: ChatRoute, payload: string, opts?: SendMessageOptions): Promise<{ sendId: string }>
	/** Encrypt a mailbox command (e.g. gossip_delivery_ack) to route B and POST via entry C ≠ B. */
	postMailboxCommand(
		routerArmoredPublicKey: string,
		command: Record<string, unknown>,
	): Promise<boolean>
	on<K extends ChatEventName>(event: K, cb: ChatEventListener<K>): Unsubscribe
	/** Probe mailbox listen-pool presence for the given contacts. */
	queryPresence(contacts: ChatRoute[]): Promise<Record<string, boolean>>
	/** Update the set of contacts to listen for and probe. */
	setRoutes(routes: ChatRoute[]): void
	history: BeamioChatHistory
	pause(): void
	resume(): void
	destroy(): void
}
