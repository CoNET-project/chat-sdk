/**
 * Main-thread {@link BeamioChatClient} implementation. Boots the gossip Worker,
 * marshals commands, and re-emits worker events. Zero openpgp/verify on the main
 * thread — all heavy crypto runs in the worker.
 *
 * The host supplies the Worker instance (via `workerFactory`) so the SDK stays
 * bundler-agnostic: CRA/Vite/webpack each create the worker their own way, e.g.
 *   new Worker(new URL('@beamio/chat-sdk/worker', import.meta.url), { type: 'module' })
 */

import type {
	BeamioChatClient,
	BeamioChatConfig,
	BeamioChatHistory,
	ChatEventListener,
	ChatEventName,
	ChatRoute,
	SendMessageOptions,
	HistoryBufferEvent,
	HistoryEntry,
	HistoryLoadOptions,
	HistoryReadOptions,
	NodeInfo,
	Unsubscribe,
} from './types.js'
import type { WorkerInbound, WorkerInitPayload, WorkerOutbound } from './protocol.js'

export interface BeamioChatClientOptions {
	/**
	 * Host-created Worker running `@beamio/chat-sdk/worker`. Required — the SDK never
	 * hard-codes a worker URL so it works under any bundler / native shell.
	 */
	workerFactory: () => Worker
}

const DEFAULT_RUNTIME = {
	sendFanout: 3,
	reconnectBaseMs: 4_000,
	reconnectMaxMs: 30_000,
	outerWrap: true,
} as const

type Emitter = {
	[K in ChatEventName]: Set<ChatEventListener<K>>
}

class ChatHistoryBridge implements BeamioChatHistory {
	private bufferListeners = new Set<(batch: HistoryBufferEvent) => void>()

	constructor(private readonly client: BeamioChatClientImpl) {}

	load(options?: HistoryLoadOptions): Promise<void> {
		return this.client.request<void>({ type: 'historyLoad', reqId: 0, options })
	}

	append(entry: Omit<HistoryEntry, 'seq'>): Promise<void> {
		return this.client.request<void>({ type: 'historyAppend', reqId: 0, entry })
	}

	read(options?: HistoryReadOptions): Promise<HistoryEntry[]> {
		return this.client.request<HistoryEntry[]>({ type: 'historyRead', reqId: 0, options }, 60_000)
	}

	onBuffer(cb: (batch: HistoryBufferEvent) => void): Unsubscribe {
		this.bufferListeners.add(cb)
		return () => this.bufferListeners.delete(cb)
	}

	_emit(batch: HistoryBufferEvent): void {
		for (const cb of this.bufferListeners) {
			try {
				cb(batch)
			} catch {
				/* listener errors isolated */
			}
		}
	}
}

class BeamioChatClientImpl implements BeamioChatClient {
	private worker: Worker | null = null
	private reqSeq = 1
	private pending = new Map<number, { resolve: (v: unknown) => void; reject: (e: Error) => void }>()
	private listeners: Emitter = {
		message: new Set(),
		delivery: new Set(),
		presence: new Set(),
		status: new Set(),
		log: new Set(),
		historyBuffer: new Set(),
		voiceFrame: new Set(),
	}
	private historyBridge: ChatHistoryBridge
	private routes: ChatRoute[] = []
	private nodes: NodeInfo[] = []
	private destroyed = false

	constructor(
		private readonly config: BeamioChatConfig,
		private readonly options: BeamioChatClientOptions,
	) {
		this.historyBridge = new ChatHistoryBridge(this)
	}

	get history(): BeamioChatHistory {
		return this.historyBridge
	}

	async init(): Promise<void> {
		if (this.worker) return
		this.worker = this.options.workerFactory()
		this.worker.addEventListener('message', (ev: MessageEvent<WorkerOutbound>) => this.onWorkerMessage(ev.data))
		this.worker.addEventListener('error', (ev: ErrorEvent) => {
			this.emit('log', { level: 'error', message: `worker error: ${ev.message}` })
		})
		this.nodes = await this.config.getNodes().catch(() => [])
		this.routes = []
		const payload: WorkerInitPayload = {
			identity: this.config.identity,
			conetRpcUrl: this.config.conetRpcUrl,
			addressPgpContractAddress: this.config.addressPgpContractAddress,
			ipfsBaseUrl: this.config.ipfsBaseUrl,
			ipfsWriteBaseUrl: this.config.ipfsWriteBaseUrl,
			chainId: this.config.chainId ?? 224422,
			chatIndexRegistryAddress:
				this.config.chatIndexRegistryAddress ?? '0x1511Caa71081C84d8a591490D1b83879088EED72',
			apiBaseUrl: this.config.apiBaseUrl,
			runtime: { ...DEFAULT_RUNTIME, ...(this.config.runtime ?? {}) },
			nodes: this.nodes,
			routes: this.routes,
		}
		await this.request<void>({ type: 'init', reqId: 0, payload })
	}

	setRoutes(routes: ChatRoute[]): void {
		this.routes = routes || []
		this.postCommand({ type: 'setRoutes', routes: this.routes })
	}

	/** Push a refreshed node snapshot into the worker (host owns discovery). */
	setNodes(nodes: NodeInfo[]): void {
		if (!nodes?.length) return
		this.nodes = nodes
		this.postCommand({ type: 'setNodes', nodes })
	}

	async sendMessage(to: ChatRoute, payload: string, opts?: SendMessageOptions): Promise<{ sendId: string }> {
		const sendId = opts?.sendId || `${Date.now()}-${Math.random().toString(36).slice(2, 10)}`
		await this.request<unknown>({
			type: 'send',
			reqId: 0,
			to,
			payload,
			sendId,
			beamioNoPush: opts?.beamioNoPush,
		})
		return { sendId }
	}

	async queryPresence(contacts: ChatRoute[]): Promise<Record<string, boolean>> {
		return this.request<Record<string, boolean>>({ type: 'queryPresence', reqId: 0, contacts })
	}

	/** After presence: true/false when the mailbox lookup is trusted; null when it is not. */
	async queryNativeWake(contact: ChatRoute): Promise<boolean | null> {
		return this.request<boolean | null>({ type: 'queryNativeWake', reqId: 0, contact })
	}

	/** Encrypt & POST an arbitrary mailbox command (e.g. gossip_delivery_ack) to route B via entry C ≠ B. */
	async postMailboxCommand(
		routerArmoredPublicKey: string,
		command: Record<string, unknown>,
	): Promise<boolean> {
		const r = await this.request<{ sent: boolean }>({
			type: 'mailboxCommand',
			reqId: 0,
			routerArmoredPublicKey,
			command,
		})
		return !!r?.sent
	}

	/** Encrypt and post a command to this wallet's own mailbox route. */
	async postOwnMailboxCommand(command: Record<string, unknown>): Promise<boolean> {
		const r = await this.request<{ sent: boolean }>({
			type: 'ownMailboxCommand',
			reqId: 0,
			command,
		})
		return !!r?.sent
	}

	async sendVoiceFrame(routerArmoredPublicKey: string, frame: Record<string, unknown>): Promise<boolean> {
		const r = await this.request<{ sent: boolean }>({
			type: 'voiceFrame',
			reqId: 0,
			routerArmoredPublicKey,
			frame,
		})
		return !!r?.sent
	}

	async startVoiceListen(
		sessionId: string,
		pushWakeup?: {
			callId: string
			calleeEoa: string
			expiresAt: number
			timestamp: number
			offerText?: string
			recipientPgp?: string
		},
	): Promise<boolean> {
		const r = await this.request<{ started: boolean }>({ type: 'voiceListen', reqId: 0, sessionId, pushWakeup })
		return !!r?.started
	}

	async stopVoiceListen(sessionId: string): Promise<boolean> {
		const r = await this.request<{ stopped: boolean }>({ type: 'voiceUnlisten', reqId: 0, sessionId })
		return !!r?.stopped
	}

	on<K extends ChatEventName>(event: K, cb: ChatEventListener<K>): Unsubscribe {
		this.listeners[event].add(cb as never)
		return () => this.listeners[event].delete(cb as never)
	}

	pause(): void {
		this.postCommand({ type: 'pause' })
	}

	resume(): void {
		this.postCommand({ type: 'resume' })
	}

	destroy(): void {
		if (this.destroyed) return
		this.destroyed = true
		this.postCommand({ type: 'destroy' })
		for (const { reject } of this.pending.values()) reject(new Error('client destroyed'))
		this.pending.clear()
		try {
			this.worker?.terminate()
		} catch {
			/* ignore */
		}
		this.worker = null
	}

	// ---- internals ------------------------------------------------------------
	request<T>(cmd: WorkerInbound & { reqId: number }, timeoutMs = 20_000): Promise<T> {
		if (!this.worker) return Promise.reject(new Error('client not initialised'))
		const reqId = this.reqSeq++
		const message = { ...cmd, reqId } as WorkerInbound
		return new Promise<T>((resolve, reject) => {
			const timer = setTimeout(() => {
				if (!this.pending.has(reqId)) return
				this.pending.delete(reqId)
				reject(new Error('Chat worker did not respond'))
			}, timeoutMs)
			this.pending.set(reqId, {
				resolve: (value) => {
					clearTimeout(timer)
					resolve(value as T)
				},
				reject: (error) => {
					clearTimeout(timer)
					reject(error)
				},
			})
			this.worker!.postMessage(message)
		})
	}

	private postCommand(cmd: WorkerInbound): void {
		this.worker?.postMessage(cmd)
	}

	private emit<K extends ChatEventName>(event: K, payload: Parameters<ChatEventListener<K>>[0]): void {
		for (const cb of this.listeners[event]) {
			try {
				;(cb as ChatEventListener<K>)(payload)
			} catch {
				/* isolate listener errors */
			}
		}
	}

	private onWorkerMessage(msg: WorkerOutbound): void {
		switch (msg.type) {
			case 'ready':
			case 'ack': {
				const reqId = msg.reqId
				const p = this.pending.get(reqId)
				if (!p) return
				this.pending.delete(reqId)
				if (msg.type === 'ready') {
					p.resolve(undefined)
				} else if (msg.ok) {
					p.resolve(msg.result)
				} else {
					p.reject(new Error(msg.error))
				}
				return
			}
			case 'event:message':
				this.emit('message', msg.payload)
				return
			case 'event:delivery':
				this.emit('delivery', msg.payload)
				return
			case 'event:presence':
				this.emit('presence', msg.payload)
				return
			case 'event:status':
				this.emit('status', msg.payload)
				return
			case 'event:historyBuffer':
				this.emit('historyBuffer', msg.payload)
				this.historyBridge._emit(msg.payload)
				return
			case 'event:voiceFrame':
				this.emit('voiceFrame', msg.payload)
				return
			case 'event:log':
				this.emit('log', { level: msg.level, message: msg.message })
				return
			case 'nodesRequest': {
				void this.config
					.getNodes()
					.then((nodes) => {
						this.nodes = nodes
						this.postCommand({ type: 'nodesResponse', reqId: msg.reqId, nodes } as WorkerInbound)
					})
					.catch(() => {
						this.postCommand({ type: 'nodesResponse', reqId: msg.reqId, nodes: this.nodes } as WorkerInbound)
					})
				return
			}
			default:
				return
		}
	}
}

/** Factory: create a chat client. Call `init()` before use. */
export function createBeamioChatClient(
	config: BeamioChatConfig,
	options: BeamioChatClientOptions,
): BeamioChatClient & {
	setNodes(nodes: NodeInfo[]): void
	postMailboxCommand(
		routerArmoredPublicKey: string,
		command: Record<string, unknown>,
	): Promise<boolean>
} {
	return new BeamioChatClientImpl(config, options)
}
