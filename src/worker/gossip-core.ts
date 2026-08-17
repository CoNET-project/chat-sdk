/**
 * Gossip core — runs entirely inside the Worker. All `openpgp` encrypt/decrypt
 * happens here so the main thread never blocks (root cause of the multi-second
 * freeze in SilentPassUI `services/chat.ts` L945-955 inbound decrypt).
 *
 * Ported from SilentPassUI `services/chat.ts`:
 *  - `startGossip` (SSE connect/reconnect, entry health, single in-flight read)
 *  - inbound decrypt → emit host-ready line
 *  - `sendMessage` (encrypt → POST to entry A ≠ B)
 *  - `wallet_online_query` presence (encrypt to mailbox B route key, POST via C ≠ B)
 *
 * Routing rules preserved (repo `conet-p2p-mailbox-routing-protocol`,
 * `beamio-conet-chat-protocol`, `src/docs/gitbook/l0/si-developer-guide.md`):
 * listen encrypted to mailbox B route key via entry C ≠ B with `listenKind:'chat'`;
 * business payload encrypted to recipient EOA user PGP via entry A ≠ B; ACK
 * encrypted to mailbox B route key. Each POST wraps inner armor to **that entry's**
 * route public key. Clients never set `X-CoNET-Hop-Sigs`.
 */

import {
	createMessage,
	decrypt,
	decryptKey,
	encrypt,
	enums,
	readKey,
	readMessage,
	readPrivateKey,
	type PrivateKey,
} from 'openpgp'
import { ethers } from 'ethers'

import type { ChatRoute, NodeInfo, PresenceEvent, StatusEvent } from '../types.js'
import type { WorkerInitPayload } from '../protocol.js'
import {
	getRandomNode,
	getRandomNodes,
	markGossipNodeBad,
	markGossipNodeHealthy,
	pickGossipEntryNodesForSend,
	pickListenEntryNodes,
	pickRouteNodesByArmoredKey,
	postUrl,
	postWithTimeout,
} from '../nodes.js'
import { base64ToUtf8, keccakUtf8, utf8ToBase64 } from '../crypto.js'
import { buildPostBody, encryptRouteCommand, wrapArmorToEntryRoute, wrapArmorToMailboxWork } from '../envelope.js'

/** Callbacks the worker entry wires to `postMessage`. */
export interface GossipEmit {
	message(line: string, armorHash: string | undefined, plain: boolean, viaDomain?: string): void
	status(status: StatusEvent['status'], detail?: string): void
	log(level: 'info' | 'warn' | 'error', message: string): void
	presence(payload: PresenceEvent): void
}

interface TimeoutConfig {
	connectTimeout: number
	idleTimeout: number
	readOperationTimeout: number
	retryDelay: number
}

const GOSSIP_STOP_REASONS = new Set([
	'root_stop',
	'replaced_by_new_connection',
	'component_unmount',
	'relaunching',
	'connect_failed',
	'foreground_resume',
	'background_pause',
	'destroy',
])

function extractGossipListingBlockHeight(payload: unknown): string | null {
	if (!payload || typeof payload !== 'object') return null
	const epoch = (payload as Record<string, unknown>).epoch
	if (epoch == null) return null
	if (typeof epoch === 'number' && Number.isFinite(epoch)) return String(Math.trunc(epoch))
	if (typeof epoch === 'string' && epoch.trim()) return epoch.trim()
	return null
}

function isGossipListingLivenessFrame(payload: unknown): boolean {
	if (!payload || typeof payload !== 'object') return false
	const row = payload as Record<string, unknown>
	if (typeof row.ipaddress === 'string' || 'nodeWallets' in row) return true
	return row.status != null && row.epoch != null
}

export class GossipCore {
	private cfg: WorkerInitPayload | null = null
	private nodes: NodeInfo[] = []
	private routes: ChatRoute[] = []
	private wallet: ethers.Wallet | null = null
	private pgpPrivateKey: PrivateKey | null = null
	private userPgpKeyID = ''
	private listenController: AbortController | null = null
	private lastActivityAt = 0
	private paused = false
	/** Listen `Securitykey` (aes-256-cbc). Sent on the command; live SI SSE frames are still plaintext JSON. */
	private listenSecurityKey = ''
	private ackContext: {
		routerArmoredPublicKey: string
		entryNodes: NodeInfo[]
		mailboxDomains: string[]
	} | null = null

	constructor(private readonly emit: GossipEmit) {}

	async init(payload: WorkerInitPayload): Promise<void> {
		this.cfg = payload
		this.nodes = payload.nodes || []
		this.routes = payload.routes || []
		const pkHex = payload.identity.privateKeyHex.startsWith('0x')
			? payload.identity.privateKeyHex
			: `0x${payload.identity.privateKeyHex}`
		this.wallet = new ethers.Wallet(pkHex)
		const pk = await readPrivateKey({ armoredKey: payload.identity.pgpPrivateKeyArmored })
		this.pgpPrivateKey = pk.isDecrypted()
			? pk
			: await decryptKey({ privateKey: pk, passphrase: payload.identity.pgpPassphrase || '' })
		if (payload.identity.pgpPublicKeyArmored) {
			try {
				const keyObj = await readKey({ armoredKey: payload.identity.pgpPublicKeyArmored })
				this.userPgpKeyID = keyObj.getKeyIDs()[1].toHex().toUpperCase()
			} catch {
				/* keyID optional */
			}
		}
		this.paused = false
		await this.startListen()
	}

	setNodes(nodes: NodeInfo[]): void {
		if (nodes?.length) this.nodes = nodes
	}

	setRoutes(routes: ChatRoute[]): void {
		this.routes = routes || []
	}

	pause(): void {
		this.paused = true
		this.listenSecurityKey = ''
		this.clearListen('background_pause')
		this.lastActivityAt = 0
		this.emit.status('paused')
	}

	resume(): void {
		if (!this.paused && this.listenController && !this.listenController.signal.aborted) return
		this.paused = false
		void this.startListen()
	}

	destroy(): void {
		this.clearListen('destroy')
		this.wallet = null
		this.pgpPrivateKey = null
		this.cfg = null
	}

	private clearListen(reason: string): void {
		if (this.listenController) {
			try {
				this.listenController.abort(reason)
			} catch {
				/* ignore */
			}
			this.listenController = null
		}
	}

	// ---- Listen (mailbox B route key, entry C ≠ B, listenKind:'chat') -----------
	private async startListen(): Promise<void> {
		if (this.paused) return
		if (!this.cfg || !this.wallet || !this.pgpPrivateKey) return
		if (this.listenController && !this.listenController.signal.aborted) {
			this.emit.log('info', 'listen skipped: SSE already live')
			return
		}
		this.listenController = null

		// Resolve mailbox B route from the identity's own route (host injects own route key).
		const ownRouteKey = this.cfg.identity.ownRouteArmoredPublicKey || ''
		if (!ownRouteKey) {
			this.emit.log('warn', 'listen: empty mailbox route key; awaiting identity')
			this.emit.status('reconnecting', 'awaiting_route_key')
			setTimeout(() => void this.startListen(), 6_000)
			return
		}
		const routeNodes = pickRouteNodesByArmoredKey(this.nodes, ownRouteKey)
		if (!routeNodes.length) {
			this.emit.log('warn', 'listen: mailbox B not in Guardian list; posting via any entry')
		}
		const mailboxDomains = new Set(routeNodes.map((n) => n.domain))

		this.emit.status('connecting')
		const controller = new AbortController()
		this.listenController = controller
		const rootSignal = controller.signal

		try {
			const key = utf8ToBase64(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(16))))
			this.listenSecurityKey = key
			const innerArmor = await encryptRouteCommand(
				this.wallet,
				{
					command: 'mining',
					listenKind: 'chat',
					walletAddress: this.wallet.address,
					algorithm: 'aes-256-cbc',
					Securitykey: key,
				},
				ownRouteKey,
			)

			const listenEntries = pickListenEntryNodes(this.nodes, mailboxDomains)
			if (!listenEntries.length) {
				this.emit.log('warn', 'listen: empty node pool; retry')
				this.emit.status('reconnecting', 'no_entry_c')
				this.clearListen('connect_failed')
				setTimeout(() => void this.startListen(), 6_000)
				return
			}
			this.ackContext = {
				routerArmoredPublicKey: ownRouteKey,
				entryNodes: listenEntries,
				mailboxDomains: [...mailboxDomains],
			}

			this.emit.log('info', `listen starting via POST /post entries=${listenEntries.length}`)
			this.spawnGossip(listenEntries, innerArmor, rootSignal)
		} catch (ex) {
			this.emit.log('error', `startListen error: ${(ex as Error)?.message ?? String(ex)}`)
			this.clearListen('connect_failed')
			this.emit.status('error', (ex as Error)?.message)
			setTimeout(() => void this.startListen(), 6_000)
		}
	}

	private spawnGossip(
		nodes: NodeInfo[],
		innerArmor: string,
		rootSignal: AbortSignal,
		timeoutConfig?: Partial<TimeoutConfig>,
		reconnectAttempt = 0,
	): void {
		if (rootSignal.aborted) return
		if (!nodes.length) return
		const node = getRandomNode(nodes)!
		const config: TimeoutConfig = {
			connectTimeout: 12_000,
			idleTimeout: 90_000,
			readOperationTimeout: 20_000,
			retryDelay: 2_000,
			...timeoutConfig,
		}
		const url = postUrl(node.domain)
		const controller = new AbortController()
		const onRootAbort = () => controller.abort('root_stop')
		rootSignal.addEventListener('abort', onRootAbort)

		let isRelaunching = false
		const triggerRelaunch = (reason?: string) => {
			if (rootSignal.aborted) return
			if (isRelaunching) return
			isRelaunching = true
			rootSignal.removeEventListener('abort', onRootAbort)
			try {
				controller.abort('relaunching')
			} catch {
				/* ignore */
			}
			const nextAttempt = reconnectAttempt + 1
			const delay = Math.min(30_000, Math.round(config.retryDelay * Math.pow(1.6, Math.min(nextAttempt, 8))))
			setTimeout(() => {
				if (rootSignal.aborted) return
				this.emit.log('info', `reconnecting entry C attempt=${nextAttempt} reason=${reason || 'stream_end'}`)
				const remaining = nodes.filter((n) => n.domain !== node.domain)
				this.spawnGossip(remaining.length ? remaining : nodes, innerArmor, rootSignal, timeoutConfig, nextAttempt)
			}, delay)
		}

		let connectTimer: ReturnType<typeof setTimeout> | null = null
		let idleTimer: ReturnType<typeof setTimeout> | null = null
		const resetIdle = () => {
			if (idleTimer) clearTimeout(idleTimer)
			idleTimer = setTimeout(() => controller.abort('idle_timeout'), config.idleTimeout)
		}

		void (async () => {
			let reader: ReadableStreamDefaultReader<Uint8Array> | undefined
			let pendingRead: Promise<ReadableStreamReadResult<Uint8Array>> | null = null
			try {
				const armored =
					this.cfg?.runtime.outerWrap === false
						? innerArmor
						: await wrapArmorToEntryRoute(innerArmor, node.armoredPublicKey)
				connectTimer = setTimeout(() => controller.abort('connect_timeout'), config.connectTimeout)
				const res = await fetch(url, {
					method: 'POST',
					headers: {
						'Content-Type': 'application/json;charset=UTF-8',
						Accept: 'text/event-stream',
						Connection: 'keep-alive',
					},
					body: JSON.stringify(buildPostBody(armored)),
					signal: controller.signal,
					cache: 'no-store',
				})
				if (connectTimer) clearTimeout(connectTimer)
				if (!res.ok || !res.body) throw new Error(`HTTP ${res.status}`)
				markGossipNodeHealthy(node.domain)
				this.lastActivityAt = Date.now()
				reconnectAttempt = 0
				this.emit.status('listening')
				this.emit.log('info', `listen SSE open entry=${node.domain}`)
				reader = res.body.getReader()
				const decoder = new TextDecoder('utf-8')
				let buffer = ''
				resetIdle()

				while (true) {
					// eslint-disable-next-line no-throw-literal -- string stop-reason protocol (see resolveAbortReason)
					if (rootSignal.aborted) throw 'root_stop'
					if (controller.signal.aborted) throw controller.signal.reason
					let readResult: ReadableStreamReadResult<Uint8Array>
					let readTimer: ReturnType<typeof setTimeout> | undefined
					try {
						if (!pendingRead) pendingRead = reader.read()
						const timeoutPromise = new Promise<never>((_, reject) => {
							readTimer = setTimeout(() => reject(new Error('read_operation_timeout')), config.readOperationTimeout)
						})
						readResult = await Promise.race([pendingRead, timeoutPromise])
						pendingRead = null
					} catch (readErr: unknown) {
						if ((readErr as Error)?.message === 'read_operation_timeout') {
							// eslint-disable-next-line no-throw-literal -- string stop-reason protocol (see resolveAbortReason)
							if (rootSignal.aborted) throw 'root_stop'
							if (controller.signal.aborted) throw controller.signal.reason
							continue
						}
						pendingRead = null
						throw readErr
					} finally {
						if (readTimer) clearTimeout(readTimer)
					}

					const { value, done } = readResult
					if (done) break
					resetIdle()
					reconnectAttempt = 0
					this.lastActivityAt = Date.now()
					buffer += decoder.decode(value, { stream: true })

					let idx: number
					while ((idx = buffer.indexOf('\r\n\r\n')) !== -1 || (idx = buffer.indexOf('\n\n')) !== -1) {
						const isFour = buffer.substring(idx, idx + 4) === '\r\n\r\n'
						const separatorLen = isFour ? 4 : 2
						const block = buffer.slice(0, idx)
						buffer = buffer.slice(idx + separatorLen)
						const lines = block.split('\n')
						const dataLines = lines.filter((l) => l.startsWith('data:')).map((l) => l.slice(5).trimStart())
						const payload = (dataLines.length ? dataLines.join('\n') : block).trim()
						if (!payload) continue
						await this.handleInbound(payload, node.domain, rootSignal)
					}
				}
				triggerRelaunch('server_closed')
			} catch (err: unknown) {
				if (connectTimer) clearTimeout(connectTimer)
				if (idleTimer) clearTimeout(idleTimer)
				const msg = this.resolveAbortReason(err, controller, rootSignal)
				if (GOSSIP_STOP_REASONS.has(msg)) return
				if ((err as { name?: string })?.name === 'AbortError' && rootSignal.aborted) return
				if ((err as { name?: string })?.name !== 'AbortError') {
					this.emit.log('warn', `SSE error (${node.domain}): ${msg}`)
				}
				if (msg === 'connect_timeout' || msg === 'idle_timeout' || msg === 'Failed to fetch') {
					markGossipNodeBad(node.domain)
				}
				triggerRelaunch(msg)
			} finally {
				rootSignal.removeEventListener('abort', onRootAbort)
				if (reader) {
					try {
						await reader.cancel()
						reader.releaseLock()
					} catch {
						/* ignore */
					}
				}
			}
		})()
	}

	private resolveAbortReason(err: unknown, controller: AbortController, rootSignal: AbortSignal): string {
		if (typeof err === 'string' && err) return err
		const signalReason = controller.signal.reason ?? rootSignal.reason
		if (typeof signalReason === 'string' && signalReason) return signalReason
		if (err && typeof err === 'object' && 'message' in err && typeof (err as Error).message === 'string') {
			return (err as Error).message
		}
		return 'unknown'
	}

	private async handleInbound(rawData: string, viaDomain: string, rootSignal: AbortSignal): Promise<void> {
		if (rootSignal.aborted) return
		let data: Record<string, unknown>
		try {
			data = JSON.parse(rawData)
		} catch {
			return
		}
		if (isGossipListingLivenessFrame(data) && extractGossipListingBlockHeight(data)) {
			// Liveness/listing frame: no business payload, but proves the SSE is alive.
			// Refresh internal activity + surface a heartbeat so the host can keep its
			// own foreground/background staleness timer fresh (parity with the old
			// main-thread noteGossipActivity() that fired on every frame).
			this.lastActivityAt = Date.now()
			const height = extractGossipListingBlockHeight(data)
			this.emit.status('listening', 'heartbeat')
			this.emit.log('info', height ? `heartbeat epoch=${height}` : 'heartbeat')
			return
		}
		try {
			const armored = typeof data.data === 'string' ? data.data : ''
			if (armored && /^-----BEGIN PGP MESSAGE-----/i.test(armored)) {
				const msg = await readMessage({ armoredMessage: armored })
				const { data: decrypted } = await decrypt({ message: msg, decryptionKeys: this.pgpPrivateKey! })
				const decryptedString = typeof decrypted === 'string' ? decrypted : String(decrypted)
				const kkk = base64ToUtf8(decryptedString)
				const armorHash = keccakUtf8(armored)
				let line = kkk
				try {
					const env = JSON.parse(kkk)
					if (env && typeof env === 'object') {
						env._beamioPgpArmorHash = armorHash
						line = JSON.stringify(env)
					}
				} catch {
					/* keep raw */
				}
				this.emit.message(line, armorHash, false, viaDomain)
			} else if (data.from && data.text != null && data.signMessage) {
				this.emit.message(JSON.stringify(data), undefined, true, viaDomain)
			}
		} catch (ex: unknown) {
			const msg = (ex as Error)?.message ?? String(ex)
			if (msg.includes('No decryption key packets found')) {
				this.emit.log('warn', 'inbound PGP is not for this listen key (stale contact publicArmored or wrong recipient)')
				return
			}
			this.emit.log('warn', `inbound parse error: ${msg}`)
		}
	}

	// ---- Send (recipient EOA user PGP, entry A ≠ B, wrap to each A) ------------
	async send(to: ChatRoute, text: string, opts?: { beamioNoPush?: boolean }): Promise<boolean> {
		if (!this.wallet) throw new Error('not initialised')
		const pgpPublic = to.userPublicKeyArmored?.trim()
		if (!pgpPublic) {
			this.emit.log('error', 'send: missing recipient userPublicKeyArmored')
			return false
		}
		const signMessage = await this.wallet.signMessage(text)
		const message = { timestamp: Date.now(), text, from: this.wallet.address, signMessage }
		let innerArmor: string
		try {
			const encObj = {
				message: await createMessage({ text: utf8ToBase64(JSON.stringify(message)) }),
				encryptionKeys: await readKey({ armoredKey: pgpPublic }),
				config: { preferredCompressionAlgorithm: enums.compression.zlib },
			}
			innerArmor = await encrypt(encObj)
		} catch (ex: unknown) {
			this.emit.log('error', `send encrypt error: ${(ex as Error)?.message ?? String(ex)}`)
			return false
		}
		if (opts?.beamioNoPush) {
			const mailboxKey = to.routerArmoredPublicKey?.trim()
			if (!mailboxKey) {
				this.emit.log('error', 'send: NoPush requires recipient mailbox routerArmoredPublicKey')
				return false
			}
			try {
				innerArmor = await wrapArmorToMailboxWork(innerArmor, mailboxKey, { NoPush: true })
			} catch (ex: unknown) {
				this.emit.log('error', `send mailbox wrap error: ${(ex as Error)?.message ?? String(ex)}`)
				return false
			}
		}
		const mailboxDomains = new Set(pickRouteNodesByArmoredKey(this.nodes, to.routerArmoredPublicKey || '').map((n) => n.domain))
		return this.postToEntries(innerArmor, mailboxDomains)
	}

	private async postToEntries(
		innerArmor: string,
		excludeDomains: Set<string>,
	): Promise<boolean> {
		const send = async (targets: NodeInfo[]): Promise<boolean> => {
			if (!targets.length) return false
			const results = await Promise.all(
				targets.map(async (node) => {
					const url = postUrl(node.domain)
					try {
						const armored =
							this.cfg?.runtime.outerWrap === false
								? innerArmor
								: await wrapArmorToEntryRoute(innerArmor, node.armoredPublicKey)
						const res = await postWithTimeout(
							url,
							{
								method: 'POST',
								headers: { 'Content-Type': 'application/json' },
								body: JSON.stringify(buildPostBody(armored)),
								referrerPolicy: 'no-referrer',
							},
							12_000,
						)
						if (!res.ok) {
							markGossipNodeBad(node.domain)
							return false
						}
						markGossipNodeHealthy(node.domain)
						return true
					} catch {
						markGossipNodeBad(node.domain)
						return false
					}
				}),
			)
			return results.some(Boolean)
		}
		const fanout = this.cfg?.runtime.sendFanout ?? 3
		const wave1 = await pickGossipEntryNodesForSend(this.nodes, Math.min(fanout + 1, this.nodes.length), excludeDomains)
		if (await send(wave1)) return true
		const tried = new Set([...excludeDomains, ...wave1.map((n) => n.domain)])
		const wave2 = await pickGossipEntryNodesForSend(this.nodes, Math.min(fanout + 1, this.nodes.length), tried)
		return send(wave2)
	}

	// ---- Presence (wallet_online_query, encrypt to mailbox B, POST via C ≠ B) --
	async queryPresence(contacts: ChatRoute[]): Promise<Record<string, boolean>> {
		const out: Record<string, boolean> = {}
		if (!this.wallet || !contacts.length) return out
		await Promise.all(
			contacts.map(async (c) => {
				const addr = (c.address || '').trim().toLowerCase()
				const route = (c.routerArmoredPublicKey || '').trim()
				if (!addr || !ethers.isAddress(addr) || !route) return
				const routeNodes = pickRouteNodesByArmoredKey(this.nodes, route)
				const mailboxDomains = new Set(routeNodes.map((n) => n.domain).filter(Boolean))
				const r = await this.walletOnlineQuery(addr, route, mailboxDomains)
				if (r?.ok) out[addr] = r.online
			}),
		)
		this.emit.presence({ online: out })
		return out
	}

	private async walletOnlineQuery(
		targetWallet: string,
		routerArmoredPublicKey: string,
		mailboxDomains: Set<string>,
	): Promise<{ ok: boolean; online: boolean } | null> {
		if (!this.wallet) return null
		try {
			const timestamp = Math.floor(Date.now() / 1000)
			const command = {
				command: 'wallet_online_query',
				walletAddress: this.wallet.address,
				targetWallet: ethers.getAddress(targetWallet),
				timestamp,
			}
			const innerArmor = await encryptRouteCommand(this.wallet, command, routerArmoredPublicKey)
			const pool = this.nodes.filter((n) => n?.domain && !mailboxDomains.has(n.domain))
			const entries = await pickGossipEntryNodesForSend(pool.length ? pool : this.nodes, 4, mailboxDomains)
			const targets = entries.length ? entries : getRandomNodes(pool.length ? pool : this.nodes, 4)
			const results = await Promise.all(
				targets.map(async (node) => {
					const url = postUrl(node.domain)
					try {
						const armored =
							this.cfg?.runtime.outerWrap === false
								? innerArmor
								: await wrapArmorToEntryRoute(innerArmor, node.armoredPublicKey)
						const res = await postWithTimeout(
							url,
							{
								method: 'POST',
								headers: { 'Content-Type': 'application/json' },
								body: JSON.stringify(buildPostBody(armored)),
								referrerPolicy: 'no-referrer',
							},
							10_000,
						)
						const text = (await res.text()).trim()
						if (!text) return null
						try {
							return JSON.parse(text)
						} catch {
							const m = text.match(/\{[\s\S]*\}/)
							return m ? JSON.parse(m[0]) : null
						}
					} catch {
						return null
					}
				}),
			)
			for (const r of results) {
				if (r && typeof r === 'object' && (r as { ok?: boolean }).ok === true) {
					return { ok: true, online: !!(r as { online?: boolean }).online }
				}
			}
			return null
		} catch {
			return null
		}
	}

	/** Encrypt a mailbox command (e.g. gossip_delivery_ack) to route B and POST via entry C ≠ B. */
	async postMailboxCommand(
		routerArmoredPublicKey: string,
		command: Record<string, unknown>,
	): Promise<boolean> {
		if (!this.wallet) return false
		try {
			const innerArmor = await encryptRouteCommand(this.wallet, command, routerArmoredPublicKey)
			const mailboxDomains = new Set(
				pickRouteNodesByArmoredKey(this.nodes, routerArmoredPublicKey).map((n) => n.domain),
			)
			return this.postToEntries(innerArmor, mailboxDomains)
		} catch (ex) {
			this.emit.log('warn', `postMailboxCommand error: ${(ex as Error)?.message ?? String(ex)}`)
			return false
		}
	}
}
