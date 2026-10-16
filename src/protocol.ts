/**
 * postMessage protocol between the main-thread {@link BeamioChatClient} and the
 * gossip Worker. All heavy crypto (openpgp encrypt/decrypt, ethers verify/sign)
 * runs in the worker; the main thread only marshals commands and re-emits events.
 */

import type {
	ChatIdentity,
	ChatRoute,
	ChatRuntimeOptions,
	DeliveryReceiptEvent,
	HistoryBufferEvent,
	HistoryEntry,
	HistoryLoadOptions,
	HistoryReadOptions,
	InboundEnvelope,
	NodeInfo,
	PresenceEvent,
	StatusEvent,
} from './types.js'

/** Serialisable subset of config passed into the worker at init. */
export interface WorkerInitPayload {
	identity: ChatIdentity
	conetRpcUrl: string
	addressPgpContractAddress: string
	ipfsBaseUrl: string
	ipfsWriteBaseUrl?: string
	chainId: number
	/** ChatIndexRegistry proxy (on-chain encrypted-history head pointer). */
	chatIndexRegistryAddress: string
	/** Cluster API base for the gasless index-pointer relay (optional). */
	apiBaseUrl?: string
	runtime: Required<ChatRuntimeOptions>
	/** Initial node snapshot (worker requests refreshes via `nodesRequest`). */
	nodes: NodeInfo[]
	/** Initial routes to listen/probe. */
	routes: ChatRoute[]
}

/** Commands: main → worker. */
export type WorkerCommand =
	| { type: 'init'; reqId: number; payload: WorkerInitPayload }
	| { type: 'setRoutes'; routes: ChatRoute[] }
	| { type: 'setNodes'; nodes: NodeInfo[] }
	| { type: 'send'; reqId: number; to: ChatRoute; payload: string; sendId: string; beamioNoPush?: boolean }
	| { type: 'queryPresence'; reqId: number; contacts: ChatRoute[] }
	| { type: 'queryNativeWake'; reqId: number; contact: ChatRoute }
	| { type: 'historyLoad'; reqId: number; options?: HistoryLoadOptions }
	| { type: 'historyRead'; reqId: number; options?: HistoryReadOptions }
	| { type: 'historyAppend'; reqId: number; entry: Omit<HistoryEntry, 'seq'> }
	/** Encrypt an arbitrary mailbox command (e.g. gossip_delivery_ack) to route B and POST via entry C ≠ B. */
	| {
			type: 'mailboxCommand'
			reqId: number
			routerArmoredPublicKey: string
			command: Record<string, unknown>
	  }
	| {
			type: 'ownMailboxCommand'
			reqId: number
			command: Record<string, unknown>
	  }
	| {
			type: 'voiceFrame'
			reqId: number
			routerArmoredPublicKey: string
			frame: Record<string, unknown>
	  }
	| {
			type: 'voiceListen'
			reqId: number
			sessionId: string
			pushWakeup?: {
				callId: string
				calleeEoa: string
				expiresAt: number
				timestamp: number
				/** Signed offer JSON. The worker encrypts it to the callee user PGP. */
				offerText?: string
				recipientPgp?: string
			}
	  }
	| { type: 'voiceUnlisten'; reqId: number; sessionId: string }
	| { type: 'pause' }
	| { type: 'resume' }
	| { type: 'destroy' }

/** Events + command replies: worker → main. */
export type WorkerOutbound =
	| { type: 'ready'; reqId: number }
	| { type: 'ack'; reqId: number; ok: true; result?: unknown }
	| { type: 'ack'; reqId: number; ok: false; error: string }
	| { type: 'event:message'; payload: InboundEnvelope }
	| { type: 'event:delivery'; payload: DeliveryReceiptEvent }
	| { type: 'event:presence'; payload: PresenceEvent }
	| { type: 'event:status'; payload: StatusEvent }
	| { type: 'event:historyBuffer'; payload: HistoryBufferEvent }
	| { type: 'event:voiceFrame'; payload: Record<string, unknown> }
	| { type: 'event:log'; level: 'info' | 'warn' | 'error'; message: string }
	/** Worker asks host (main thread) to refresh node list (host owns discovery). */
	| { type: 'nodesRequest'; reqId: number }
	| { type: 'nodesResponse:consume'; reqId: number }

/** Host → worker response to a `nodesRequest`. */
export interface NodesResponseCommand {
	type: 'nodesResponse'
	reqId: number
	nodes: NodeInfo[]
}

export type WorkerInbound = WorkerCommand | NodesResponseCommand
