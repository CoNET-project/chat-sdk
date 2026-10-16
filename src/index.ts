/**
 * @conet.project/chat-sdk — public entry (main thread).
 *
 * Gossip messaging with all openpgp encrypt/decrypt + ethers signing running in a
 * Web Worker (zero main-thread crypto → no UI freeze) + encrypted fragmented IPFS
 * history. UI-agnostic; reusable across SilentPassUI / bizSite / Alliance / POS.
 *
 * Usage (host owns worker creation so the SDK stays bundler-agnostic):
 * ```ts
 * import { createBeamioChatClient } from '@conet.project/chat-sdk'
 * const client = createBeamioChatClient(config, {
 *   workerFactory: () => new Worker(new URL('@conet.project/chat-sdk/worker', import.meta.url), { type: 'module' }),
 * })
 * await client.init()
 * client.on('message', (env) => addNewMessage(env.line)) // host serial queue + checkSign
 * ```
 */

export { createBeamioChatClient } from './client.js'
export type { BeamioChatClientOptions } from './client.js'

export {
	armorToString,
	buildPostBody,
	encryptRouteCommand,
	wrapArmorToEntryRoute,
	wrapArmorToMailboxWork,
	wrapWouldHitSameNode,
} from './envelope.js'
export type { MailboxWorkEnvelope } from './envelope.js'
export { postUrl } from './nodes.js'

export type {
	BeamioChatClient,
	BeamioChatConfig,
	BeamioChatHistory,
	ChatEventListener,
	ChatEventMap,
	ChatEventName,
	ChatIdentity,
	ChatLogEvent,
	ChatRoute,
	ChatRuntimeOptions,
	ChatStatus,
	DeliveryReceiptEvent,
	HistoryBufferEvent,
	HistoryEntry,
	HistoryLoadOptions,
	HistoryReadOptions,
	InboundEnvelope,
	NodeInfo,
	PersistenceAdapter,
	PresenceEvent,
	SendMessageOptions,
	StatusEvent,
	Unsubscribe,
} from './types.js'
