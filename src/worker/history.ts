/**
 * Encrypted fragmented IPFS history — runs inside the Worker.
 *
 * Design (repo plan `beamio_chat_sdk`, on-chain head pointer variant):
 *  - master   = keccak256(EOA_sign("beamio.chat.history.v1|chainId|eoa"))  (private key never leaves worker)
 *  - indexKey = HKDF(master, "index-enc")       → AES-256-GCM of the ordered index manifest
 *  - fragment ratchet: k_i = HKDF(master, `frag|${seq}|${cid_{i-1}}`), cid_{-1}=HKDF(master,"frag-genesis")
 *      cipher_i = AES-GCM(k_i, plaintext_i); cid_i = keccak256(cipher_i) → content-addressed IPFS fragment.
 *      All cid_{i-1} recorded in the index → any k_i is O(1) derivable (newest-first restore).
 *  - HEAD POINTER (mutable): the encrypted index cipher is itself a content-addressed IPFS fragment
 *      (indexHash = keccak256(cipher)). The *latest* indexHash is recorded on-chain in `ChatIndexRegistry`
 *      via an EIP-712 `SetPointer(owner,indexHash,ts,seq,nonce)` signed offline by the EOA; a gasless API
 *      relayer pays gas. Only the owner's signature can move the owner's pointer (write right = private key).
 *      Read path is pure RPC `getPointer(eoa)` (no mutable server state). Replaces the old `point-${L}` alias.
 *
 * Trust rule: a failed/untrusted network read must NOT clobber the local IndexedDB
 * mirror (repo `beamio-trusted-vs-untrusted-fetch`).
 */

import { ethers } from 'ethers'

import type { HistoryEntry, HistoryLoadOptions, PersistenceAdapter } from '../types.js'
import {
	aesGcmDecryptString,
	aesGcmEncryptString,
	base64ToBytes,
	bytesToBase64,
	hexToBytes,
	hkdf,
	keccakUtf8,
} from '../crypto.js'

/** ChatIndexRegistry lives only on CoNET L1; EIP-712 domain chainId is fixed. */
const REGISTRY_CHAIN_ID = 224422
const REGISTRY_READ_ABI = [
	'function getPointer(address) view returns (bytes32 indexHash,uint64 ts,uint64 seq,uint64 updatedAt)',
	'function nonceOf(address) view returns (uint256)',
] as const
const SET_POINTER_TYPES = {
	SetPointer: [
		{ name: 'owner', type: 'address' },
		{ name: 'indexHash', type: 'bytes32' },
		{ name: 'ts', type: 'uint64' },
		{ name: 'seq', type: 'uint64' },
		{ name: 'nonce', type: 'uint256' },
	],
} as const

interface IndexRecord {
	seq: number
	cid: string
	prevCid: string
	ts: number
	peer: string
	dir: 'in' | 'out'
	sendId?: string
	preview?: string
}

interface IndexManifest {
	v: 1
	eoa: string
	updatedAt: number
	records: IndexRecord[]
}

export interface HistoryEmit {
	buffer(peer: string, entries: HistoryEntry[], isTail: boolean): void
	log(level: 'info' | 'warn' | 'error', message: string): void
}

const LOCAL_INDEX_KEY_PREFIX = 'beamio.chat.history.index:'
const LOCAL_FRAG_KEY_PREFIX = 'beamio.chat.history.frag:'
const FRAGMENT_GENESIS_INFO = 'frag-genesis'

export class HistoryStore {
	private master: Uint8Array | null = null
	private indexKey: Uint8Array | null = null
	private genesisCid = ''
	private manifest: IndexManifest | null = null
	private eoaLower = ''
	private ready = false
	/** Cached signer + its self-address EIP-191 signature (storageFragment auth). */
	private wallet: ethers.Wallet | null = null
	private selfSign = ''
	/** Lazily-created read-only CoNET provider (RPC-first pointer reads). */
	private provider: ethers.JsonRpcProvider | null = null

	constructor(
		private readonly emit: HistoryEmit,
		private readonly opts: {
			eoaAddress: string
			privateKeyHex: string
			chainId: number
			ipfsBaseUrl: string
			ipfsWriteBaseUrl?: string
			conetRpcUrl: string
			chatIndexRegistryAddress: string
			apiBaseUrl?: string
			persistence?: PersistenceAdapter
		},
	) {}

	private get writeBase(): string {
		return (this.opts.ipfsWriteBaseUrl || this.opts.ipfsBaseUrl).replace(/\/$/, '')
	}
	private get readBase(): string {
		return this.opts.ipfsBaseUrl.replace(/\/$/, '')
	}
	private getProvider(): ethers.JsonRpcProvider {
		if (!this.provider) {
			const net = new ethers.Network('conet', REGISTRY_CHAIN_ID)
			this.provider = new ethers.JsonRpcProvider(this.opts.conetRpcUrl, net, { staticNetwork: net })
		}
		return this.provider
	}

	async init(): Promise<void> {
		if (this.ready) return
		this.eoaLower = this.opts.eoaAddress.toLowerCase()
		const pkHex = this.opts.privateKeyHex.startsWith('0x') ? this.opts.privateKeyHex : `0x${this.opts.privateKeyHex}`
		const wallet = new ethers.Wallet(pkHex)
		this.wallet = wallet
		// storageFragment auth message = the wallet's own address (checkSign(wallet, sig, wallet)).
		this.selfSign = await wallet.signMessage(wallet.address)
		const domain = `beamio.chat.history.v1|${this.opts.chainId}|${this.eoaLower}`
		const sig = await wallet.signMessage(domain)
		this.master = hexToBytes(keccakUtf8(sig))
		this.indexKey = await hkdf(this.master, 'index-enc', 32)
		const genesisBytes = await hkdf(this.master, FRAGMENT_GENESIS_INFO, 32)
		this.genesisCid = ethers.hexlify(genesisBytes)
		this.ready = true
	}

	// ---- On-chain head pointer / index ---------------------------------------
	/** Local mirror is keyed per-EOA (index cipher changes each append). */
	private localIndexKey(): string {
		return `${LOCAL_INDEX_KEY_PREFIX}${this.eoaLower}`
	}

	/** Read the on-chain head pointer (RPC-first). Returns null when unset/unreachable. */
	private async readOnchainPointer(): Promise<{ indexHash: string; ts: bigint; seq: bigint } | null> {
		try {
			const registry = new ethers.Contract(
				this.opts.chatIndexRegistryAddress,
				REGISTRY_READ_ABI,
				this.getProvider(),
			)
			const ptr = await registry.getPointer!(ethers.getAddress(this.eoaLower))
			const indexHash = String(ptr[0])
			if (!indexHash || indexHash === ethers.ZeroHash) return null
			return { indexHash, ts: BigInt(ptr[1].toString()), seq: BigInt(ptr[2].toString()) }
		} catch (ex) {
			this.emit.log('warn', `readOnchainPointer error: ${(ex as Error)?.message ?? String(ex)}`)
			return null
		}
	}

	/** Fetch the encrypted index cipher by its content hash. */
	private async fetchIndexCipherByHash(indexHash: string): Promise<string | null> {
		try {
			const url = `${this.readBase}/getFragment?hash=${encodeURIComponent(indexHash)}`
			const res = await fetch(url, { method: 'GET', cache: 'no-store' })
			if (!res.ok) return null
			const text = (await res.text()).trim()
			return text || null
		} catch {
			return null
		}
	}

	private async loadManifest(localOnly: boolean): Promise<IndexManifest | null> {
		// Local-first (instant open).
		if (this.opts.persistence) {
			const cached = (await this.opts.persistence.get(this.localIndexKey())) as string | undefined
			if (cached && this.indexKey) {
				try {
					const json = await aesGcmDecryptString(this.indexKey, cached)
					const parsed = JSON.parse(json) as IndexManifest
					if (parsed?.v === 1) this.manifest = parsed
				} catch {
					/* corrupt local; fall through to network */
				}
			}
		}
		if (localOnly) return this.manifest
		// Network refresh (trusted-only overwrite): resolve on-chain head pointer → fetch index cipher.
		const pointer = await this.readOnchainPointer()
		if (pointer) {
			const cipher = await this.fetchIndexCipherByHash(pointer.indexHash)
			if (cipher && this.indexKey) {
				try {
					const json = await aesGcmDecryptString(this.indexKey, cipher)
					const parsed = JSON.parse(json) as IndexManifest
					if (parsed?.v === 1) {
						// Only overwrite when network is at least as complete as local (trusted).
						const netLen = parsed.records?.length ?? 0
						const localLen = this.manifest?.records?.length ?? 0
						if (netLen >= localLen) {
							this.manifest = parsed
							if (this.opts.persistence) await this.opts.persistence.set(this.localIndexKey(), cipher)
						}
					}
				} catch {
					/* untrusted parse — keep local */
				}
			}
		}
		return this.manifest
	}

	private async persistManifest(): Promise<void> {
		if (!this.manifest || !this.indexKey) return
		const json = JSON.stringify(this.manifest)
		const cipher = await aesGcmEncryptString(this.indexKey, json)
		if (this.opts.persistence) await this.opts.persistence.set(this.localIndexKey(), cipher)
		// Upload the fresh index cipher as a content-addressed fragment, then move the on-chain head pointer.
		const indexHash = await this.uploadFragment(cipher)
		if (indexHash) await this.updateOnchainPointer(indexHash)
	}

	/**
	 * Move the EOA's on-chain head pointer to `indexHash` via the gasless relay.
	 * The EOA signs `SetPointer(owner,indexHash,ts,seq,nonce)` (EIP-712); the API relayer pays gas.
	 * No-op (with a warning) when `apiBaseUrl` is not configured.
	 */
	private async updateOnchainPointer(indexHash: string): Promise<void> {
		if (!this.wallet) return
		if (!this.opts.apiBaseUrl) {
			this.emit.log('warn', 'chat history: apiBaseUrl unset — on-chain head pointer not updated')
			return
		}
		if (!ethers.isHexString(indexHash, 32)) {
			this.emit.log('warn', `chat history: bad indexHash ${indexHash}`)
			return
		}
		try {
			const nonce = await new ethers.Contract(
				this.opts.chatIndexRegistryAddress,
				REGISTRY_READ_ABI,
				this.getProvider(),
			).nonceOf!(this.wallet.address)
			// ts = client monotonic timestamp (ms); seq = monotonic append count. Both non-decreasing.
			const ts = BigInt(Date.now())
			const seq = BigInt(this.manifest?.records?.length ?? 0)
			const domain = {
				name: 'ChatIndexRegistry',
				version: '1',
				chainId: REGISTRY_CHAIN_ID,
				verifyingContract: this.opts.chatIndexRegistryAddress,
			}
			const value = { owner: this.wallet.address, indexHash, ts, seq, nonce: BigInt(nonce.toString()) }
			const signature = await this.wallet.signTypedData(domain, SET_POINTER_TYPES as never, value)
			const base = this.opts.apiBaseUrl.replace(/\/$/, '')
			const res = await fetch(`${base}/setChatIndexPointer`, {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({
					owner: this.wallet.address,
					indexHash,
					ts: ts.toString(),
					seq: seq.toString(),
					nonce: nonce.toString(),
					signature,
				}),
			})
			if (!res.ok) {
				this.emit.log('warn', `setChatIndexPointer HTTP ${res.status}`)
			}
		} catch (ex) {
			this.emit.log('warn', `updateOnchainPointer error: ${(ex as Error)?.message ?? String(ex)}`)
		}
	}

	// ---- Fragment upload/download --------------------------------------------
	private async uploadFragment(cipherB64: string): Promise<string | null> {
		if (!this.wallet) throw new Error('history not initialised')
		const contentHash = keccakUtf8(cipherB64)
		// storageFragment contract: { wallet, signMessage, image }. `image` is the raw
		// content whose keccak256(toUtf8Bytes(image)) the server recomputes as the hash.
		const body: Record<string, unknown> = {
			wallet: this.wallet.address,
			signMessage: this.selfSign,
			image: cipherB64,
		}
		try {
			const res = await fetch(`${this.writeBase}/storageFragment`, {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify(body),
			})
			if (!res.ok) {
				this.emit.log('warn', `uploadFragment HTTP ${res.status}`)
				return null
			}
			return contentHash
		} catch (ex) {
			this.emit.log('warn', `uploadFragment error: ${(ex as Error)?.message ?? String(ex)}`)
			return null
		}
	}

	private async downloadFragment(cid: string): Promise<string | null> {
		// Local mirror first.
		if (this.opts.persistence) {
			const cached = (await this.opts.persistence.get(`${LOCAL_FRAG_KEY_PREFIX}${cid}`)) as string | undefined
			if (cached) return cached
		}
		try {
			const url = `${this.readBase}/getFragment?hash=${encodeURIComponent(cid)}`
			const res = await fetch(url, { method: 'GET', cache: 'no-store' })
			if (!res.ok) return null
			const text = (await res.text()).trim()
			if (text && this.opts.persistence) await this.opts.persistence.set(`${LOCAL_FRAG_KEY_PREFIX}${cid}`, text)
			return text || null
		} catch {
			return null
		}
	}

	private async fragmentKey(seq: number, prevCid: string): Promise<Uint8Array> {
		if (!this.master) throw new Error('history not initialised')
		return hkdf(this.master, `frag|${seq}|${prevCid}`, 32)
	}

	private async decryptRecord(rec: IndexRecord): Promise<HistoryEntry | null> {
		const cipher = await this.downloadFragment(rec.cid)
		if (!cipher) return null
		try {
			const key = await this.fragmentKey(rec.seq, rec.prevCid)
			const body = await aesGcmDecryptString(key, cipher)
			return { seq: rec.seq, ts: rec.ts, peer: rec.peer, dir: rec.dir, sendId: rec.sendId, body }
		} catch {
			return null
		}
	}

	// ---- Public: load / append -----------------------------------------------
	async load(options?: HistoryLoadOptions): Promise<void> {
		await this.init()
		const tailCount = options?.tailCount ?? 60
		const localOnly = options?.localOnly ?? false
		const peerFilter = options?.peer ? options.peer.toLowerCase() : undefined

		const manifest = await this.loadManifest(localOnly)
		if (!manifest?.records?.length) {
			this.emit.buffer(peerFilter ?? 'all', [], true)
			return
		}
		let records = manifest.records
		if (peerFilter) records = records.filter((r) => r.peer.toLowerCase() === peerFilter)
		if (!records.length) {
			this.emit.buffer(peerFilter ?? 'all', [], true)
			return
		}
		const ordered = [...records].sort((a, b) => a.seq - b.seq)
		const tail = ordered.slice(Math.max(0, ordered.length - tailCount))
		const older = ordered.slice(0, Math.max(0, ordered.length - tailCount))

		// Eagerly decrypt the last ~2 screens in parallel.
		const tailEntries = (await Promise.all(tail.map((r) => this.decryptRecord(r)))).filter(
			(e): e is HistoryEntry => !!e,
		)
		this.emit.buffer(peerFilter ?? 'all', tailEntries, true)

		// Backfill older entries in the background, newest-first, in small batches.
		void (async () => {
			const batchSize = 20
			for (let i = older.length; i > 0; i -= batchSize) {
				const slice = older.slice(Math.max(0, i - batchSize), i)
				const entries = (await Promise.all(slice.map((r) => this.decryptRecord(r)))).filter(
					(e): e is HistoryEntry => !!e,
				)
				if (entries.length) this.emit.buffer(peerFilter ?? 'all', entries, false)
			}
		})()
	}

	async append(entry: Omit<HistoryEntry, 'seq'>): Promise<void> {
		await this.init()
		if (!this.manifest) {
			await this.loadManifest(false)
			if (!this.manifest) {
				this.manifest = { v: 1, eoa: this.eoaLower, updatedAt: Date.now(), records: [] }
			}
		}
		const records = this.manifest.records
		const seq = records.length ? records[records.length - 1].seq + 1 : 0
		const prevCid = records.length ? records[records.length - 1].cid : this.genesisCid
		const key = await this.fragmentKey(seq, prevCid)
		const cipher = await aesGcmEncryptString(key, entry.body)
		const cid = keccakUtf8(cipher)
		// Mirror fragment locally before network (trusted local first).
		if (this.opts.persistence) await this.opts.persistence.set(`${LOCAL_FRAG_KEY_PREFIX}${cid}`, cipher)
		await this.uploadFragment(cipher)
		const rec: IndexRecord = {
			seq,
			cid,
			prevCid,
			ts: entry.ts,
			peer: entry.peer.toLowerCase(),
			dir: entry.dir,
			sendId: entry.sendId,
			preview: entry.body.slice(0, 80),
		}
		records.push(rec)
		this.manifest.updatedAt = Date.now()
		await this.persistManifest()
	}

	destroy(): void {
		this.master = null
		this.indexKey = null
		this.manifest = null
		this.provider?.destroy?.()
		this.provider = null
		this.ready = false
	}

	// Encoding helpers kept for potential binary fragment mode (unused for now).
	static _b64 = { bytesToBase64, base64ToBytes }
}
