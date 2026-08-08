/**
 * Encrypted fragmented IPFS history — runs inside the Worker.
 *
 * Design (repo plan `beamio_chat_sdk`):
 *  - master  = keccak256(EOA_sign("beamio.chat.history.v1|chainId|eoa"))  (private key never leaves worker)
 *  - locator L = HKDF(master, "index-locator")  → hidden in the hash-sea; re-pointed via server `point-${L}`
 *  - indexKey  = HKDF(master, "index-enc")       → AES-256-GCM of the ordered index manifest
 *  - fragment ratchet: k_i = HKDF(master, `frag|${seq}|${cid_{i-1}}`), cid_{-1}=HKDF(master,"frag-genesis")
 *      cipher_i = AES-GCM(k_i, plaintext_i); cid_i = keccak256(cipher_i) → uploaded fragment address.
 *      All cid_{i-1} recorded in the index → any k_i is O(1) derivable (newest-first restore).
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
	private locator = ''
	private indexKey: Uint8Array | null = null
	private genesisCid = ''
	private manifest: IndexManifest | null = null
	private eoaLower = ''
	private ready = false
	/** Cached signer + its self-address EIP-191 signature (storageFragment auth). */
	private wallet: ethers.Wallet | null = null
	private selfSign = ''

	constructor(
		private readonly emit: HistoryEmit,
		private readonly opts: {
			eoaAddress: string
			privateKeyHex: string
			chainId: number
			ipfsBaseUrl: string
			ipfsWriteBaseUrl?: string
			persistence?: PersistenceAdapter
		},
	) {}

	private get writeBase(): string {
		return (this.opts.ipfsWriteBaseUrl || this.opts.ipfsBaseUrl).replace(/\/$/, '')
	}
	private get readBase(): string {
		return this.opts.ipfsBaseUrl.replace(/\/$/, '')
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
		const locatorBytes = await hkdf(this.master, 'index-locator', 32)
		this.locator = `point-${ethers.hexlify(locatorBytes)}`
		this.indexKey = await hkdf(this.master, 'index-enc', 32)
		const genesisBytes = await hkdf(this.master, FRAGMENT_GENESIS_INFO, 32)
		this.genesisCid = ethers.hexlify(genesisBytes)
		this.ready = true
	}

	// ---- Locator / index ------------------------------------------------------
	private localIndexKey(): string {
		return `${LOCAL_INDEX_KEY_PREFIX}${this.locator}`
	}

	private async fetchIndexCipherFromNetwork(): Promise<string | null> {
		try {
			const url = `${this.readBase}/getFragment?hash=${encodeURIComponent(this.locator)}`
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
		// Network refresh (trusted-only overwrite).
		const cipher = await this.fetchIndexCipherFromNetwork()
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
		return this.manifest
	}

	private async persistManifest(): Promise<void> {
		if (!this.manifest || !this.indexKey) return
		const json = JSON.stringify(this.manifest)
		const cipher = await aesGcmEncryptString(this.indexKey, json)
		if (this.opts.persistence) await this.opts.persistence.set(this.localIndexKey(), cipher)
		// Re-point server alias `point-${L}` at the fresh index cipher.
		await this.uploadFragment(cipher, this.locator)
	}

	// ---- Fragment upload/download --------------------------------------------
	private async uploadFragment(cipherB64: string, pointer?: string): Promise<string | null> {
		if (!this.wallet) throw new Error('history not initialised')
		const contentHash = keccakUtf8(cipherB64)
		// storageFragment contract: { wallet, signMessage, image }. `image` is the raw
		// content whose keccak256(toUtf8Bytes(image)) the server recomputes as the hash.
		const body: Record<string, unknown> = {
			wallet: this.wallet.address,
			signMessage: this.selfSign,
			image: cipherB64,
		}
		if (pointer) {
			// point-${L} alias: EOA-signed, owner-bound (see fragmentClusterServer upgrade).
			try {
				const ts = Math.floor(Date.now() / 1000)
				const pointerSig = await this.wallet.signMessage(`${pointer}|${contentHash}|${ts}`)
				body.pointer = pointer
				body.pointerOwner = this.wallet.address
				body.pointerTs = ts
				body.pointerSig = pointerSig
			} catch {
				/* pointer optional */
			}
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
		this.ready = false
	}

	// Encoding helpers kept for potential binary fragment mode (unused for now).
	static _b64 = { bytesToBase64, base64ToBytes }
}
