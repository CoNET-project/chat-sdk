/**
 * Crypto + encoding helpers. Runtime-agnostic (works in Worker and main thread).
 * Uses WebCrypto SubtleCrypto and `ethers` (keccak256 for content-addressing +
 * HKDF domain separation for history keys). No `Buffer` dependency.
 */

import { ethers } from 'ethers'

const textEncoder = new TextEncoder()
const textDecoder = new TextDecoder()

/** UTF-8 string → base64 (browser/worker safe, no Buffer). */
export function utf8ToBase64(input: string): string {
	const bytes = textEncoder.encode(input)
	return bytesToBase64(bytes)
}

/** base64 → UTF-8 string. */
export function base64ToUtf8(b64: string): string {
	const bytes = base64ToBytes(b64)
	return textDecoder.decode(bytes)
}

export function bytesToBase64(bytes: Uint8Array): string {
	let binary = ''
	const chunk = 0x8000
	for (let i = 0; i < bytes.length; i += chunk) {
		binary += String.fromCharCode(...bytes.subarray(i, i + chunk))
	}
	// eslint-disable-next-line no-undef
	return btoa(binary)
}

export function base64ToBytes(b64: string): Uint8Array {
	// eslint-disable-next-line no-undef
	const binary = atob(b64)
	const out = new Uint8Array(binary.length)
	for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i)
	return out
}

export function hexToBytes(hex: string): Uint8Array {
	const clean = hex.replace(/^0x/i, '')
	const out = new Uint8Array(clean.length / 2)
	for (let i = 0; i < out.length; i++) {
		out[i] = parseInt(clean.substr(i * 2, 2), 16)
	}
	return out
}

/** keccak256 content address of a UTF-8 payload → `0x`+64hex (Beamio fragment hash rule). */
export function keccakUtf8(input: string): string {
	return ethers.keccak256(ethers.toUtf8Bytes(input))
}

/** keccak256 of raw bytes → `0x`+64hex. */
export function keccakBytes(bytes: Uint8Array): string {
	return ethers.keccak256(bytes)
}

function subtle(): SubtleCrypto {
	const c = (globalThis as { crypto?: Crypto }).crypto
	if (!c?.subtle) throw new Error('SubtleCrypto unavailable in this runtime')
	return c.subtle
}

/**
 * HKDF-SHA256 domain-separated derivation.
 * @returns `length`-byte derived key.
 */
export async function hkdf(
	masterBytes: Uint8Array,
	info: string,
	length = 32,
	salt: Uint8Array = new Uint8Array(0),
): Promise<Uint8Array> {
	const baseKey = await subtle().importKey('raw', masterBytes, 'HKDF', false, ['deriveBits'])
	const bits = await subtle().deriveBits(
		{ name: 'HKDF', hash: 'SHA-256', salt, info: textEncoder.encode(info) },
		baseKey,
		length * 8,
	)
	return new Uint8Array(bits)
}

/** AES-256-GCM encrypt. Returns base64 of `nonce(12) || ciphertext||tag`. */
export async function aesGcmEncryptBytes(key: Uint8Array, plaintext: Uint8Array): Promise<string> {
	const iv = (globalThis.crypto as Crypto).getRandomValues(new Uint8Array(12))
	const cryptoKey = await subtle().importKey('raw', key, 'AES-GCM', false, ['encrypt'])
	const ct = new Uint8Array(await subtle().encrypt({ name: 'AES-GCM', iv }, cryptoKey, plaintext))
	const combined = new Uint8Array(iv.length + ct.length)
	combined.set(iv, 0)
	combined.set(ct, iv.length)
	return bytesToBase64(combined)
}

/** AES-256-GCM decrypt of base64 `nonce(12) || ciphertext||tag`. */
export async function aesGcmDecryptBytes(key: Uint8Array, b64: string): Promise<Uint8Array> {
	const combined = base64ToBytes(b64)
	const iv = combined.subarray(0, 12)
	const ct = combined.subarray(12)
	const cryptoKey = await subtle().importKey('raw', key, 'AES-GCM', false, ['decrypt'])
	const pt = await subtle().decrypt({ name: 'AES-GCM', iv }, cryptoKey, ct)
	return new Uint8Array(pt)
}

export async function aesGcmEncryptString(key: Uint8Array, plaintext: string): Promise<string> {
	return aesGcmEncryptBytes(key, textEncoder.encode(plaintext))
}

export async function aesGcmDecryptString(key: Uint8Array, b64: string): Promise<string> {
	return textDecoder.decode(await aesGcmDecryptBytes(key, b64))
}

export { textEncoder, textDecoder }
