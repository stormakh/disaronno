// Frozen benchmark: real Baileys build (upstream/lib) on Node. The Rust bench must do the same work.
import { createHash, randomBytes } from 'crypto'
import { mkdirSync, rmSync, writeFileSync, readFileSync } from 'fs'
import { deflateSync } from 'zlib'
import { dirname, join } from 'path'
import { fileURLToPath } from 'url'

const here = dirname(fileURLToPath(import.meta.url))
const lib = join(here, '../../upstream/lib')
const load = p => import(join(lib, p))
const { proto } = await import(join(here, '../../upstream/WAProto/index.js'))
const { encodeBinaryNode, decodeBinaryNode } = await load('WABinary/index.js')
const { makeNoiseHandler } = await load('Utils/noise-handler.js')
const { Curve, hkdf, aesEncryptGCM, signedKeyPair } = await load('Utils/crypto.js')
const { makeLibSignalRepository } = await load('Signal/libsignal.js')
const { initAuthCreds } = await load('Utils/auth-utils.js')
const { encodeSyncdPatch, decodeSyncdPatch, newLTHashState } = await load('Utils/chat-utils.js')
const { encryptedStream } = await load('Utils/messages-media.js')
const { LT_HASH_ANTI_TAMPERING } = await load('Utils/lt-hash.js')
const { processHistoryMessage } = await load('Utils/history.js')
const { NOISE_WA_HEADER } = await load('Defaults/index.js')
const P = (await import(join(here, '../../upstream/node_modules/pino/pino.js'))).default
const logger = P({ level: 'silent' })

// base process cost: the library is loaded and nothing else has run
if (process.argv[2] === 'idle') {
	const st = readFileSync('/proc/self/status', 'utf8')
	console.log(JSON.stringify({ VmHWM_kB: +st.match(/VmHWM:\s+(\d+)/)[1], VmRSS_kB: +st.match(/VmRSS:\s+(\d+)/)[1] }))
	process.exit(0)
}

// deterministic bytes, shared with Rust through fixture files
const prng = (seed, n) => {
	const out = Buffer.alloc(n)
	let h = createHash('sha256').update(seed).digest(), o = 0
	while (o < n) {
		h.copy(out, o)
		o += 32
		h = createHash('sha256').update(h).digest()
	}
	return out
}

const fx = join(here, '../fixtures')
mkdirSync(fx, { recursive: true })

const stanza = {
	tag: 'message',
	attrs: { to: '1234567890@s.whatsapp.net', id: '3EB0ABCDEF0123456789', type: 'text', t: '1700000000', participant: '19995550123:7@s.whatsapp.net' },
	content: [
		{ tag: 'enc', attrs: { v: '2', type: 'msg' }, content: prng('enc', 1024) },
		{ tag: 'device-identity', attrs: {}, content: prng('did', 64) },
		{ tag: 'participants', attrs: {}, content: Array.from({ length: 5 }, (_, i) => ({ tag: 'to', attrs: { jid: `1555000${i}@s.whatsapp.net` }, content: [{ tag: 'enc', attrs: { v: '2', type: 'pkmsg' }, content: prng('p' + i, 256) }] })) }
	]
}
const stanzaBytes = encodeBinaryNode(stanza)
writeFileSync(join(fx, 'stanza.bin'), stanzaBytes)

const wmi = {
	key: { remoteJid: '1234567890@s.whatsapp.net', fromMe: false, id: '3EB0ABCDEF0123456789', participant: '19995550123@s.whatsapp.net' },
	messageTimestamp: 1700000000,
	pushName: 'Benchmark User',
	status: 3,
	message: { extendedTextMessage: { text: 'x'.repeat(1000), matchedText: 'https://example.com', title: 'Example', description: 'A description', contextInfo: { stanzaId: 'ABCDEF', participant: '1555@s.whatsapp.net', quotedMessage: { conversation: 'quoted' }, mentionedJid: ['1@s.whatsapp.net', '2@s.whatsapp.net', '3@s.whatsapp.net'] } } }
}
const wmiObj = proto.WebMessageInfo.fromObject(wmi)
const wmiBytes = Buffer.from(proto.WebMessageInfo.encode(wmiObj).finish())
writeFileSync(join(fx, 'wmi.bin'), wmiBytes)

const hist = proto.HistorySync.fromObject({
	syncType: proto.HistorySync.HistorySyncType.RECENT,
	conversations: Array.from({ length: 200 }, (_, c) => ({
		id: `1555${c}@s.whatsapp.net`, name: 'Chat ' + c, unreadCount: 1,
		messages: Array.from({ length: 10 }, (_, m) => ({ msgOrderId: m, message: { ...wmi, key: { ...wmi.key, remoteJid: `1555${c}@s.whatsapp.net`, id: `M${c}_${m}` } } }))
	}))
})
const histRaw = Buffer.from(proto.HistorySync.encode(hist).finish())
const histZ = deflateSync(histRaw)
writeFileSync(join(fx, 'history.bin'), histZ)

const media1m = prng('media', 1 << 20)
const ltItems = Array.from({ length: 64 }, (_, i) => prng('lt' + i, 32))
const LT_BASE = Buffer.alloc(128)

const memStore = () => {
	const d = {}
	return {
		d,
		get: async (t, ids) => { const o = {}; for (const id of ids) { const v = d[t]?.[id]; if (v !== undefined && v !== null) o[id] = v } return o },
		set: async data => { for (const t in data) { d[t] ??= {}; for (const id in data[t]) { const v = data[t][id]; if (v) d[t][id] = v; else delete d[t][id] } } },
		transaction: async work => work(),
		isInTransaction: () => false
	}
}

const party = () => { const creds = initAuthCreds(); const keys = memStore(); return { creds, keys, repo: makeLibSignalRepository({ creds, keys }, logger) } }
const ALICE = '1111@s.whatsapp.net', BOB = '2222@s.whatsapp.net', GROUP = '1203630@g.us'

const pairSessions = async () => {
	const a = party(), b = party()
	const pk = Curve.generateKeyPair()
	await b.keys.set({ 'pre-key': { 1: pk } })
	const pub = k => Buffer.concat([Buffer.from([5]), k])
	await a.repo.injectE2ESession({ jid: BOB, session: { registrationId: b.creds.registrationId, identityKey: pub(b.creds.signedIdentityKey.public), signedPreKey: { keyId: b.creds.signedPreKey.keyId, publicKey: pub(b.creds.signedPreKey.keyPair.public), signature: b.creds.signedPreKey.signature }, preKey: { keyId: 1, publicKey: pub(pk.public) } } })
	return { a, b }
}

const pad = m => Buffer.concat([m, Buffer.alloc(1, 1)])

const workloads = {
	binary_encode: async () => () => encodeBinaryNode(stanza),
	binary_decode: async () => () => decodeBinaryNode(stanzaBytes),
	proto_encode: async () => () => proto.WebMessageInfo.encode(wmiObj).finish(),
	proto_decode: async () => () => proto.WebMessageInfo.decode(wmiBytes),
	history_decode: async () => () => proto.HistorySync.decode(Buffer.from(deflateSyncCache())),
	lthash_64: async () => () => LT_HASH_ANTI_TAMPERING.subtractThenAdd(LT_BASE, ltItems, []),
	media_encrypt_1mb: async () => async () => {
		const r = await encryptedStream(media1m, 'image', { logger })
		rmSync(r.encFilePath, { force: true })
	},
	curve_sign: async () => { const k = Curve.generateKeyPair(); return () => Curve.sign(k.private, ltItems[0]) },
	curve_agree: async () => { const a = Curve.generateKeyPair(), b = Curve.generateKeyPair(); return () => Curve.sharedKey(a.private, b.public) },
	signal_roundtrip: async () => {
		const { a, b } = await pairSessions()
		const data = pad(Buffer.from('hello world'.repeat(10)))
		return async () => {
			const e = await a.repo.encryptMessage({ jid: BOB, data })
			await b.repo.decryptMessage({ jid: ALICE, type: e.type, ciphertext: e.ciphertext })
		}
	},
	group_roundtrip: async () => {
		const a = party(), b = party()
		const skdm = await a.repo.getSenderKeyDistributionMessage({ group: GROUP, meId: ALICE })
		await b.repo.processSenderKeyDistributionMessage({ authorJid: ALICE, item: { groupId: GROUP, axolotlSenderKeyDistributionMessage: skdm } })
		const data = pad(Buffer.from('hello world'.repeat(10)))
		return async () => {
			const { ciphertext } = await a.repo.encryptGroupMessage({ group: GROUP, meId: ALICE, data })
			await b.repo.decryptGroupMessage({ group: GROUP, authorJid: ALICE, msg: ciphertext })
		}
	},
	appstate_roundtrip: async () => {
		const keyData = prng('appstate', 32), keyId = prng('keyid', 6).toString('base64')
		const get = async () => ({ keyData })
		const create = { type: 'regular', index: ['mute', '1555@s.whatsapp.net'], apiVersion: 2, operation: proto.SyncdMutation.SyncdOperation.SET, syncAction: { timestamp: 1700000000, muteAction: { muted: true, muteEndTimestamp: 1700000100 } } }
		let state = newLTHashState()
		return async () => {
			const { patch, state: st } = await encodeSyncdPatch(create, keyId, state, get)
			state = { ...st, indexValueMap: {} }
			await decodeSyncdPatch({ ...patch, version: { version: st.version } }, 'regular', newLTHashState(), get, () => {}, false)
		}
	},
	receive_pipeline: async () => {
		const { a, b } = await pairSessions()
		const salt = Buffer.from('Noise_XX_25519_AESGCM_SHA256\0\0\0\0')
		const k = Curve.generateKeyPair()
		const noise = makeNoiseHandler({ keyPair: k, NOISE_HEADER: NOISE_WA_HEADER, logger })
		await noise.finishInit()
		// handler's hash/salt starts as NOISE_MODE, transport read key is second half of HKDF
		const dec = hkdf(Buffer.alloc(0), 64, { salt, info: '' }).subarray(32)
		const msg = proto.Message.encode({ extendedTextMessage: { text: 'x'.repeat(200) } }).finish()
		let wc = 0
		const ivOf = c => { const iv = Buffer.alloc(12); iv.writeUInt32BE(c, 8); return iv }
		const queue = []
		const fill = async n => {
			for (let i = 0; i < n; i++) {
				const e = await a.repo.encryptMessage({ jid: BOB, data: pad(Buffer.from(msg)) })
				const node = { tag: 'message', attrs: { from: ALICE, id: 'M' + i, t: '1700000000', type: 'text' }, content: [{ tag: 'enc', attrs: { v: '2', type: e.type }, content: e.ciphertext }] }
				const plain = encodeBinaryNode(node)
				const ct = aesEncryptGCM(plain, dec, ivOf(wc++), Buffer.alloc(0))
				const fr = Buffer.alloc(3 + ct.length); fr.writeUIntBE(ct.length, 0, 3); ct.copy(fr, 3)
				queue.push(fr)
			}
		}
		const step = async () => {
			if (!queue.length) { throw new Error('pipeline queue empty') }
			const fr = queue.shift()
			let node
			await noise.decodeFrame(fr, n => { node = n })
			const enc = node.content[0]
			const pt = await b.repo.decryptMessage({ jid: node.attrs.from, type: enc.attrs.type, ciphertext: enc.content })
			proto.Message.decode(pt.subarray(0, pt.length - pt[pt.length - 1]))
		}
		step.prefill = fill
		return step
	},
	// not part of the 13 frozen workloads: the cost of the compact form of `memory-compact`
	compact_hold: async () => () => { proto.WebMessageInfo.decode(wmiBytes); return Buffer.from(wmiBytes) },
	compact_read: async () => { const held = Buffer.from(wmiBytes); return () => proto.WebMessageInfo.decode(held) }
}
function deflateSyncCache() { return histRaw }

const median = a => a.slice().sort((x, y) => x - y)[a.length >> 1]
const runOne = async (name, fn) => {
	const samples = []
	const batches = 5
	for (let b = 0; b <= batches; b++) {
		let ops = 0, elapsed = 0
		if (fn.prefill) {
			const n = 1000
			await fn.prefill(n)
			const t = process.hrtime.bigint()
			for (let i = 0; i < n; i++) { await fn(); ops++ }
			elapsed = Number(process.hrtime.bigint() - t) / 1e9
		} else {
			const t = process.hrtime.bigint()
			do { await fn(); ops++; elapsed = Number(process.hrtime.bigint() - t) / 1e9 } while (elapsed < 1)
		}
		if (b > 0) samples.push(ops / elapsed) // first batch is JIT warmup
	}
	return median(samples)
}

const mode = process.argv[2] || 'speed'
if (mode === 'startup') {
	// measured from outside: process start until here
	process.exit(0)
}
if (mode === 'memory') {
	// 1000 signal sessions and 10,000 decoded messages kept in memory
	const a = party(); const held = []
	const b = party(); const pk = Curve.generateKeyPair()
	const pub = k => Buffer.concat([Buffer.from([5]), k])
	for (let i = 0; i < 1000; i++) {
		await a.repo.injectE2ESession({ jid: `${10000 + i}@s.whatsapp.net`, session: { registrationId: b.creds.registrationId, identityKey: pub(b.creds.signedIdentityKey.public), signedPreKey: { keyId: b.creds.signedPreKey.keyId, publicKey: pub(b.creds.signedPreKey.keyPair.public), signature: b.creds.signedPreKey.signature }, preKey: { keyId: 1, publicKey: pub(pk.public) } } })
	}
	for (let i = 0; i < 10000; i++) held.push(proto.WebMessageInfo.decode(wmiBytes))
	globalThis.gc?.()
	const st = readFileSync('/proc/self/status', 'utf8')
	console.log(JSON.stringify({ VmHWM_kB: +st.match(/VmHWM:\s+(\d+)/)[1], VmRSS_kB: +st.match(/VmRSS:\s+(\d+)/)[1], held: held.length }))
	process.exit(0)
}
if (mode === 'memory-compact') {
	// a separate measure: the same sessions, with each message decoded fully and then held as a private copy of its bytes
	const a = party(); const held = []
	const b = party(); const pk = Curve.generateKeyPair()
	const pub = k => Buffer.concat([Buffer.from([5]), k])
	for (let i = 0; i < 1000; i++) {
		await a.repo.injectE2ESession({ jid: `${10000 + i}@s.whatsapp.net`, session: { registrationId: b.creds.registrationId, identityKey: pub(b.creds.signedIdentityKey.public), signedPreKey: { keyId: b.creds.signedPreKey.keyId, publicKey: pub(b.creds.signedPreKey.keyPair.public), signature: b.creds.signedPreKey.signature }, preKey: { keyId: 1, publicKey: pub(pk.public) } } })
	}
	for (let i = 0; i < 10000; i++) {
		proto.WebMessageInfo.decode(wmiBytes)
		held.push(Buffer.from(wmiBytes))
	}
	globalThis.gc?.()
	const st = readFileSync('/proc/self/status', 'utf8')
	console.log(JSON.stringify({ VmHWM_kB: +st.match(/VmHWM:\s+(\d+)/)[1], VmRSS_kB: +st.match(/VmRSS:\s+(\d+)/)[1], held: held.length }))
	process.exit(0)
}
const out = {}
const only = process.argv[3]
for (const [name, mk] of Object.entries(workloads)) {
	if (only && only !== name) continue
	const fn = await mk()
	const r = await runOne(name, fn)
	out[name] = +r.toFixed(1)
	console.error(name.padEnd(22), r.toFixed(1).padStart(12), 'ops/s')
}
console.log(JSON.stringify(out, null, 2))
process.exit(0)
