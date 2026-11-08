// A small WhatsApp-like server for end-to-end checks of this port and of real Baileys.
//
// It speaks the real wire protocol: WebSocket, Noise XX as the responder, with a certificate chain
// under a test root key, binary nodes, QR pairing with a real ADV signature, pre-key bundles, usync,
// routing of encrypted messages between devices, group fanout, and app-state patches.
//
// It is NOT WhatsApp. It holds no message content (it cannot read the ciphertext), and it does not
// model any of the rules, limits, or validations of the real servers.
//
// Standalone:  node scripts/mock-server.mjs [port]
// It prints the url and the root public key. To scan a QR: curl -d "<qr>" "localhost:<port>/scan?phone=15550001"
import { createServer } from 'http'
import { createRequire } from 'module'
import { dirname, join } from 'path'
import { fileURLToPath } from 'url'

const here = dirname(fileURLToPath(import.meta.url))
const upstream = join(here, '../upstream')
const require = createRequire(join(upstream, 'package.json'))
const { WebSocketServer } = require('ws')
const curve = require('libsignal/src/curve')
const { proto } = await import(join(upstream, 'WAProto/index.js'))
const { Curve, hkdf, aesEncryptGCM, aesDecryptGCM, sha256, hmacSign } = await import(join(upstream, 'lib/Utils/crypto.js'))
const { encodeBinaryNode, decodeBinaryNode, getBinaryNodeChild, getBinaryNodeChildren, jidDecode } = await import(join(upstream, 'lib/WABinary/index.js'))

const S_WHATSAPP_NET = 's.whatsapp.net'
const NOISE_MODE = Buffer.from('Noise_XX_25519_AESGCM_SHA256\0\0\0\0')
const ADV_ACCOUNT_SIG_PREFIX = Buffer.from([6, 0])
const ADV_DEVICE_SIG_PREFIX = Buffer.from([6, 1])
const now = () => Math.floor(Date.now() / 1000).toString()
const bytes = v => (v instanceof Uint8Array ? Buffer.from(v) : Buffer.from(String(v ?? '')))
const uint = (n, len) => {
	const b = Buffer.alloc(len)
	b.writeUIntBE(n, 0, len)
	return b
}
const children = n => (Array.isArray(n?.content) ? n.content : [])
const realVerify = (pub, msg, sig) => {
	try {
		return curve.verifySignature(pub, msg, sig) === true
	} catch {
		return false
	}
}

/** The responder side of Noise XX, the mirror of Utils/noise-handler.ts. */
class ServerNoise {
	constructor() {
		this.hash = NOISE_MODE
		this.salt = NOISE_MODE
		this.enc = NOISE_MODE
		this.dec = NOISE_MODE
		this.counter = 0
		this.transport = null
	}
	iv(c) {
		const iv = Buffer.alloc(12)
		iv.writeUInt32BE(c, 8)
		return iv
	}
	authenticate(d) {
		this.hash = sha256(Buffer.concat([this.hash, d]))
	}
	mixIntoKey(d) {
		const k = hkdf(d, 64, { salt: this.salt, info: '' })
		this.salt = k.subarray(0, 32)
		this.enc = this.dec = k.subarray(32)
		this.counter = 0
	}
	encrypt(p) {
		const r = aesEncryptGCM(p, this.enc, this.iv(this.counter++), this.hash)
		this.authenticate(r)
		return r
	}
	decrypt(c) {
		const r = aesDecryptGCM(c, this.dec, this.iv(this.counter++), this.hash)
		this.authenticate(c)
		return r
	}
	finish() {
		const k = hkdf(Buffer.alloc(0), 64, { salt: this.salt, info: '' })
		this.transport = { recv: k.subarray(0, 32), send: k.subarray(32), r: 0, w: 0 }
	}
	sealTransport(p) {
		return aesEncryptGCM(p, this.transport.send, this.iv(this.transport.w++), Buffer.alloc(0))
	}
	openTransport(c) {
		return aesDecryptGCM(c, this.transport.recv, this.iv(this.transport.r++), Buffer.alloc(0))
	}
}

/** The fields of a ClientPayload as attributes, for the stanza log. Keys and random values are masked. */
function maskPayload(payload) {
	const flat = {}
	const walk = (prefix, o) => {
		for (const [k, v] of Object.entries(o)) {
			const name = prefix ? `${prefix}.${k}` : k
			if (v && typeof v === 'object' && !Array.isArray(v)) walk(name, v)
			else flat[name] = String(v)
		}
	}
	const json = payload.toJSON()
	if (json.devicePairingData) {
		const d = proto.DeviceProps.decode(Buffer.from(json.devicePairingData.deviceProps, 'base64')).toJSON()
		json.devicePairingData = { buildHash: json.devicePairingData.buildHash, eKeytype: json.devicePairingData.eKeytype, deviceProps: d }
	}
	walk('', json)
	return flat
}

export class MockServer {
	constructor({ log = () => {} } = {}) {
		this.log = log
		this.rootKey = Curve.generateKeyPair()
		this.staticKey = Curve.generateKeyPair()
		this.certPayload = this.makeCertChain()
		/** phone -> account */
		this.accounts = new Map()
		this.lidToPhone = new Map()
		this.groups = new Map()
		this.conns = new Set()
		/** ref -> connection that waits for a scan */
		this.pendingRefs = new Map()
		/** message id -> the device that sent it, to route receipts back */
		this.messageSenders = new Map()
		this.nextLid = 90000
		this.nextGroup = 120363000000000
		this.nextId = 1
		/** Every stanza a client sent, by the label given to `labelNext`. */
		this.stanzaLog = new Map()
		this.nextLabel = null
		this.delivered = 0
		this.errors = []
	}

	makeCertChain() {
		const intermediateKey = Curve.generateKeyPair()
		const { Details } = proto.CertChain.NoiseCertificate
		const intermediateDetails = Details.encode({ serial: 1, issuerSerial: 0, key: intermediateKey.public, notBefore: 0, notAfter: 4102444800 }).finish()
		const leafDetails = Details.encode({ serial: 2, issuerSerial: 1, key: this.staticKey.public, notBefore: 0, notAfter: 4102444800 }).finish()
		return proto.CertChain.encode({
			leaf: { details: leafDetails, signature: Curve.sign(intermediateKey.private, leafDetails) },
			intermediate: { details: intermediateDetails, signature: Curve.sign(this.rootKey.private, intermediateDetails) }
		}).finish()
	}

	listen(port = 0) {
		this.http = createServer((req, res) => this.onHttp(req, res))
		this.wss = new WebSocketServer({ server: this.http, path: '/ws/chat' })
		this.wss.on('connection', ws => this.onConnection(ws))
		return new Promise(resolve => {
			this.http.listen(port, '127.0.0.1', () => {
				this.port = this.http.address().port
				this.url = `ws://127.0.0.1:${this.port}/ws/chat`
				resolve(this)
			})
		})
	}

	close() {
		for (const c of this.conns) c.ws.terminate()
		this.wss?.close()
		return new Promise(resolve => (this.http ? this.http.close(() => resolve()) : resolve()))
	}

	onHttp(req, res) {
		const url = new URL(req.url, 'http://localhost')
		if (req.method === 'POST' && url.pathname === '/scan') {
			let body = ''
			req.on('data', d => (body += d))
			req.on('end', () => {
				const r = this.scan(body.trim(), url.searchParams.get('phone') || '15550001')
				res.writeHead(r.ok ? 200 : 400)
				res.end(JSON.stringify(r))
			})
			return
		}
		res.writeHead(404)
		res.end()
	}

	/** Tags the next connection with a label for the stanza log. */
	labelNext(label) {
		this.nextLabel = label
	}

	onConnection(ws) {
		const conn = { ws, noise: new ServerNoise(), inBytes: Buffer.alloc(0), first: true, state: 'hello', device: null, label: this.nextLabel, queue: Promise.resolve() }
		this.nextLabel = null
		this.conns.add(conn)
		ws.on('message', data => {
			conn.queue = conn.queue.then(() => this.onData(conn, Buffer.from(data))).catch(e => this.fail(conn, e))
		})
		ws.on('close', () => {
			this.conns.delete(conn)
			if (conn.device?.conn === conn) conn.device.conn = null
		})
		ws.on('error', () => {})
	}

	fail(conn, e) {
		this.errors.push(String(e?.stack || e))
		this.log('server error: ' + (e?.stack || e))
		conn.ws.terminate()
	}

	async onData(conn, data) {
		conn.inBytes = Buffer.concat([conn.inBytes, data])
		if (conn.first) {
			if (conn.inBytes.length < 4) return
			let off = 0
			if (conn.inBytes[0] === 0x45 && conn.inBytes[1] === 0x44) {
				if (conn.inBytes.length < 7) return
				off = 7 + conn.inBytes.readUIntBE(4, 3)
			}
			if (conn.inBytes.length < off + 4) return
			conn.noise.authenticate(conn.inBytes.subarray(off, off + 4))
			conn.inBytes = conn.inBytes.subarray(off + 4)
			conn.first = false
		}
		while (conn.inBytes.length >= 3) {
			const size = conn.inBytes.readUIntBE(0, 3)
			if (conn.inBytes.length < size + 3) return
			const frame = conn.inBytes.subarray(3, size + 3)
			conn.inBytes = conn.inBytes.subarray(size + 3)
			await this.onFrame(conn, frame)
		}
	}

	async onFrame(conn, frame) {
		if (conn.state === 'hello') return this.onClientHello(conn, frame)
		if (conn.state === 'finish') return this.onClientFinish(conn, frame)
		const node = await decodeBinaryNode(conn.noise.openTransport(frame))
		if (process.env.MOCK_TRACE) console.log('  recv', conn.device ? `${conn.device.account.phone}:${conn.device.id}` : '?', node.tag, JSON.stringify(node.attrs))
		this.record(conn, node)
		return this.onNode(conn, node)
	}

	record(conn, node) {
		if (!conn.label) return
		if (!this.stanzaLog.has(conn.label)) this.stanzaLog.set(conn.label, [])
		this.stanzaLog.get(conn.label).push(node)
	}

	writeRaw(conn, b) {
		const f = Buffer.alloc(3 + b.length)
		f.writeUIntBE(b.length, 0, 3)
		b.copy(f, 3)
		if (conn.ws.readyState === 1) conn.ws.send(f)
	}

	send(conn, node) {
		if (process.env.MOCK_TRACE) console.log('  send', conn.device ? `${conn.device.account.phone}:${conn.device.id}` : '?', node.tag, JSON.stringify(node.attrs))
		this.writeRaw(conn, Buffer.from(conn.noise.sealTransport(encodeBinaryNode(node))))
	}

	onClientHello(conn, frame) {
		const hello = proto.HandshakeMessage.decode(frame).clientHello
		const clientEphemeral = Buffer.from(hello.ephemeral)
		conn.clientEphemeral = clientEphemeral
		const n = conn.noise
		n.authenticate(clientEphemeral)
		const eph = Curve.generateKeyPair()
		conn.serverEphemeral = eph
		n.authenticate(eph.public)
		n.mixIntoKey(Curve.sharedKey(eph.private, clientEphemeral))
		const encStatic = n.encrypt(this.staticKey.public)
		n.mixIntoKey(Curve.sharedKey(this.staticKey.private, clientEphemeral))
		const payload = n.encrypt(this.certPayload)
		conn.state = 'finish'
		this.writeRaw(conn, Buffer.from(proto.HandshakeMessage.encode({ serverHello: { ephemeral: eph.public, static: encStatic, payload } }).finish()))
	}

	onClientFinish(conn, frame) {
		const finish = proto.HandshakeMessage.decode(frame).clientFinish
		const n = conn.noise
		const noiseKey = n.decrypt(Buffer.from(finish.static))
		conn.noiseKey = Buffer.from(noiseKey)
		n.mixIntoKey(Curve.sharedKey(conn.serverEphemeral.private, noiseKey))
		const payload = proto.ClientPayload.decode(n.decrypt(Buffer.from(finish.payload)))
		n.finish()
		conn.state = 'open'
		conn.payload = payload
		this.record(conn, { tag: 'client-payload', attrs: maskPayload(payload) })
		if (payload.devicePairingData) this.startPairing(conn, payload)
		else this.startLogin(conn, payload)
	}

	startPairing(conn, payload) {
		const d = payload.devicePairingData
		conn.registration = {
			registrationId: Buffer.from(d.eRegid).readUInt32BE(0),
			identity: Buffer.from(d.eIdent),
			skey: { id: Buffer.from(d.eSkeyId).readUIntBE(0, 3), value: Buffer.from(d.eSkeyVal), signature: Buffer.from(d.eSkeySig) }
		}
		const refs = []
		for (let i = 0; i < 6; i++) {
			const ref = `ref-${this.nextId++}-${Math.random().toString(36).slice(2)}`
			this.pendingRefs.set(ref, conn)
			refs.push({ tag: 'ref', attrs: {}, content: Buffer.from(ref) })
		}
		this.send(conn, { tag: 'iq', attrs: { from: S_WHATSAPP_NET, type: 'set', id: this.id(), xmlns: 'md' }, content: [{ tag: 'pair-device', attrs: {}, content: refs }] })
	}

	id() {
		return `srv-${this.nextId++}`
	}

	account(phone) {
		let a = this.accounts.get(phone)
		if (!a) {
			const lid = String(this.nextLid++)
			a = { phone, lid, identity: Curve.generateKeyPair(), devices: new Map(), nextDevice: 1, appState: new Map() }
			this.accounts.set(phone, a)
			this.lidToPhone.set(lid, phone)
		}
		return a
	}

	/** What the phone does when it scans a QR. `qr` is the text the client got in `connection.update`. */
	scan(qr, phone) {
		const parts = qr.split('#')[1]?.split(',')
		if (!parts || parts.length < 4) return { ok: false, error: 'bad qr' }
		const [ref, noiseB64, identityB64, advB64] = parts
		const conn = this.pendingRefs.get(ref)
		if (!conn) return { ok: false, error: 'unknown ref' }
		if (!Buffer.from(noiseB64, 'base64').equals(conn.noiseKey)) return { ok: false, error: 'noise key of the qr is not the key of the connection' }
		const identityPub = Buffer.from(identityB64, 'base64')
		if (!identityPub.equals(conn.registration.identity)) return { ok: false, error: 'identity key of the qr is not the key of the registration' }
		for (const [r, c] of this.pendingRefs) if (c === conn) this.pendingRefs.delete(r)
		const account = this.account(phone)
		const deviceId = account.nextDevice++
		const details = proto.ADVDeviceIdentity.encode({ rawId: deviceId, timestamp: Number(now()), keyIndex: deviceId }).finish()
		const accountSignature = Curve.sign(account.identity.private, Buffer.concat([ADV_ACCOUNT_SIG_PREFIX, details, identityPub]))
		const signedIdentity = proto.ADVSignedDeviceIdentity.encode({ details, accountSignatureKey: account.identity.public, accountSignature }).finish()
		const hmac = hmacSign(signedIdentity, Buffer.from(advB64, 'base64'))
		const hmacIdentity = proto.ADVSignedDeviceIdentityHMAC.encode({ details: signedIdentity, hmac }).finish()
		conn.pairing = { account, deviceId, identityPub }
		this.send(conn, {
			tag: 'iq',
			attrs: { from: S_WHATSAPP_NET, type: 'set', id: this.id(), xmlns: 'md', t: now() },
			content: [
				{
					tag: 'pair-success',
					attrs: {},
					content: [
						{ tag: 'device-identity', attrs: { 'key-index': String(deviceId) }, content: Buffer.from(hmacIdentity) },
						{ tag: 'platform', attrs: { name: 'web' } },
						{ tag: 'device', attrs: { jid: `${phone}:${deviceId}@${S_WHATSAPP_NET}`, lid: `${account.lid}:${deviceId}@lid` } }
					]
				}
			]
		})
		return { ok: true, phone, device: deviceId }
	}

	/** The reply to pair-success. The signature is checked for real, with the key of the device. */
	onPairDeviceSign(conn, iq, sign) {
		const { account, deviceId, identityPub } = conn.pairing
		const signed = proto.ADVSignedDeviceIdentity.decode(getBinaryNodeChild(sign, 'device-identity').content)
		const msg = Buffer.concat([ADV_DEVICE_SIG_PREFIX, signed.details, identityPub, account.identity.public])
		if (!realVerify(identityPub, msg, Buffer.from(signed.deviceSignature))) throw new Error('bad device signature in pair-device-sign')
		const reg = conn.registration
		account.devices.set(deviceId, { account, id: deviceId, noiseKey: conn.noiseKey, registrationId: reg.registrationId, identity: reg.identity, skey: reg.skey, preKeys: [], conn: null, offline: [] })
		for (const c of this.conns) {
			if (c.device) this.notifyDevices(c, account, deviceId)
		}
		// the server asks the client to restart the connection, as the real one does
		this.send(conn, { tag: 'stream:error', attrs: { code: '515' } })
		setTimeout(() => conn.ws.close(), 20)
	}

	notifyDevices(conn, account, deviceId) {
		this.send(conn, { tag: 'notification', attrs: { from: `${account.phone}@${S_WHATSAPP_NET}`, type: 'devices', id: this.id(), t: now() }, content: [{ tag: 'add', attrs: { device_hash: 'mock' }, content: [{ tag: 'device', attrs: { jid: `${account.phone}:${deviceId}@${S_WHATSAPP_NET}` } }] }] })
	}

	startLogin(conn, payload) {
		const phone = String(payload.username)
		const account = this.accounts.get(phone)
		const device = account?.devices.get(payload.device || 0)
		if (!device || !device.noiseKey.equals(conn.noiseKey)) {
			this.send(conn, { tag: 'failure', attrs: { reason: '401', location: 'mock' } })
			setTimeout(() => conn.ws.close(), 20)
			return
		}
		if (device.conn) {
			this.send(device.conn, { tag: 'stream:error', attrs: {}, content: [{ tag: 'conflict', attrs: { type: 'replaced' } }] })
			device.conn.ws.close()
		}
		device.conn = conn
		conn.device = device
		this.send(conn, { tag: 'success', attrs: { t: now(), lid: `${account.lid}:${device.id}@lid`, props: '0', location: 'mock', creation: now() } })
	}

	onNode(conn, node) {
		switch (node.tag) {
			case 'iq':
				return this.onIq(conn, node)
			case 'message':
				return this.onMessage(conn, node)
			case 'receipt':
				return this.onReceipt(conn, node)
			case 'presence':
			case 'chatstate':
			case 'ib':
			case 'ack':
				return
			case 'call':
				return this.result(conn, node)
			default:
				this.log(`unknown stanza ${node.tag}`)
		}
	}

	result(conn, node, content) {
		const attrs = { from: S_WHATSAPP_NET, type: 'result', id: node.attrs.id }
		this.send(conn, content === undefined ? { tag: 'iq', attrs } : { tag: 'iq', attrs, content })
	}

	onIq(conn, node) {
		const first = children(node)[0]
		if (node.attrs.type === 'result') {
			const sign = getBinaryNodeChild(node, 'pair-device-sign')
			if (sign) this.onPairDeviceSign(conn, node, sign)
			return
		}
		switch (node.attrs.xmlns) {
			case 'encrypt':
				return this.onEncryptIq(conn, node, first)
			case 'usync':
				return this.onUsync(conn, node)
			case 'w:g2':
				return this.onGroupIq(conn, node, first)
			case 'w:sync:app:state':
				return this.onAppStateIq(conn, node)
			case 'passive':
				this.result(conn, node)
				// every pending item is out now, and the client flushes its buffer on this
				this.deliverOffline(conn)
				return
			case 'abt':
				return this.result(conn, node, [{ tag: 'props', attrs: { protocol: '1', hash: 'mock-hash' }, content: [{ tag: 'prop', attrs: { name: '10518', value: 'true' } }] }])
			case 'blocklist':
				return this.result(conn, node, [{ tag: 'list', attrs: {} }])
			case 'privacy':
				if (first?.tag === 'privacy') return this.result(conn, node, [{ tag: 'privacy', attrs: {}, content: [{ tag: 'category', attrs: { name: 'readreceipts', value: 'all' } }] }])
				return this.result(conn, node)
			case 'w:m':
				return this.result(conn, node, [{ tag: 'media_conn', attrs: { auth: 'mock', ttl: '3600' }, content: [{ tag: 'host', attrs: { hostname: '127.0.0.1', maxContentLengthBytes: '1000000' } }] }])
			default:
				return this.result(conn, node)
		}
	}

	deliverOffline(conn) {
		const d = conn.device
		if (!d) return
		const pending = d.offline
		d.offline = []
		for (const m of pending) {
			m.attrs.offline = '1'
			this.send(conn, m)
		}
		this.send(conn, { tag: 'ib', attrs: {}, content: [{ tag: 'offline', attrs: { count: String(pending.length) } }] })
	}

	onEncryptIq(conn, node, first) {
		const d = conn.device
		if (first?.tag === 'count') return this.result(conn, node, [{ tag: 'count', attrs: { value: String(d.preKeys.length) } }])
		if (first?.tag === 'digest') return this.result(conn, node, [{ tag: 'digest', attrs: {}, content: [{ tag: 'registration', attrs: {}, content: uint(d.registrationId, 4) }] }])
		if (first?.tag === 'key') return this.onKeyFetch(conn, node, first)
		if (first?.tag === 'rotate') {
			const skey = getBinaryNodeChild(first, 'skey')
			d.skey = { id: bytes(getBinaryNodeChild(skey, 'id').content).readUIntBE(0, 3), value: bytes(getBinaryNodeChild(skey, 'value').content), signature: bytes(getBinaryNodeChild(skey, 'signature').content) }
			return this.result(conn, node)
		}
		// a pre-key upload
		const list = getBinaryNodeChild(node, 'list')
		const skey = getBinaryNodeChild(node, 'skey')
		if (list) {
			for (const k of getBinaryNodeChildren(list, 'key')) d.preKeys.push({ id: bytes(getBinaryNodeChild(k, 'id').content).readUIntBE(0, 3), value: bytes(getBinaryNodeChild(k, 'value').content) })
		}
		if (skey) d.skey = { id: bytes(getBinaryNodeChild(skey, 'id').content).readUIntBE(0, 3), value: bytes(getBinaryNodeChild(skey, 'value').content), signature: bytes(getBinaryNodeChild(skey, 'signature').content) }
		this.result(conn, node)
	}

	/** The account and device of a jid in either addressing form. */
	resolve(jid) {
		const j = jidDecode(jid)
		if (!j) return null
		const phone = j.server === 'lid' ? this.lidToPhone.get(j.user) : j.user
		const account = this.accounts.get(phone)
		if (!account) return null
		return { account, device: j.device || 0, isLid: j.server === 'lid' }
	}

	onKeyFetch(conn, node, key) {
		const users = []
		for (const u of getBinaryNodeChildren(key, 'user')) {
			const jid = u.attrs.jid
			const r = this.resolve(jid)
			const d = r?.account.devices.get(r.device)
			if (!d) {
				users.push({ tag: 'user', attrs: { jid }, content: [{ tag: 'error', attrs: { code: '404', text: 'item-not-found' } }] })
				continue
			}
			const pre = d.preKeys.shift()
			const content = [
				{ tag: 'registration', attrs: {}, content: uint(d.registrationId, 4) },
				{ tag: 'type', attrs: {}, content: Buffer.from([5]) },
				{ tag: 'identity', attrs: {}, content: d.identity },
				{ tag: 'skey', attrs: {}, content: [{ tag: 'id', attrs: {}, content: uint(d.skey.id, 3) }, { tag: 'value', attrs: {}, content: d.skey.value }, { tag: 'signature', attrs: {}, content: d.skey.signature }] }
			]
			if (pre) content.push({ tag: 'key', attrs: {}, content: [{ tag: 'id', attrs: {}, content: uint(pre.id, 3) }, { tag: 'value', attrs: {}, content: pre.value }] })
			users.push({ tag: 'user', attrs: { jid }, content })
		}
		this.result(conn, node, [{ tag: 'list', attrs: {}, content: users }])
	}

	onUsync(conn, node) {
		const usync = getBinaryNodeChild(node, 'usync')
		const protocols = children(getBinaryNodeChild(usync, 'query')).map(p => p.tag)
		const users = []
		for (const u of children(getBinaryNodeChild(usync, 'list'))) {
			const contact = getBinaryNodeChild(u, 'contact')
			let jid = u.attrs.jid
			let found = jid ? this.resolve(jid) : null
			if (!jid && contact?.content) {
				const phone = bytes(contact.content).toString().replace('+', '')
				jid = `${phone}@${S_WHATSAPP_NET}`
				found = this.resolve(jid)
			}
			const content = []
			for (const p of protocols) {
				if (p === 'contact') content.push({ tag: 'contact', attrs: { type: found ? 'in' : 'out' } })
				if (p === 'lid' && found && !found.isLid) content.push({ tag: 'lid', attrs: { val: `${found.account.lid}@lid` } })
				if (p === 'status') content.push({ tag: 'status', attrs: { t: now() }, content: Buffer.from('hello from the mock') })
				if (p === 'disappearing_mode') content.push({ tag: 'disappearing_mode', attrs: { duration: '0', t: now() } })
				if (p === 'devices' && found) {
					const list = [...found.account.devices.keys()].map(id => ({ tag: 'device', attrs: { id: String(id), 'key-index': String(id) } }))
					content.push({ tag: 'devices', attrs: {}, content: [{ tag: 'device-list', attrs: {}, content: list }, { tag: 'key-index-list', attrs: { ts: now() }, content: Buffer.from('mock') }] })
				}
			}
			users.push({ tag: 'user', attrs: { jid }, content })
		}
		this.result(conn, node, [{ tag: 'usync', attrs: { sid: usync.attrs.sid, mode: 'query', last: 'true', index: '0', context: usync.attrs.context }, content: [{ tag: 'result', attrs: {} }, { tag: 'list', attrs: {}, content: users }] }])
	}

	groupNode(g) {
		return {
			tag: 'group',
			attrs: { id: g.id, subject: g.subject, s_t: g.t, s_o: g.owner, creation: g.t, creator: g.owner, addressing_mode: g.addressingMode, size: String(g.members.length) },
			content: g.members.map((jid, i) => ({ tag: 'participant', attrs: i === 0 ? { jid, type: 'superadmin' } : { jid } }))
		}
	}

	onGroupIq(conn, node, first) {
		const target = node.attrs.to
		if (first?.tag === 'create') {
			const id = String(this.nextGroup++)
			const mode = first.attrs.addressing_mode || (getBinaryNodeChild(first, 'lid-mode') ? 'lid' : this.groupAddressing || 'pn')
			const creator = conn.device.account
			const memberJid = phone => {
				const a = this.accounts.get(phone)
				return mode === 'lid' ? `${a.lid}@lid` : `${phone}@${S_WHATSAPP_NET}`
			}
			const others = getBinaryNodeChildren(first, 'participant').map(p => this.resolve(p.attrs.jid)?.account.phone).filter(Boolean)
			const members = [creator.phone, ...others.filter(p => p !== creator.phone)].map(memberJid)
			const g = { id, jid: `${id}@g.us`, subject: first.attrs.subject, t: now(), owner: memberJid(creator.phone), addressingMode: mode, members }
			this.groups.set(g.jid, g)
			this.result(conn, node, [this.groupNode(g)])
			for (const jid of members) {
				const a = this.resolve(jid).account
				for (const d of a.devices.values()) {
					if (d === conn.device || !d.conn) continue
					this.send(d.conn, { tag: 'notification', attrs: { from: g.jid, type: 'w:gp2', id: this.id(), t: now(), participant: g.owner }, content: [{ tag: 'create', attrs: {}, content: [this.groupNode(g)] }] })
				}
			}
			return
		}
		const g = this.groups.get(target)
		if (!g) return this.send(conn, { tag: 'iq', attrs: { from: target, type: 'error', id: node.attrs.id }, content: [{ tag: 'error', attrs: { code: '404', text: 'item-not-found' } }] })
		if (first?.tag === 'query') return this.result(conn, node, [this.groupNode(g)])
		this.result(conn, node)
	}

	groupOwnIdentity(g, account, device) {
		return g.addressingMode === 'lid' ? `${account.lid}:${device}@lid` : `${account.phone}:${device}@${S_WHATSAPP_NET}`
	}

	onMessage(conn, node) {
		const from = conn.device
		const to = node.attrs.to
		this.messageSenders.set(node.attrs.id, from)
		const sent = () => this.send(conn, { tag: 'ack', attrs: { class: 'message', id: node.attrs.id, from: to, t: now() } })
		const carried = children(node).filter(c => c.tag === 'device-identity' || c.tag === 'meta')
		const base = { id: node.attrs.id, t: now(), type: node.attrs.type, notify: from.account.pushName || 'mock' }
		for (const k of ['edit', 'category', 'push_priority']) if (node.attrs[k]) base[k] = node.attrs[k]
		const toDevices = new Map()
		for (const t of children(getBinaryNodeChild(node, 'participants'))) {
			const enc = children(t)[0]
			if (enc) toDevices.set(t.attrs.jid, enc)
		}
		if (node.attrs.category === 'peer') return sent() // only the phone gets these, and the mock has no phone
		if (to.endsWith('@g.us')) {
			const g = this.groups.get(to)
			if (!g) return this.send(conn, { tag: 'ack', attrs: { class: 'message', id: node.attrs.id, from: to, error: '404' } })
			const skmsg = children(node).find(c => c.tag === 'enc')
			const account = from.account
			const direct = new Map()
			for (const [jid, enc] of toDevices) {
				const r = this.resolve(jid)
				if (r) direct.set(`${r.account.phone}.${r.device}`, enc)
			}
			const retry = node.attrs.participant
			for (const memberJid of g.members) {
				const m = this.resolve(memberJid).account
				for (const d of m.devices.values()) {
					if (d === from) continue
					const content = []
					const enc = direct.get(`${m.phone}.${d.id}`)
					if (enc) content.push(enc)
					if (retry && this.resolve(retry)?.account === m && this.resolve(retry).device === d.id) {
						this.deliver(d, { tag: 'message', attrs: { ...base, from: to, participant: this.groupOwnIdentity(g, account, from.id) }, content: [...children(node), ...carried] })
						continue
					}
					if (retry) continue
					if (skmsg) content.push(skmsg)
					const attrs = { ...base, from: to, participant: this.groupOwnIdentity(g, account, from.id), addressing_mode: g.addressingMode }
					if (g.addressingMode === 'lid') attrs.participant_pn = `${account.phone}:${from.id}@${S_WHATSAPP_NET}`
					else attrs.participant_lid = `${account.lid}:${from.id}@lid`
					this.deliver(d, { tag: 'message', attrs, content: [...content, ...carried] })
				}
			}
			return sent()
		}
		const toIsLid = to.endsWith('@lid')
		const account = from.account
		const senderJid = toIsLid ? `${account.lid}:${from.id}@lid` : `${account.phone}:${from.id}@${S_WHATSAPP_NET}`
		const altAttrs = toIsLid ? { sender_pn: `${account.phone}:${from.id}@${S_WHATSAPP_NET}`, addressing_mode: 'lid' } : { sender_lid: `${account.lid}:${from.id}@lid`, addressing_mode: 'pn' }
		// a retry resend has one enc for one device, without a participants node
		const single = children(node).find(c => c.tag === 'enc')
		if (single && !toDevices.size) {
			const r = this.resolve(to)
			const d = r?.account.devices.get(r.device)
			if (d) {
				const attrs = { ...base, from: senderJid, ...altAttrs }
				if (node.attrs.recipient) attrs.recipient = node.attrs.recipient
				this.deliver(d, { tag: 'message', attrs, content: [single, ...carried] })
			}
			return sent()
		}
		for (const [jid, enc] of toDevices) {
			const r = this.resolve(jid)
			const d = r?.account.devices.get(r.device)
			if (!d) continue
			const attrs = { ...base, from: senderJid, ...altAttrs }
			if (r.account === account) attrs.recipient = to
			this.deliver(d, { tag: 'message', attrs, content: [enc, ...carried] })
		}
		sent()
	}

	deliver(device, stanza) {
		this.delivered++
		if (device.conn) this.send(device.conn, stanza)
		else device.offline.push(stanza)
	}

	onReceipt(conn, node) {
		this.send(conn, { tag: 'ack', attrs: { class: 'receipt', id: node.attrs.id, from: node.attrs.to, ...(node.attrs.type ? { type: node.attrs.type } : {}) } })
		const target = this.messageSenders.get(node.attrs.id)
		if (!target) return
		const me = conn.device
		const attrs = { id: node.attrs.id, t: node.attrs.t || now() }
		if (node.attrs.type && node.attrs.type !== 'inactive') attrs.type = node.attrs.type
		const to = node.attrs.to
		if (to.endsWith('@g.us')) {
			attrs.from = to
			attrs.participant = this.groupOwnIdentity(this.groups.get(to), me.account, me.id)
		} else {
			attrs.from = to.endsWith('@lid') ? `${me.account.lid}:${me.id}@lid` : `${me.account.phone}:${me.id}@${S_WHATSAPP_NET}`
		}
		if (me.account === target.account) attrs.recipient = node.attrs.recipient || to
		this.deliver(target, { tag: 'receipt', attrs, content: children(node).length ? children(node) : undefined })
	}

	onAppStateIq(conn, node) {
		const account = conn.device.account
		const out = []
		for (const c of children(getBinaryNodeChild(node, 'sync'))) {
			const name = c.attrs.name
			let st = account.appState.get(name)
			if (!st) account.appState.set(name, (st = { patches: [] }))
			const upload = getBinaryNodeChild(c, 'patch')
			if (upload) {
				// a real server rejects a patch that does not build on the latest version
				if (+c.attrs.version !== st.patches.length) {
					out.push({ tag: 'collection', attrs: { name, type: 'error', version: String(st.patches.length) }, content: [{ tag: 'error', attrs: { code: '409', text: 'conflict' } }] })
					continue
				}
				const patch = proto.SyncdPatch.decode(bytes(upload.content))
				patch.version = { version: st.patches.length + 1 }
				st.patches.push(Buffer.from(proto.SyncdPatch.encode(patch).finish()))
				out.push({ tag: 'collection', attrs: { name, version: String(st.patches.length) } })
				for (const d of account.devices.values()) {
					if (d === conn.device || !d.conn) continue
					this.send(d.conn, { tag: 'notification', attrs: { from: S_WHATSAPP_NET, type: 'server_sync', id: this.id(), t: now() }, content: [{ tag: 'collection', attrs: { name, version: String(st.patches.length) } }] })
				}
				continue
			}
			const since = +c.attrs.version
			const patches = st.patches.slice(since).map(p => ({ tag: 'patch', attrs: {}, content: p }))
			const attrs = { name, version: String(st.patches.length) }
			out.push({ tag: 'collection', attrs, content: patches.length ? [{ tag: 'patches', attrs: {}, content: patches }] : undefined })
		}
		this.result(conn, node, [{ tag: 'sync', attrs: {}, content: out }])
	}

	/** Sends a stanza to every connected device of an account. For server-made events in a check. */
	notifyAccount(phone, stanza) {
		for (const d of this.accounts.get(phone)?.devices.values() ?? []) if (d.conn) this.send(d.conn, stanza)
	}
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
	const server = new MockServer({ log: m => console.log(m) })
	await server.listen(+(process.argv[2] || 0))
	console.log(JSON.stringify({ url: server.url, rootKey: Buffer.from(server.rootKey.public).toString('hex') }))
	process.on('SIGINT', () => server.close().then(() => process.exit(0)))
	process.on('SIGTERM', () => server.close().then(() => process.exit(0)))
}
