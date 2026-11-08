// Interop with the real Baileys build. `gen` writes vectors for Rust. `check` reads the Rust reply and decrypts it.
import { readFileSync, writeFileSync } from 'fs'
import { dirname, join } from 'path'
import { fileURLToPath } from 'url'
const here = dirname(fileURLToPath(import.meta.url))
const lib = join(here, '../upstream/lib')
const load = p => import(join(lib, p))
const { proto } = await import(join(here, '../upstream/WAProto/index.js'))
const c = await load('Utils/crypto.js')
const { makeLibSignalRepository } = await load('Signal/libsignal.js')
const { initAuthCreds } = await load('Utils/auth-utils.js')
const { encodeBinaryNode, decodeBinaryNode } = await load('WABinary/index.js')
const { LT_HASH_ANTI_TAMPERING } = await load('Utils/lt-hash.js')
const P = (await import(join(here, '../upstream/node_modules/pino/pino.js'))).default
const logger = P({ level: 'silent' })
const hex = b => Buffer.from(b).toString('hex')
const out = join(here, '../tests-data/interop.json')
const memStore = init => {
	const d = init || {}
	return {
		d,
		get: async (t, ids) => { const o = {}; for (const id of ids) { const v = d[t]?.[id]; if (v !== undefined && v !== null) o[id] = v } return o },
		set: async data => { for (const t in data) { d[t] ??= {}; for (const id in data[t]) { const v = data[t][id]; if (v) d[t][id] = v; else delete d[t][id] } } },
		transaction: async work => work(),
		isInTransaction: () => false
	}
}
const ALICE = '1111@s.whatsapp.net', BOB = '2222@s.whatsapp.net', GROUP = '1203630@g.us'
if (process.argv[2] === 'gen') {
	const key = Buffer.alloc(32, 7), iv16 = Buffer.alloc(16, 9), iv12 = Buffer.alloc(12, 3), aad = Buffer.from('aad'), data = Buffer.from('The quick brown fox jumps over the lazy dog, twice over.')
	const kp = { private: Buffer.alloc(32, 0).fill(0x41), public: null }
	const a = c.Curve.generateKeyPair(), b = c.Curve.generateKeyPair()
	const sigMsg = Buffer.from('sign me')
	const v = {
		key: hex(key), iv16: hex(iv16), iv12: hex(iv12), aad: hex(aad), data: hex(data),
		sha256: hex(c.sha256(data)), md5: hex(c.md5(data)),
		hmac256: hex(c.hmacSign(data, key)), hmac512: hex(c.hmacSign(data, key, 'sha512')),
		hkdf: hex(c.hkdf(data, 112, { info: 'WhatsApp Image Keys' })), hkdf_salt: hex(c.hkdf(data, 64, { salt: key, info: '' })),
		gcm: hex(c.aesEncryptGCM(data, key, iv12, aad)), ctr: hex(c.aesEncryptCTR(data, key, iv16)), cbc: hex(c.aesEncrypWithIV(data, key, iv16)),
		pbkdf: hex(await c.derivePairingCodeKey('ABCD1234', key)),
		x_a_priv: hex(a.private), x_a_pub: hex(a.public), x_b_pub: hex(b.public), x_shared: hex(c.Curve.sharedKey(a.private, b.public)),
		sig_msg: hex(sigMsg), sig: hex(c.Curve.sign(a.private, sigMsg)),
		lt: hex(LT_HASH_ANTI_TAMPERING.subtractThenAdd(Buffer.alloc(128, 5), [Buffer.alloc(32, 1), Buffer.alloc(20, 2)], [Buffer.alloc(32, 3)]))
	}
	// binary nodes: strings of each encoding class
	const nodes = [
		{ tag: 'iq', attrs: { id: '123-456.789', xmlns: 'w:g2', to: 'g.us', type: 'get', hexv: 'ABCDEF0123', jid: '1555:7@s.whatsapp.net', lid: '99@lid', host: '77:99@hosted', hl: '77:99@hosted.lid', free: 'héllo wörld', e: '' }, content: [{ tag: 'a', attrs: {}, content: 'text value' }, { tag: 'b', attrs: {} }, { tag: 'c', attrs: { x: 'y' }, content: Buffer.alloc(300, 1) }] },
		{ tag: 'message', attrs: {}, content: Buffer.alloc(1 << 20, 2) }
	]
	v.nodes = nodes.map(n => hex(encodeBinaryNode(n)))
	// a signal conversation started by Node, for Rust to continue
	const mk = () => { const creds = initAuthCreds(); const keys = memStore(); return { creds, keys, repo: makeLibSignalRepository({ creds, keys }, logger) } }
	const alice = mk(), bob = mk()
	const pk = c.Curve.generateKeyPair()
	const pub = k => Buffer.concat([Buffer.from([5]), k])
	await alice.repo.injectE2ESession({ jid: BOB, session: { registrationId: bob.creds.registrationId, identityKey: pub(bob.creds.signedIdentityKey.public), signedPreKey: { keyId: bob.creds.signedPreKey.keyId, publicKey: pub(bob.creds.signedPreKey.keyPair.public), signature: bob.creds.signedPreKey.signature }, preKey: { keyId: 1, publicKey: pub(pk.public) } } })
	const msgs = []
	for (const t of ['first', 'second', 'third']) { const e = await alice.repo.encryptMessage({ jid: BOB, data: Buffer.from(t) }); msgs.push({ type: e.type, c: hex(e.ciphertext), p: t }) }
	const skdm = await alice.repo.getSenderKeyDistributionMessage({ group: GROUP, meId: ALICE })
	const groupMsgs = []
	for (const t of ['g one', 'g two']) { const e = await alice.repo.encryptGroupMessage({ group: GROUP, meId: ALICE, data: Buffer.from(t) }); groupMsgs.push({ c: hex(e.ciphertext), p: t }) }
	v.signal = {
		bob: { reg: bob.creds.registrationId, id_priv: hex(bob.creds.signedIdentityKey.private), id_pub: hex(bob.creds.signedIdentityKey.public), spk_priv: hex(bob.creds.signedPreKey.keyPair.private), spk_pub: hex(bob.creds.signedPreKey.keyPair.public), spk_sig: hex(bob.creds.signedPreKey.signature), spk_id: bob.creds.signedPreKey.keyId, pk_priv: hex(pk.private), pk_pub: hex(pk.public) },
		msgs, skdm: hex(skdm), groupMsgs,
		alice_session: JSON.stringify(alice.keys.d.session),
		alice_id_priv: hex(alice.creds.signedIdentityKey.private), alice_id_pub: hex(alice.creds.signedIdentityKey.public), alice_reg: alice.creds.registrationId, alice_spk_priv: hex(alice.creds.signedPreKey.keyPair.private), alice_spk_pub: hex(alice.creds.signedPreKey.keyPair.public), alice_spk_sig: hex(alice.creds.signedPreKey.signature)
	}
	v.proto = { wmi: readFileSync(join(here, '../bench/fixtures/wmi.bin')).toString('hex') }
	const wmi = proto.WebMessageInfo.decode(readFileSync(join(here, '../bench/fixtures/wmi.bin')))
	v.proto.wmi_json = JSON.stringify(wmi.toJSON())
	writeFileSync(out, JSON.stringify(v))
	console.log('wrote', out)
} else {
	// Alice in Node reads Rust's replies, using the session state Rust loaded and Node kept
	const v = JSON.parse(readFileSync(out, 'utf8'))
	const r = JSON.parse(readFileSync(join(here, '../tests-data/interop-rust.json'), 'utf8'))
	const s = v.signal
	const h = x => Buffer.from(x, 'hex')
	const creds = { signedIdentityKey: { private: h(s.alice_id_priv), public: h(s.alice_id_pub) }, registrationId: s.alice_reg, signedPreKey: { keyId: 1, keyPair: { private: h(s.alice_spk_priv), public: h(s.alice_spk_pub) }, signature: h(s.alice_spk_sig) } }
	const keys = memStore({ session: JSON.parse(s.alice_session) })
	const repo = makeLibSignalRepository({ creds, keys }, logger)
	let ok = 0
	for (const m of r.to_alice) {
		const pt = await repo.decryptMessage({ jid: BOB, type: m.type, ciphertext: h(m.c) })
		if (pt.toString() !== m.p) throw new Error('mismatch: ' + pt)
		ok++
	}
	// a fresh Rust-started session and Rust group messages, read by Node
	const bob2 = { creds: { signedIdentityKey: { private: h(r.fresh.id_priv), public: h(r.fresh.id_pub) }, registrationId: r.fresh.reg, signedPreKey: { keyId: 1, keyPair: { private: h(r.fresh.spk_priv), public: h(r.fresh.spk_pub) }, signature: h(r.fresh.spk_sig) } }, keys: memStore({ 'pre-key': { 1: { private: h(r.fresh.pk_priv), public: h(r.fresh.pk_pub) } } }) }
	const repo2 = makeLibSignalRepository(bob2, logger)
	for (const m of r.fresh.msgs) { const pt = await repo2.decryptMessage({ jid: ALICE, type: m.type, ciphertext: h(m.c) }); if (pt.toString() !== m.p) throw new Error('fresh mismatch'); ok++ }
	await repo2.processSenderKeyDistributionMessage({ authorJid: ALICE, item: { groupId: GROUP, axolotlSenderKeyDistributionMessage: h(r.fresh.skdm) } })
	for (const m of r.fresh.group) { const pt = await repo2.decryptGroupMessage({ group: GROUP, authorJid: ALICE, msg: h(m.c) }); if (pt.toString() !== m.p) throw new Error('group mismatch'); ok++ }
	if (!c.Curve.verify(h(r.sig.pub), h(r.sig.msg), h(r.sig.sig))) throw new Error('Node rejected a Rust signature')
	console.log('Node read every Rust message:', ok, 'and accepted the Rust signature')
}
