// Tool for scripts/e2e.mjs: runs one real Baileys socket in its own process, so that its memory is
// not mixed with the mock server. Same JSON lines on stdin and stdout as examples/e2e_driver.rs.
import { createRequire } from 'module'
import { dirname, join } from 'path'
import { createInterface } from 'readline'
import { fileURLToPath } from 'url'

const here = dirname(fileURLToPath(import.meta.url))
const upstream = join(here, '../upstream')
const require = createRequire(join(upstream, 'package.json'))
const P = require('pino')
const { proto } = await import(join(upstream, 'WAProto/index.js'))
const makeWASocket = (await import(join(upstream, 'lib/Socket/index.js'))).default
const { useMultiFileAuthState } = await import(join(upstream, 'lib/Utils/index.js'))

const out = o => process.stdout.write(JSON.stringify(o) + '\n')
// libsignal prints sessions on stdout, which is the channel to the runner
console.log = () => {}
console.info = () => {}
const sent = new Map()
let auth
let sock

async function start({ url, dir, keepalive }) {
	auth ??= await useMultiFileAuthState(dir)
	sock = makeWASocket({
		waWebSocketUrl: url,
		auth: auth.state,
		logger: P({ level: 'silent' }),
		shouldSyncHistoryMessage: () => false,
		appStateMacVerification: { patch: true, snapshot: true },
		keepAliveIntervalMs: keepalive || 30000,
		// a fast peer can ask for a retry before sendMessage has returned here and the message is stored
		getMessage: async key => {
			for (let i = 0; i < 50 && !sent.has(key.id); i++) await new Promise(r => setTimeout(r, 10))
			return sent.get(key.id)
		}
	})
	sock.ev.on('creds.update', auth.saveCreds)
	sock.ev.on('connection.update', u => {
		if (u.qr) out({ ev: 'qr', qr: u.qr })
		if (u.connection) out({ ev: 'conn', state: u.connection, ...(u.lastDisconnect?.error ? { code: u.lastDisconnect.error.output?.statusCode, error: u.lastDisconnect.error.message } : {}) })
		if (u.receivedPendingNotifications) out({ ev: 'pending' })
	})
	sock.ev.on('messages.upsert', ({ messages, type }) => {
		for (const m of messages) {
			const c = m.message
			const text = c?.conversation || c?.extendedTextMessage?.text
			const e = { ev: 'msg', type, id: m.key.id, jid: m.key.remoteJid, fromMe: !!m.key.fromMe }
			if (m.key.participant) e.participant = m.key.participant
			if (text) e.text = text
			if (m.messageStubType) {
				e.stub = proto.WebMessageInfo.StubType[m.messageStubType]
				e.stubParams = m.messageStubParameters
			}
			out(e)
		}
	})
	sock.ev.on('messages.update', list => {
		for (const u of list) if (u.update.status) out({ ev: 'status', id: u.key.id, status: u.update.status })
	})
	sock.ev.on('message-receipt.update', list => {
		for (const u of list) out({ ev: 'receipt', id: u.key.id })
	})
	sock.ev.on('chats.update', list => {
		for (const u of list) if (u.muteEndTime !== undefined) out({ ev: 'chat_mute', id: u.id, mute: Number(u.muteEndTime) })
	})
	sock.ev.on('groups.upsert', list => {
		for (const g of list) out({ ev: 'group_upsert', id: g.id, subject: g.subject })
	})
}
async function api(name, args) {
	if (name === 'sendMessage') {
		const [jid, kind, text, key] = args
		const content = {
			text: { text },
			edit: { text, edit: key },
			delete: { delete: key },
			react: { react: { text, key } },
			pin: { pin: key, type: proto.PinInChat.Type.PIN_FOR_ALL, time: 86400 },
			location: { location: { degreesLatitude: 1.5, degreesLongitude: 2.5 } },
			poll: { poll: { name: text, values: ['a', 'b'], selectableCount: 1 } },
			disappearing: { disappearingMessagesInChat: true }
		}[kind]
		await sock.sendMessage(jid, content)
	} else if (name === 'sendWAMBuffer') {
		await sock.sendWAMBuffer(Buffer.from('WAM-test'))
	} else if (name === 'createCallLink') {
		await sock.createCallLink(args[0], args[1])
	} else if (name === 'getCatalog') {
		await sock.getCatalog({ jid: args[0], limit: args[1], cursor: args[2] })
	} else if (name === 'updateBussinesProfile') {
		await sock.updateBussinesProfile({ ...args[0], hours: { timezone: 'UTC', days: [{ day: 'mon', mode: 'specific_hours', openTimeInMinutes: '60', closeTimeInMinutes: '120' }, { day: 'tue', mode: 'open_24h' }] } })
	} else if (name === 'sendReceipts') {
		await sock.sendReceipts([args[0]], args[1])
	} else if (name === 'readMessages') {
		await sock.readMessages([args[0]])
	} else if (name === 'refreshMediaConn') {
		await sock.refreshMediaConn(true)
	} else if (name === 'assertSessions') {
		await sock.assertSessions(args[0], true)
	} else if (name === 'getUSyncDevices') {
		await sock.getUSyncDevices(args[0], false, false)
	} else if (name === 'issuePrivacyTokens') {
		await sock.issuePrivacyTokens(args[0], args[1])
	} else if (name === 'addOrEditContact') {
		await sock.addOrEditContact(args[0], { fullName: args[1], firstName: args[2] })
	} else if (name === 'addOrEditQuickReply') {
		await sock.addOrEditQuickReply({ shortcut: args[0], message: args[1], timestamp: args[2] })
	} else if (name === 'groupAcceptInviteV4' || name === 'communityAcceptInviteV4') {
		await sock[name](args[0], { groupJid: args[1], inviteCode: args[2], inviteExpiration: args[3] })
	} else if (name === 'star') {
		await sock.star(args[0], [{ id: args[1], fromMe: true }], true)
	} else if (name === 'addLabel') {
		await sock.addLabel(args[0], { id: args[1], name: args[2], color: 1, deleted: false })
	} else if (name === 'updateDisableLinkPreviewsPrivacy') {
		await sock.updateDisableLinkPreviewsPrivacy(true)
	} else {
		await sock[name](...args)
	}
}
const commands = {
	start,
	send: async ({ jid, text }) => {
		const m = await sock.sendMessage(jid, { text })
		sent.set(m.key.id, m.message)
		// a retry asks only for a recent message, and a long run must not measure this store
		if (sent.size > 1000) sent.delete(sent.keys().next().value)
		return { id: m.key.id }
	},
	group_create: async ({ subject, participants }) => ({ id: (await sock.groupCreate(subject, participants)).id }),
	set_app_key: async ({ id, key }) => {
		await sock.authState.keys.set({ 'app-state-sync-key': { [id]: proto.Message.AppStateSyncKeyData.fromObject({ keyData: Buffer.from(key, 'base64') }) } })
		sock.ev.emit('creds.update', { myAppStateKeyId: id })
	},
	mute: ({ jid, until }) => sock.chatModify({ mute: until }, jid),
	on_whatsapp: async ({ jid }) => ({ exists: !!(await sock.onWhatsApp(jid))?.[0]?.exists }),
	fetch_status: async ({ jid }) => ({ status: (await sock.fetchStatus(jid))?.[0]?.status?.status }),
	drop_session: async ({ jid }) => {
		const addr = sock.signalRepository.jidToSignalProtocolAddress(jid)
		await sock.authState.keys.set({ session: { [addr]: null } })
	},
	api: async ({ name, args }) => {
		try {
			await api(name, args)
			return { ok: true }
		} catch (e) {
			return { ok: false, message: e.message }
		}
	},
	end: () => sock.end(undefined),
	quit: async () => {
		await sock?.end(undefined)
		out({ ev: 'quit' })
		setTimeout(() => process.exit(0), 10)
	}
}
process.on('unhandledRejection', e => process.stderr.write(`unhandled rejection: ${e?.message || e}\n`))
createInterface({ input: process.stdin }).on('line', async line => {
	const { cmd, req, ...args } = JSON.parse(line)
	try {
		const r = await commands[cmd](args)
		out({ ev: 'reply', req, ...(r && typeof r === 'object' ? r : {}) })
	} catch (e) {
		out({ ev: 'reply', req, error: e.message })
	}
})
