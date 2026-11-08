// Tool for scripts/live-test.mjs: real Baileys, with the same settings and JSON lines as examples/live_stats.rs.
// It never prints message text, names or numbers. `stop` on stdin logs out, which unlinks the device.
import { createRequire } from 'module'
import { dirname, join } from 'path'
import { createInterface } from 'readline'
import { fileURLToPath } from 'url'

const here = dirname(fileURLToPath(import.meta.url))
const upstream = join(here, '../upstream')
const require = createRequire(join(upstream, 'package.json'))
const P = require('pino')
const makeWASocket = (await import(join(upstream, 'lib/Socket/index.js'))).default
const { useMultiFileAuthState, DisconnectReason } = await import(join(upstream, 'lib/index.js'))

const out = o => process.stdout.write(JSON.stringify(o) + '\n')
// libsignal prints sessions on stdout, which is the channel to the runner
console.log = () => {}
console.info = () => {}
const auth = await useMultiFileAuthState(process.argv[2])
let sock

const start = () => {
	sock = makeWASocket({
		auth: auth.state,
		logger: P({ level: 'info' }, P.destination(2)),
		markOnlineOnConnect: false,
		syncFullHistory: true,
		shouldSyncHistoryMessage: () => true
	})
	sock.ev.on('creds.update', auth.saveCreds)
	sock.ev.on('connection.update', async u => {
		if (u.qr) out({ ev: 'qr', qr: u.qr })
		if (!u.connection) return
		out({ ev: 'conn', state: u.connection })
		if (u.connection !== 'close') return
		const code = u.lastDisconnect?.error?.output?.statusCode ?? null
		out({ ev: 'closed', code })
		if ([DisconnectReason.loggedOut, DisconnectReason.forbidden, DisconnectReason.connectionReplaced].includes(code)) process.exit(1)
		setTimeout(start, 1000)
	})
	sock.ev.on('messaging-history.set', h => {
		out({ ev: 'history', chats: h.chats.length, contacts: h.contacts.length, messages: h.messages.length, progress: h.progress ?? undefined, isLatest: h.isLatest, syncType: h.syncType ?? undefined })
	})
	sock.ev.on('messages.upsert', u => out({ ev: 'upsert', messages: u.messages.length }))
}
start()
createInterface({ input: process.stdin }).on('line', async line => {
	if (line.trim() !== 'stop') return
	let loggedOut = false
	try {
		await sock.logout()
		loggedOut = true
	} catch {}
	out({ ev: 'stopped', loggedOut })
	setTimeout(() => process.exit(0), 1000)
})
