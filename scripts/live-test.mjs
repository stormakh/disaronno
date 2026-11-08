// One real WhatsApp run of a client, on a personal account, with the same stats for both clients.
//   node scripts/live-test.mjs rust|baileys
// It shows the QR in this terminal only. It saves counts, sizes and times to bench/results/live-<client>.json, and no
// message text, names or numbers. At the end the client logs out, which unlinks the device, and the keys are deleted.
// LIVE_NO_QR=1 hides the QR and LIVE_QR_ONLY=1 stops at the first QR: this checks the setup without a login.
// LIVE_MINUTES=240 stays linked for that time after the first connection, and saves to live-long-<client>.json.
import { spawn, spawnSync } from 'child_process'
import { mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'fs'
import { dirname, join } from 'path'
import { createInterface } from 'readline'
import { fileURLToPath } from 'url'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const client = process.argv[2]
const FIRST_HISTORY_WAIT_S = 600
const QUIET_S = 240
const MAX_S = 3600
const QR_ONLY = !!process.env.LIVE_QR_ONLY
const LONG_MINUTES = +process.env.LIVE_MINUTES || 0
const LINK_WAIT_S = 1800
// LIVE_PROBE=1, Rust only: also records the allocator counts, huge pages and memory regions, and before the logout
// gives free heap back to the system, to find what holds the memory after a sync
const PROBE = !!process.env.LIVE_PROBE
const TIMELINE_TICKS = LONG_MINUTES ? 300 : 25

const auth = mkdtempSync(join(root, 'target/tmp/live-auth-'))
const cmd = client === 'rust' ? [join(root, 'target/release/examples/live_stats'), auth] : [process.execPath, join(root, 'scripts/live-baileys.mjs'), auth]
const child = spawn(cmd[0], cmd.slice(1), { cwd: root, stdio: ['pipe', 'pipe', 'pipe'] })
const t0 = Date.now()
const now = () => +((Date.now() - t0) / 1000).toFixed(2)
const r = {
	client, started: new Date(t0).toISOString(), done: false, stopReason: null, exit: null, loggedOut: null,
	qrSeenS: null, connections: 0, closeCodes: [], firstOpenS: null, firstHistoryS: null, lastHistoryS: null,
	historyEvents: 0, chats: 0, contacts: 0, messages: 0, upsertEvents: 0, upsertMessages: 0, lastProgress: null, syncTypes: {},
	peakKb: 0, peakAnonKb: 0, lastRssKb: 0, peakThreads: 0, cpuS: 0, cpuAtOpenS: null, cpuAtLastHistoryS: null, peakAtOpenKb: null,
	logs: {}, timeline: [], mem: [], regions: {}
}
const save = () => writeFileSync(join(root, `bench/results/live-${LONG_MINUTES ? 'long-' : PROBE ? 'probe-' : ''}${client}.json`), JSON.stringify(r, null, 1) + '\n')
const procKb = (file, k) => {
	try {
		return +readFileSync(`/proc/${child.pid}/${file}`, 'utf8').match(new RegExp(`${k}:\\s+(\\d+)`))[1]
	} catch {
		return null
	}
}
// resident memory by kind of mapping, and the largest anonymous mappings
const regions = () => {
	const kinds = {}
	const anon = []
	let cur
	for (const line of readFileSync(`/proc/${child.pid}/smaps`, 'utf8').split('\n')) {
		const head = line.match(/^[0-9a-f]+-[0-9a-f]+ \S+ \S+ \S+ \d+\s*(.*)$/)
		if (head) {
			const name = head[1] ? head[1].split('/').pop() : 'anon'
			cur = { name, sizeKb: 0, rssKb: 0, hugeKb: 0 }
			anon.push(cur)
			continue
		}
		const m = line.match(/^(Size|Rss|AnonHugePages):\s+(\d+)/)
		if (cur && m) cur[{ Size: 'sizeKb', Rss: 'rssKb', AnonHugePages: 'hugeKb' }[m[1]]] = +m[2]
	}
	for (const a of anon) {
		const k = (kinds[a.name] ??= { rssKb: 0, hugeKb: 0, count: 0 })
		k.rssKb += a.rssKb
		k.hugeKb += a.hugeKb
		k.count++
	}
	return { kinds, top: anon.filter(a => a.name === 'anon' || a.name === '[heap]').sort((a, b) => b.rssKb - a.rssKb).slice(0, 12) }
}
const diskUse = () => {
	let kB = 0
	const names = readdirSync(auth)
	for (const f of names) kB += statSync(join(auth, f)).size / 1024
	return { diskKb: Math.round(kB), files: names.length }
}
const scrub = m => String(m).replace(/\S*@\S*/g, '<jid>').replace(/\d+/g, '#').slice(0, 120)

const showQr = qr => {
	if (process.env.LIVE_NO_QR) return console.log('QR received, hidden')
	process.stdout.write('\x1b[2J\x1b[H')
	// phone scanners need a light border of about 4 modules around the code
	spawnSync('qrencode', ['-t', 'ANSIUTF8', '-m', '4', qr], { stdio: ['ignore', 'inherit', 'inherit'] })
	console.log(`${client}: on your phone, open WhatsApp > Linked devices > Link a device, and scan this code.`)
}
const status = () => {
	process.stdout.write(`\r${client}: ${Math.round(now())} s, ${r.messages} messages, ${r.chats} chats, peak ${(r.peakKb / 1024).toFixed(1)} MB, CPU ${r.cpuS.toFixed(1)} s   `)
}
const stop = reason => {
	if (r.stopReason) return
	r.stopReason = reason
	if (PROBE && reason === 'history went quiet') {
		r.regions.beforeTrim = regions()
		child.stdin.write('trim\n')
		setTimeout(() => {
			r.regions.afterTrim = regions()
			child.stdin.write('stop\n')
			setTimeout(() => child.kill(), 20000).unref()
		}, 10000)
		return
	}
	child.stdin.write('stop\n')
	setTimeout(() => child.kill(), 20000).unref()
}
createInterface({ input: child.stdout }).on('line', line => {
	let e
	try {
		e = JSON.parse(line)
	} catch {
		return
	}
	if (e.ev === 'qr') {
		r.qrSeenS ??= now()
		showQr(e.qr)
		if (QR_ONLY) stop('qr only')
	} else if (e.ev === 'conn' && e.state === 'open') {
		r.connections++
		r.firstOpenS ??= now()
		r.cpuAtOpenS ??= r.cpuS
		r.peakAtOpenKb ??= r.peakKb
		console.log(`\n${client}: linked. Syncing your history. Keep WhatsApp open on your phone.`)
	} else if (e.ev === 'closed') {
		r.closeCodes.push(e.code)
	} else if (e.ev === 'history') {
		r.firstHistoryS ??= now()
		r.lastHistoryS = now()
		r.historyEvents++
		r.chats += e.chats
		r.contacts += e.contacts
		r.messages += e.messages
		r.cpuAtLastHistoryS = r.cpuS
		if (e.progress != null) r.lastProgress = e.progress
		if (e.syncType != null) r.syncTypes[e.syncType] = (r.syncTypes[e.syncType] || 0) + 1
	} else if (e.ev === 'upsert') {
		r.upsertEvents++
		r.upsertMessages += e.messages
	} else if (e.ev === 'stopped') {
		r.loggedOut = e.loggedOut
	} else if (e.ev === 'mem') {
		const { ev, ...counts } = e
		r.mem.push({ s: Math.round(now()), rssKb: procKb('status', 'VmRSS'), anonKb: procKb('status', 'RssAnon'), hugeKb: procKb('smaps_rollup', 'AnonHugePages'), ...counts })
		save()
	}
})
createInterface({ input: child.stderr }).on('line', line => {
	let key
	try {
		const j = JSON.parse(line)
		if (j.level < 40) return
		key = `${j.level} ${scrub(j.msg)}`
	} catch {
		key = `raw ${scrub(line)}`
	}
	r.logs[key] = (r.logs[key] || 0) + 1
})
let ticks = 0
const sample = setInterval(() => {
	try {
		const st = readFileSync(`/proc/${child.pid}/status`, 'utf8')
		const get = k => +st.match(new RegExp(`${k}:\\s+(\\d+)`))[1]
		r.peakKb = Math.max(r.peakKb, get('VmHWM'))
		r.peakAnonKb = Math.max(r.peakAnonKb, get('RssAnon'))
		r.lastRssKb = get('VmRSS')
		r.peakThreads = Math.max(r.peakThreads, get('Threads'))
		// the two fields after the name, which can hold spaces: utime and stime are 12 and 13 after `)`
		const f = readFileSync(`/proc/${child.pid}/stat`, 'utf8').split(') ')[1].split(' ')
		r.cpuS = (+f[11] + +f[12]) / 100
		r.lastAnonKb = get('RssAnon')
		r.lastThreads = get('Threads')
	} catch {
		return
	}
	if (++ticks % 25 === 0) status()
	if (ticks % TIMELINE_TICKS === 0) {
		let fds = null
		try {
			fds = readdirSync(`/proc/${child.pid}/fd`).length
		} catch {}
		r.timeline.push({ s: Math.round(now()), rssKb: r.lastRssKb, anonKb: r.lastAnonKb, cpuS: r.cpuS, threads: r.lastThreads, fds, messages: r.messages, upserts: r.upsertMessages, connections: r.connections, ...diskUse(), ...(PROBE ? { hugeKb: procKb('smaps_rollup', 'AnonHugePages') } : {}) })
		if (PROBE && !r.stopReason) child.stdin.write('mem\n')
		save()
	}
	if (r.stopReason) return
	const t = now()
	if (LONG_MINUTES) {
		if (r.firstOpenS == null && t > LINK_WAIT_S) stop('not linked')
		else if (r.firstOpenS != null && t - r.firstOpenS > LONG_MINUTES * 60) stop('time limit')
		return
	}
	if (t > MAX_S) stop('time limit')
	else if (r.firstOpenS != null && r.firstHistoryS == null && t - r.firstOpenS > FIRST_HISTORY_WAIT_S) stop('no history arrived')
	else if (r.firstHistoryS != null && t - r.lastHistoryS > QUIET_S) stop('history went quiet')
}, 100)
for (const sig of ['SIGINT', 'SIGHUP', 'SIGTERM']) process.on(sig, () => stop(`signal ${sig}`))
child.on('exit', (code, signal) => {
	clearInterval(sample)
	r.exit = signal || code
	r.done = true
	save()
	rmSync(auth, { recursive: true, force: true })
	console.log(`\n${client}: finished: ${r.stopReason || 'client stopped'}. ${r.messages} messages, peak ${(r.peakKb / 1024).toFixed(1)} MB, CPU ${r.cpuS.toFixed(1)} s. Device unlinked: ${r.loggedOut === true ? 'yes' : 'NO, unlink it on your phone'}.`)
	process.exit(0)
})
