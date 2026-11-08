// End-to-end runs against scripts/mock-server.mjs, with this port and with real Baileys.
//
//   node scripts/e2e.mjs                 all runs: rust-rust, baileys-baileys, rust-baileys, baileys-rust
//   node scripts/e2e.mjs rust-rust       one run
//   node scripts/e2e.mjs checks          WAM bytes, refusal of a bad root key, thread count after end
//   node scripts/e2e.mjs burst [count]   many messages at once, to find deadlocks and lost messages
//   node scripts/e2e.mjs memory          peak memory of each client in the flow, with the release driver.
//                                        Writes bench/results/e2e-memory.json. Static glibc would save 1.4 MB, but it
//                                        crashes in getaddrinfo when glibc loads an NSS module such as libnss_resolve.
//   node scripts/e2e.mjs soak rust|baileys [minutes]   a long run of two clients, with steady traffic and reconnects.
//                                        Writes memory and CPU of each client process to bench/results/soak-<kind>.json.
//
// Each run does the same flow, and every plaintext is checked on the receiving side. At the end the
// stanzas of the Rust clients are compared with the stanzas of the Baileys clients, with the random
// parts masked. Needs: cargo build -p baileys --example e2e_driver
import { spawn } from 'child_process'
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'fs'
import { tmpdir } from 'os'
import { dirname, join } from 'path'
import { createInterface } from 'readline'
import { fileURLToPath } from 'url'
import { MockServer } from './mock-server.mjs'

const here = dirname(fileURLToPath(import.meta.url))
const upstream = join(here, '../upstream')
const DRIVER = process.env.E2E_DRIVER || join(here, ['memory', 'soak'].includes(process.argv[2]) ? '../target/release/examples/e2e_driver' : '../target/debug/examples/e2e_driver')
const BAILEYS_DRIVER = join(here, 'e2e-baileys-driver.mjs')
// a new login writes 812 pre-key files, which takes long on a busy disk
const WAIT_MS = 60000
const baseTmp = mkdtempSync(join(process.env.E2E_TMP || tmpdir(), 'wa-e2e-'))
const sleep = ms => new Promise(r => setTimeout(r, ms))

class Waitable {
	constructor(label) {
		this.label = label
		this.events = []
		this.waiters = []
	}
	push(e) {
		this.events.push(e)
		for (const w of [...this.waiters]) {
			if (w.pred(e)) {
				clearTimeout(w.timer)
				this.waiters.splice(this.waiters.indexOf(w), 1)
				w.resolve(e)
			}
		}
	}
	/** Waits for an event that matches. It also looks at the events that already came in. */
	wait(pred, what = 'event', ms = WAIT_MS) {
		const found = this.events.find(pred)
		if (found) return Promise.resolve(found)
		return new Promise((resolve, reject) => {
			const w = { pred, resolve }
			w.timer = setTimeout(() => {
				this.waiters.splice(this.waiters.indexOf(w), 1)
				reject(new Error(`${this.label}: timed out waiting for ${what}. Events: ${JSON.stringify(this.events.slice(-8))}`))
			}, ms)
			this.waiters.push(w)
		})
	}
	forget() {
		this.events = []
	}
}
/** Peak memory of each client process that has ended. */
const memoryRecords = []
const procStatus = pid => {
	const out = {}
	for (const line of readFileSync(`/proc/${pid}/status`, 'utf8').split('\n')) {
		const m = line.match(/^(VmHWM|VmRSS|RssAnon|RssFile|Threads):\s+(\d+)/)
		if (m) out[m[1]] = +m[2]
	}
	return out
}
/** Where the resident memory of a process is, largest first: mapped file, or kind of anonymous region. */
const smapsSummary = pid => {
	const regions = new Map()
	let name = ''
	for (const line of readFileSync(`/proc/${pid}/smaps`, 'utf8').split('\n')) {
		const head = line.match(/^[0-9a-f]+-[0-9a-f]+ (\S+) \S+ \S+ \S+\s*(.*)$/)
		if (head) {
			const path = head[2].split('/').pop() || 'anon'
			name = `${path} ${head[1]}`
		} else {
			const m = line.match(/^Rss:\s+(\d+)/)
			if (m) regions.set(name, (regions.get(name) || 0) + +m[1])
		}
	}
	return [...regions].filter(([, v]) => v > 0).sort((a, b) => b[1] - a[1]).map(([k, v]) => `${v} ${k}`).slice(0, 10).join(', ')
}
/** One client in its own process: the Rust driver, or real Baileys in scripts/e2e-baileys-driver.mjs. */
class Client extends Waitable {
	constructor(kind, label) {
		super(label)
		this.kind = kind
		this.dir = join(baseTmp, label)
		this.nextReq = 1
		this.replies = new Map()
		this.proc = kind === 'rust' ? spawn(DRIVER, [], { stdio: ['pipe', 'pipe', 'pipe'] }) : spawn(process.execPath, [BAILEYS_DRIVER], { stdio: ['pipe', 'pipe', 'pipe'] })
		this.peakThreads = 0
		this.sampler = setInterval(() => {
			try {
				this.peakThreads = Math.max(this.peakThreads, procStatus(this.proc.pid).Threads || 0)
			} catch {}
		}, 20)
		this.stderr = ''
		this.proc.stderr.on('data', d => (this.stderr += d))
		createInterface({ input: this.proc.stdout }).on('line', line => {
			const e = JSON.parse(line)
			if (e.ev === 'reply') {
				const r = this.replies.get(e.req)
				this.replies.delete(e.req)
				if (e.error) r?.reject(new Error(`${label}: ${e.error}`))
				else r?.resolve(e)
			} else this.push(e)
		})
	}
	cmd(cmd, args = {}) {
		const req = this.nextReq++
		return new Promise((resolve, reject) => {
			const timer = setTimeout(() => reject(new Error(`${this.label}: no reply to ${cmd}. stderr: ${this.stderr}`)), WAIT_MS)
			this.replies.set(req, { resolve: v => (clearTimeout(timer), resolve(v)), reject: e => (clearTimeout(timer), reject(e)) })
			this.proc.stdin.write(JSON.stringify({ cmd, req, ...args }) + '\n')
		})
	}
	start(server, opts = {}) {
		return this.cmd('start', { url: server.url, root: Buffer.from(server.rootKey.public).toString('hex'), dir: this.dir, keepalive: opts.keepalive || 30000 })
	}
	async send(jid, text) {
		return (await this.cmd('send', { jid, text })).id
	}
	async createGroup(subject, participants) {
		return (await this.cmd('group_create', { subject, participants })).id
	}
	setAppKey(id, key) {
		return this.cmd('set_app_key', { id, key })
	}
	mute(jid, until) {
		return this.cmd('mute', { jid, until })
	}
	async onWhatsApp(jid) {
		return (await this.cmd('on_whatsapp', { jid })).exists
	}
	async fetchStatus(jid) {
		return (await this.cmd('fetch_status', { jid })).status
	}
	dropSession(jid) {
		return this.cmd('drop_session', { jid })
	}
	async api(name, args) {
		const r = await this.cmd('api', { name, args })
		return r.ok ? null : r.message
	}
	end() {
		return this.cmd('end')
	}
	async threads() {
		return (await this.cmd('threads')).threads
	}
	async quit() {
		clearInterval(this.sampler)
		try {
			memoryRecords.push({ kind: this.kind, label: this.label, peakThreads: this.peakThreads, ...procStatus(this.proc.pid), smaps: smapsSummary(this.proc.pid) })
		} catch {}
		await this.cmd('quit').catch(() => {})
		this.proc.kill()
	}
}
const make = (kind, label) => new Client(kind, label)

let checks = 0
const check = (cond, what) => {
	if (!cond) throw new Error(`check failed: ${what}`)
	checks++
}
const textWait = (c, text, extra = () => true) => c.wait(e => e.ev === 'msg' && e.text === text && extra(e), `message "${text}"`)
const opened = c => c.wait(e => e.ev === 'conn' && e.state === 'open', 'connection open')

/** A client acks each receipt it handled. The mock only routes it from the other client. */
async function ackedReceipt(server, label, id) {
	for (let i = 0; i < 300; i++) {
		if ((server.stanzaLog.get(label) || []).some(n => n.tag === 'ack' && n.attrs.class === 'receipt' && n.attrs.id === id)) {
			checks++
			return
		}
		await sleep(10)
	}
	throw new Error(`${label} did not ack the receipt of ${id}`)
}
async function pair(server, client, phone, label, opts) {
	server.labelNext(`${label}:pair`)
	await client.start(server, opts)
	const { qr } = await client.wait(e => e.ev === 'qr', 'QR')
	check(qr.startsWith('https://wa.me/settings/linked_devices#'), `${label} QR text`)
	const scan = server.scan(qr, phone)
	check(scan.ok, `${label} scan: ${scan.error}`)
	const closed = await client.wait(e => e.ev === 'conn' && e.state === 'close', 'restart after pairing')
	check(closed.code === 515, `${label} closes with 515 after pairing, got ${closed.code}`)
	client.forget()
	await sleep(50)
	server.labelNext(`${label}:login`)
	await client.start(server, opts)
	await opened(client)
	await client.wait(e => e.ev === 'pending', 'pending notifications')
	await sleep(200)
	if (process.env.E2E_VERBOSE) console.log(`    ${client.label} after login: ${JSON.stringify(procStatus(client.proc.pid))}`)
	return scan.device
}
async function apiCalls(c, { jidB, g }) {
	const nl = '111222@newsletter'
	const msgKey = { remoteJid: jidB, id: 'MOCKMSGID1', fromMe: false }
	const ownKey = { remoteJid: jidB, id: 'MOCKMSGID2', fromMe: true }
	const calls = [
		['updateMessagesPrivacy', ['all']], ['updateCallPrivacy', ['known']], ['updateLastSeenPrivacy', ['contacts']], ['updateOnlinePrivacy', ['all']], ['updateProfilePicturePrivacy', ['none']],
		['updateStatusPrivacy', ['contact_blacklist']], ['updateReadReceiptsPrivacy', ['none']], ['updateGroupsAddPrivacy', ['contacts']], ['updateDefaultDisappearingMode', [86400]], ['getBotListV2', []],
		['fetchStatus', [jidB]], ['fetchDisappearingDuration', [jidB]], ['removeProfilePicture', [jidB]], ['updateProfileStatus', ['my status']], ['fetchBlocklist', []],
		['updateBlockStatus', [jidB, 'block']], ['updateBlockStatus', [jidB, 'unblock']], ['getBusinessProfile', [jidB]], ['cleanDirtyBits', ['groups']], ['cleanDirtyBits', ['account_sync', '123']],
		['profilePictureUrl', [jidB, 'image']], ['profilePictureUrl', [g, 'preview']], ['createCallLink', ['audio']], ['createCallLink', ['video', { startTime: 123 }]],
		['sendPresenceUpdate', ['composing', jidB]], ['sendPresenceUpdate', ['recording', jidB]], ['sendPresenceUpdate', ['paused', jidB]], ['sendPresenceUpdate', ['available']], ['sendPresenceUpdate', ['unavailable']], ['presenceSubscribe', [jidB]],
		['digestKeyBundle', []], ['rotateSignedPreKey', []], ['sendWAMBuffer', []], ['fetchAccountReachoutTimelock', []], ['fetchNewChatMessageCap', []],
		['groupMetadata', [g]], ['groupCreate', ['subject x', [jidB]]], ['groupLeave', ['123@g.us']], ['groupUpdateSubject', [g, 'new subject']], ['groupRequestParticipantsList', [g]], ['groupRequestParticipantsUpdate', [g, [jidB], 'approve']],
		['groupParticipantsUpdate', [g, [jidB], 'promote']], ['groupParticipantsUpdate', [g, [jidB], 'demote']], ['groupUpdateDescription', [g, 'a description']], ['groupUpdateDescription', [g]], ['groupInviteCode', [g]], ['groupRevokeInvite', [g]], ['groupAcceptInvite', ['CODE']],
		['groupRevokeInviteV4', [g, jidB]], ['groupGetInviteInfo', ['CODE']], ['groupToggleEphemeral', [g, 86400]], ['groupToggleEphemeral', [g, 0]], ['groupSettingUpdate', [g, 'announcement']], ['groupMemberAddMode', [g, 'all_member_add']], ['groupJoinApprovalMode', [g, 'on']], ['groupFetchAllParticipating', []],
		['newsletterCreate', ['nl name', 'nl desc']], ['newsletterCreate', ['nl name']], ['newsletterSubscribers', [nl]], ['newsletterMetadata', ['jid', nl]], ['newsletterMetadata', ['invite', 'CODE']], ['newsletterFollow', [nl]], ['newsletterUnfollow', [nl]], ['newsletterMute', [nl]], ['newsletterUnmute', [nl]],
		['newsletterUpdateName', [nl, 'a name']], ['newsletterUpdateDescription', [nl, 'a desc']], ['newsletterRemovePicture', [nl]], ['newsletterReactMessage', [nl, '99', 'x']], ['newsletterReactMessage', [nl, '99']], ['newsletterFetchMessages', [nl, 10, 5, 7]], ['subscribeNewsletterUpdates', [nl]],
		['newsletterAdminCount', [nl]], ['newsletterChangeOwner', [nl, jidB]], ['newsletterDemote', [nl, jidB]], ['newsletterDelete', [nl]],
		['communityMetadata', [g]], ['communityCreate', ['c name', 'c body']], ['communityCreateGroup', ['c sub', [jidB], g]], ['communityLeave', ['123@g.us']], ['communityUpdateSubject', [g, 'c subject']], ['communityLinkGroup', ['5@g.us', g]], ['communityUnlinkGroup', ['5@g.us', g]],
		['communityFetchLinkedGroups', [g]], ['communityRequestParticipantsList', [g]], ['communityRequestParticipantsUpdate', [g, [jidB], 'reject']], ['communityParticipantsUpdate', [g, [jidB], 'remove']], ['communityParticipantsUpdate', [g, [jidB], 'add']], ['communityInviteCode', [g]], ['communityRevokeInvite', [g]], ['communityAcceptInvite', ['CODE']],
		['communityRevokeInviteV4', [g, jidB]], ['communityGetInviteInfo', ['CODE']], ['communityToggleEphemeral', [g, 86400]], ['communityToggleEphemeral', [g, 0]], ['communitySettingUpdate', [g, 'locked']], ['communityMemberAddMode', [g, 'admin_add']], ['communityJoinApprovalMode', [g, 'off']], ['communityFetchAllParticipating', []],
		['updateBussinesProfile', [{ address: 'addr', email: 'e@x', description: 'desc', websites: ['https://a.example'] }]], ['removeCoverPhoto', ['77']], ['getCatalog', [jidB, 5, 'cursor']], ['getCollections', [jidB, 7]], ['getOrderDetails', ['order1', 'tok']], ['productDelete', [['p1', 'p2']]],
		['sendReceipt', [jidB, null, ['MID1', 'MID2'], 'read']], ['sendReceipt', [jidB, jidB, ['MID3'], 'sender']], ['sendReceipts', [msgKey, 'read']], ['readMessages', [msgKey]], ['refreshMediaConn', []], ['assertSessions', [[jidB]]], ['getUSyncDevices', [[jidB]]],
		['updateMemberLabel', [g, 'a label']], ['fetchMessageHistory', [50, ownKey, 1700000000]], ['rejectCall', ['call-id', jidB]], ['issuePrivacyTokens', [[jidB], 1700000000]],
		['star', [jidB, 'MID4']], ['addLabel', [jidB, 'L1', 'label']], ['addChatLabel', [jidB, 'L1']], ['removeChatLabel', [jidB, 'L1']], ['addMessageLabel', [jidB, 'M1', 'L1']], ['removeMessageLabel', [jidB, 'M1', 'L1']], ['removeContact', [jidB]], ['updateDisableLinkPreviewsPrivacy', []], ['removeQuickReply', ['1700000000']], ['updateProfileName', ['New Name']],
		['addOrEditContact', [jidB, 'Full Name', 'First']], ['addOrEditQuickReply', ['sc', 'quick text', '1700000001']],
		['groupAcceptInviteV4', [msgKey, g, 'CODE', 1700000000]], ['communityAcceptInviteV4', [{ remoteJid: jidB, id: '', fromMe: false }, g, 'CODE', 1700000000]],
		['sendMessage', [nl, 'text', 'to a newsletter']],
		['sendMessage', [jidB, 'text', 'plain text']], ['sendMessage', [jidB, 'edit', 'edited', ownKey]], ['sendMessage', [jidB, 'delete', '', ownKey]], ['sendMessage', [jidB, 'react', 'x', msgKey]], ['sendMessage', [jidB, 'pin', '', msgKey]], ['sendMessage', [jidB, 'location', '']], ['sendMessage', [jidB, 'poll', 'a poll']], ['sendMessage', [g, 'text', 'to the group']], ['sendMessage', [g, 'disappearing', '']]
	]
	let failed = 0
	for (const [name, args] of calls) {
		const err = await c.api(name, args)
		if (err) {
			failed++
			if (process.env.E2E_VERBOSE) console.log(`    ERR ${name} ${JSON.stringify(args)}: ${err}`)
		}
	}
	console.log(`    ${calls.length} calls, ${failed} ended with an error from the empty mock reply`)
}
async function flow(kinds, server, out) {
	const pnA = '15550000001'
	const pnB = '15550000002'
	const jidA = `${pnA}@s.whatsapp.net`
	const jidB = `${pnB}@s.whatsapp.net`
	const a = make(kinds[0], `${out}-A`)
	const b = make(kinds[1], `${out}-B`)
	const a2 = make(kinds[1], `${out}-A2`)
	try {
		console.log(`  pairing ${kinds[0]} as A, ${kinds[1]} as B`)
		await pair(server, a, pnA, 'A', { keepalive: 1000 })
		await pair(server, b, pnB, 'B')
		// on a busy disk the upload can pass its 30 s limit, and it then finishes after the connection opens
		const uploaded = async pn => {
			for (let i = 0; i < 1200 && !server.accounts.get(pn).devices.get(1).preKeys.length; i++) await sleep(50)
			return server.accounts.get(pn).devices.get(1).preKeys.length > 0
		}
		check(await uploaded(pnA), 'A uploaded pre-keys')
		check(await uploaded(pnB), 'B uploaded pre-keys')

		console.log('  usync and status')
		check((await a.onWhatsApp(jidB)) === true, 'onWhatsApp finds B')
		check((await a.onWhatsApp('15559999999@s.whatsapp.net')) === false, 'onWhatsApp does not find an unknown number')
		check((await b.fetchStatus(jidA)) === 'hello from the mock', 'fetchStatus')

		console.log('  direct messages, both ways')
		const id1 = await a.send(jidB, 'hello from A')
		const m1 = await textWait(b, 'hello from A')
		check(m1.fromMe === false && m1.type === 'notify', 'B gets a notify message, not from itself')
		check(m1.jid.startsWith(pnB) === false, 'B sees the chat of A')
		await ackedReceipt(server, 'A:login', id1)
		await b.send(jidA, 'hello back from B')
		await textWait(a, 'hello back from B')
		await a.send(jidB, 'second from A')
		await textWait(b, 'second from A')
		await b.send(jidA, 'second from B')
		await textWait(a, 'second from B')

		console.log('  group with sender keys, phone number addressing')
		const g1 = await a.createGroup('Mock group', [jidB])
		await b.wait(e => e.ev === 'group_upsert' && e.id === g1, 'group upsert on B')
		const gid1 = await a.send(g1, 'group hello from A')
		const gm1 = await textWait(b, 'group hello from A', e => e.jid === g1)
		check(gm1.participant?.startsWith(pnA), `B sees A as the sender in the group, got ${gm1.participant}`)
		// the event can merge into the buffered upsert of the own message, as upstream does, so this reads the ack
		await ackedReceipt(server, 'A:login', gid1)
		await b.send(g1, 'group hello from B')
		await textWait(a, 'group hello from B', e => e.jid === g1)
		await a.send(g1, 'second group from A')
		await textWait(b, 'second group from A', e => e.jid === g1)

		console.log('  group with sender keys, LID addressing')
		server.groupAddressing = 'lid'
		const g2 = await a.createGroup('Mock LID group', [jidB])
		await b.wait(e => e.ev === 'group_upsert' && e.id === g2, 'LID group upsert on B')
		await a.send(g2, 'lid group from A')
		await textWait(b, 'lid group from A', e => e.jid === g2)
		await b.send(g2, 'lid group from B')
		await textWait(a, 'lid group from B', e => e.jid === g2)
		server.groupAddressing = 'pn'

		console.log('  second device of A: own-device fanout and app state both ways')
		const device2 = await pair(server, a2, pnA, 'A2')
		check(device2 === 2, `A2 is device 2, got ${device2}`)
		await sleep(200)
		await a.send(jidB, 'fanout from A')
		await textWait(b, 'fanout from A')
		const own = await textWait(a2, 'fanout from A')
		check(own.fromMe === true, 'A2 sees the message of A as its own')
		await b.send(jidA, 'to both devices of A')
		await textWait(a, 'to both devices of A')
		await textWait(a2, 'to both devices of A')

		const appKeyId = Buffer.from('mock-key-id').toString('base64')
		const appKey = Buffer.alloc(32, 7).toString('base64')
		await a.setAppKey(appKeyId, appKey)
		await a2.setAppKey(appKeyId, appKey)
		const until = 1893456000000
		await a.mute(jidB, until)
		const muted = await a2.wait(e => e.ev === 'chat_mute' && e.id === jidB, 'app state patch from A on A2')
		check(muted.mute === until, `A2 reads the patch of A: ${muted.mute}`)
		await a2.mute(jidB, until + 1000)
		const muted2 = await a.wait(e => e.ev === 'chat_mute' && e.id === jidB && e.mute === until + 1000, 'app state patch from A2 on A')
		check(muted2.mute === until + 1000, 'A reads the patch of A2')

		console.log('  offline delivery and reconnect with stored creds')
		await b.end()
		await b.wait(e => e.ev === 'conn' && e.state === 'close', 'B closed')
		b.forget()
		await sleep(50)
		await a.send(jidB, 'sent while B is offline')
		await sleep(100)
		server.labelNext('B:relogin')
		await b.start(server)
		await opened(b)
		const off = await textWait(b, 'sent while B is offline')
		check(off.type === 'append', `an offline message is an append, got ${off.type}`)
		await b.send(jidA, 'reply after reconnect')
		await textWait(a, 'reply after reconnect')

		console.log('  decrypt failure: retry receipt and resend')
		const lidA1 = `${server.accounts.get(pnA).lid}:1@lid`
		await b.dropSession(lidA1)
		await a.send(jidB, 'needs a retry')
		const retried = await textWait(b, 'needs a retry')
		check(retried.fromMe === false, 'B reads the resent message after its session was lost')
		const asked = (server.stanzaLog.get('B:relogin') || []).some(n => n.tag === 'receipt' && n.attrs.type === 'retry')
		check(asked, 'B sent a retry receipt')

		console.log('  keep-alive')
		await sleep(2500)
		const pings = (server.stanzaLog.get('A:login') || []).filter(n => n.attrs.xmlns === 'w:p').length
		check(pings >= 1, `A sends keep-alive pings, got ${pings}`)
		check(server.errors.length === 0, `server errors: ${server.errors.join('\n')}`)

		console.log('  every public method that sends a stanza')
		server.accounts.get(pnA).devices.get(1).conn.label = 'A:api'
		await apiCalls(a, { jidB, g: g1 })
		await sleep(200)
		check(server.errors.length === 0, `server errors after api calls: ${server.errors.join('\n')}`)

		console.log('  pairing code and logout')
		const c = make(kinds[0], `${out}-C`)
		try {
			server.labelNext('C:api')
			await c.start(server)
			await c.wait(e => e.ev === 'qr', 'QR on the client for the pairing code')
			await c.api('requestPairingCode', ['15550000003', 'ABCD1234'])
			await sleep(100)
		} finally {
			await c.quit().catch(() => {})
		}
		server.accounts.get(pnB).devices.get(1).conn.label = 'B:api'
		await b.api('logout', [])
		const closed = await b.wait(e => e.ev === 'conn' && e.state === 'close', 'B closed by logout')
		check(closed.code === 401, `logout closes with 401, got ${closed.code}`)
	} finally {
		for (const c of [a, b, a2]) await c.quit().catch(() => {})
	}
}
// masks what is random in a stanza, so that two runs can be compared
const MASK_ATTRS = new Set(['id', 't', 'sid', 'phash', 'key', 'hash', 'prev'])
// `reporting` is left out because upstream parses the padded bytes for it, so it comes and goes at random
const canon = (n, strict) => {
	const attrs = Object.keys(n.attrs || {})
		.sort()
		.map(k => `${k}=${MASK_ATTRS.has(k) ? '*' : n.attrs[k]}`)
		.join(' ')
	let body = ''
	if (Array.isArray(n.content)) body = n.content.filter(c => c.tag !== 'reporting').map(c => canon(c, strict)).join('')
	else if (n.content !== undefined && n.content !== null) {
		// a ciphertext has a random length, because of its padding
		const fixed = n.tag !== 'enc' && n.tag !== 'device-identity' && n.tag !== 'patch' && n.tag !== 'add'
		const shown = strict && n.content instanceof Uint8Array && /^[ -~]*$/.test(Buffer.from(n.content).toString('latin1')) ? Buffer.from(n.content).toString('latin1') : n.content.length
		body = n.content instanceof Uint8Array ? (fixed ? `BYTES(${shown})` : 'BYTES') : `TEXT(${n.content})`
	}
	return `<${n.tag}${attrs ? ' ' + attrs : ''}${body ? '>' + body + `</${n.tag}>` : '/>'}`
}
function compare(rust, baileys) {
	const diffs = []
	for (const label of new Set([...rust.keys(), ...baileys.keys()])) {
		const count = list => {
			const m = new Map()
			for (const n of list ?? []) {
				let c = canon(n, label.endsWith(':api'))
				// counts of pre-keys and keep-alives depend on timing
				if (n.attrs?.xmlns === 'w:p') c = '<iq keep-alive>'
				// how many patches of A a resync of A2 finds depends on timing
				if (label === 'A2:login' && n.attrs?.xmlns === 'w:sync:app:state') c = c.replace(/version=\d+/g, 'version=*')
				if (n.attrs?.xmlns === 'encrypt' && n.attrs.type === 'set') c = c.replace(/(<key><id>BYTES<\/id>|<key>.*?<\/key>)+/g, '<key...>')
				m.set(c, (m.get(c) || 0) + 1)
			}
			return m
		}
		const r = count(rust.get(label))
		const b = count(baileys.get(label))
		const timing = k => k === '<iq keep-alive>' || (label === 'A2:login' && k.includes('version=*'))
		for (const [k, v] of r) if (b.get(k) !== v && !timing(k)) diffs.push(`${label}: rust x${v}, baileys x${b.get(k) || 0}: ${k}`)
		for (const [k, v] of b) if (!r.has(k) && !timing(k)) diffs.push(`${label}: rust x0, baileys x${v}: ${k}`)
	}
	return diffs
}
/** The same telemetry events must encode to the same bytes. */
async function wamCheck() {
	const { encodeWAM, BinaryInfo } = await import(join(upstream, 'lib/WAM/index.js'))
	const info = new BinaryInfo({ sequence: 7 })
	info.events = [
		{ WamDroppedEvent: { props: { droppedEventCode: 300, droppedEventCount: 70000, isFromWamsys: true }, globals: { abKey2: 'ab-key' } } },
		{ WamDroppedEvent: { props: { droppedEventCode: 1.5, droppedEventCount: 5e10 }, globals: {} } }
	]
	const want = encodeWAM(info).toString('base64')
	const c = new Client('rust', 'wam')
	const got = (await c.cmd('wam')).wam
	await c.quit()
	console.log(`WAM encode: ${got === want ? 'same bytes as Baileys' : `DIFFERENT\n  rust ${got}\n  node ${want}`}`)
	return got === want
}
/** A client must refuse a server whose certificate does not chain to its root key. */
async function rootKeyCheck() {
	const server = await new MockServer().listen()
	const c = new Client('rust', 'badroot')
	try {
		await c.cmd('start', { url: server.url, root: 'ab'.repeat(32), dir: c.dir })
		const closed = await c.wait(e => e.ev === 'conn' && e.state === 'close', 'close on a bad root key')
		console.log(`root key check: closed with ${closed.code}: ${closed.error}`)
		return closed.code === 400 && /certificate/.test(closed.error)
	} finally {
		await c.quit()
		await server.close()
	}
}
/** The thread count of the Rust client before a connection, and after `end`. */
async function threadCheck() {
	const server = await new MockServer().listen()
	const c = new Client('rust', 'threads')
	try {
		const before = await c.threads()
		await pair(server, c, '15550000009', 'T', { keepalive: 1000 })
		const during = await c.threads()
		await c.end()
		await sleep(100)
		const after1 = await c.threads()
		c.forget()
		for (let i = 0; i < 5; i++) {
			await c.start(server)
			await opened(c)
			await c.wait(e => e.ev === 'pending', 'pending')
			await c.end()
			await c.wait(e => e.ev === 'conn' && e.state === 'close', 'closed')
			c.forget()
		}
		await sleep(100)
		const after5 = await c.threads()
		console.log(`threads: start ${before}, connected ${during}, after end ${after1}, after 5 more connect/end cycles ${after5}`)
		console.log('the one extra thread after the first run is the shared timer thread of utils::time, started once for the process')
		return after5 === after1 && after1 <= before + 1
	} finally {
		await c.quit()
		await server.close()
	}
}
/** Many messages at once in both directions and in a group, to find deadlocks and lost messages. */
async function burst(kinds, count) {
	const server = await new MockServer().listen()
	const tag = `burst-${kinds.join('-')}`
	const [a, b] = [make(kinds[0], `${tag}-A`), make(kinds[1], `${tag}-B`)]
	const jidA = '15550000001@s.whatsapp.net'
	const jidB = '15550000002@s.whatsapp.net'
	try {
		await pair(server, a, '15550000001', 'A')
		await pair(server, b, '15550000002', 'B')
		const g = await a.createGroup('burst', [jidB])
		// Sessions come first: two clients that both start a session at once lose messages in real
		// Baileys too, and need the retry flow. That race is not what this check is for.
		for (const [c, jid, other] of [[a, jidB, b], [b, jidA, a], [a, g, b], [b, g, a]]) {
			const hello = `hello-${jid}-${c.label}`
			await c.send(jid, hello)
			await textWait(other, hello)
		}
		const t0 = Date.now()
		const texts = n => Array.from({ length: count }, (_, i) => `${n}-${i}`)
		const sends = [...texts('ab').map(t => a.send(jidB, t)), ...texts('ba').map(t => b.send(jidA, t)), ...texts('ag').map(t => a.send(g, t)), ...texts('bg').map(t => b.send(g, t))]
		await Promise.all(sends)
		const recv = (c, list) => list.map(t => textWait(c, t, e => !e.fromMe))
		const results = await Promise.allSettled([...recv(b, texts('ab')), ...recv(a, texts('ba')), ...recv(b, texts('ag')), ...recv(a, texts('bg'))])
		const lost = results.filter(r => r.status === 'rejected')
		if (lost.length) throw new Error(`${lost.length} of ${results.length} messages not read. First: ${lost[0].reason.message}`)
		const failedDecrypts = [a, b].flatMap(c => c.events.filter(e => e.stub === 'CIPHERTEXT').map(e => e.stubParams?.[0]))
		const retries = ['A:login', 'B:login'].flatMap(l => server.stanzaLog.get(l) || []).filter(n => n.tag === 'receipt' && n.attrs.type === 'retry').length
		console.log(`burst ${kinds.join('-')}: ${count * 4} messages sent and read in ${Date.now() - t0} ms, ${server.errors.length} server errors, ${failedDecrypts.length} failed decrypts (${[...new Set(failedDecrypts)].join('; ')}), ${retries} retry receipts`)
		return server.errors.length === 0
	} finally {
		await a.quit().catch(() => {})
		await b.quit().catch(() => {})
		await server.close()
	}
}
/** The same flow with Rust clients and with Baileys clients. Each client has its own process. */
async function memoryRun() {
	const server1 = await new MockServer().listen()
	await flow(['rust', 'rust'], server1, 'mem-rust')
	await server1.close()
	const server2 = await new MockServer().listen()
	await flow(['baileys', 'baileys'], server2, 'mem-baileys')
	await server2.close()
	const row = r => `${r.kind.padEnd(8)} ${r.label.padEnd(16)} VmHWM ${String(r.VmHWM).padStart(7)} kB  RssAnon ${String(r.RssAnon).padStart(7)} kB  RssFile ${String(r.RssFile).padStart(7)} kB  threads now ${r.Threads}, peak ${r.peakThreads}`
	for (const r of memoryRecords) console.log(row(r))
	if (process.env.E2E_VERBOSE) for (const r of memoryRecords) console.log(`${r.label}: ${r.smaps}`)
	const peak = kind => Math.max(...memoryRecords.filter(r => r.kind === kind).map(r => r.VmHWM))
	const rust_kB = peak('rust')
	const node_kB = peak('baileys')
	console.log(`peak: rust ${rust_kB} kB, baileys ${node_kB} kB, ratio ${(node_kB / rust_kB).toFixed(1)}X`)
	mkdirSync(join(here, '../bench/results'), { recursive: true })
	writeFileSync(join(here, '../bench/results/e2e-memory.json'), JSON.stringify({ node_kB, rust_kB }) + '\n')
}
/** Bytes and files in a client's auth folder, which a permanent process keeps writing to. */
function diskUse(dir) {
	let kB = 0
	let files = 0
	for (const f of readdirSync(dir)) {
		kB += statSync(join(dir, f)).size / 1024
		files++
	}
	return { diskKb: Math.round(kB), files }
}
/** Two clients in one process pair: 40 messages each second or so, a large message now and then, and a reconnect every 5 minutes. */
async function soak(kind, minutes) {
	const server = await new MockServer().listen()
	const clients = [make(kind, `soak-${kind}-A`), make(kind, `soak-${kind}-B`)]
	const [a, b] = clients
	const jidA = '15550000001@s.whatsapp.net'
	const jidB = '15550000002@s.whatsapp.net'
	const file = join(here, `../bench/results/soak-${kind}.json`)
	const t0 = Date.now()
	const r = { kind, minutes, started: new Date(t0).toISOString(), done: false, error: null, messages: 0, reconnects: 0, samples: [] }
	const save = () => writeFileSync(file, JSON.stringify(r) + '\n')
	const one = c => {
		// the two fields after the name, which can hold spaces: utime and stime are 11 and 12 after `)`
		const f = readFileSync(`/proc/${c.proc.pid}/stat`, 'utf8').split(') ')[1].split(' ')
		return { ...procStatus(c.proc.pid), cpuS: (+f[11] + +f[12]) / 100, fds: readdirSync(`/proc/${c.proc.pid}/fd`).length, ...diskUse(c.dir) }
	}
	const sample = () => {
		r.samples.push({ s: Math.round((Date.now() - t0) / 1000), messages: r.messages, reconnects: r.reconnects, a: one(a), b: one(b) })
		save()
	}
	try {
		await pair(server, a, '15550000001', 'A')
		await pair(server, b, '15550000002', 'B')
		const g = await a.createGroup('soak', [jidB])
		for (const [c, jid, other] of [[a, jidB, b], [b, jidA, a], [a, g, b], [b, g, a]]) {
			const hello = `hello-${jid}-${c.label}`
			await c.send(jid, hello)
			await textWait(other, hello)
		}
		const end = t0 + minutes * 60000
		let round = 0
		let nextSample = 0
		let nextReconnect = Date.now() + 300000
		while (Date.now() < end) {
			round++
			const big = round % 50 === 0 ? 'x'.repeat(200000) : ''
			const texts = n => Array.from({ length: 10 }, (_, i) => `${n}-${round}-${i}${i === 0 ? big : ''}`)
			const plan = [[a, jidB, b, 'ab'], [b, jidA, a, 'ba'], [a, g, b, 'ag'], [b, g, a, 'bg']]
			await Promise.all(plan.flatMap(([c, jid, , n]) => texts(n).map(t => c.send(jid, t))))
			await Promise.all(plan.flatMap(([, , other, n]) => texts(n).map(t => textWait(other, t, e => !e.fromMe))))
			r.messages += 40
			await sleep(1000)
			// the mock and this runner keep logs for checks, and a long run does not need them
			a.forget()
			b.forget()
			server.stanzaLog.clear()
			server.messageSenders.clear()
			if (Date.now() >= nextReconnect) {
				const c = r.reconnects % 2 ? a : b
				await c.end()
				await c.wait(e => e.ev === 'conn' && e.state === 'close', 'closed')
				c.forget()
				await c.start(server)
				await opened(c)
				await c.wait(e => e.ev === 'pending', 'pending')
				c.forget()
				r.reconnects++
				nextReconnect = Date.now() + 300000
			}
			if (Date.now() >= nextSample) {
				sample()
				nextSample = Date.now() + 30000
			}
		}
		sample()
	} catch (e) {
		r.error = String(e.message).slice(0, 300)
	} finally {
		r.done = true
		r.endedS = Math.round((Date.now() - t0) / 1000)
		save()
		await a.quit().catch(() => {})
		await b.quit().catch(() => {})
		await server.close()
	}
	console.log(`soak ${kind}: ${r.messages} messages, ${r.reconnects} reconnects, ${r.error || 'no error'}`)
}
if (process.argv[2] === 'soak') {
	await soak(process.argv[3], +(process.argv[4] || 240))
	rmSync(baseTmp, { recursive: true, force: true })
	process.exit(0)
}
if (process.argv[2] === 'memory') {
	await memoryRun()
	rmSync(baseTmp, { recursive: true, force: true })
	process.exit(0)
}
if (process.argv[2] === 'burst') {
	const attempt = kinds => burst(kinds, +(process.argv[3] || 100)).catch(e => (console.log(`FAIL burst ${kinds.join('-')}: ${e.message.slice(0, 500)}`), false))
	const ok = await attempt(['rust', 'rust'])
	const ok2 = await attempt(['rust', 'baileys'])
	const ok3 = await attempt(['baileys', 'baileys'])
	console.log(`baseline with real Baileys on both sides: ${ok3 ? 'pass' : 'fail'}`)
	rmSync(baseTmp, { recursive: true, force: true })
	console.log(ok && ok2 ? 'BURST PASSED' : 'BURST FAILED')
	process.exit(ok && ok2 ? 0 : 1)
}
if (process.argv[2] === 'checks') {
	const ok = (await wamCheck()) & (await rootKeyCheck()) & (await threadCheck())
	rmSync(baseTmp, { recursive: true, force: true })
	console.log(ok ? 'CHECKS PASSED' : 'CHECKS FAILED')
	process.exit(ok ? 0 : 1)
}
const RUNS = { 'rust-rust': ['rust', 'rust'], 'baileys-baileys': ['baileys', 'baileys'], 'rust-baileys': ['rust', 'baileys'], 'baileys-rust': ['baileys', 'rust'] }
const wanted = process.argv.slice(2).filter(a => RUNS[a])
const names = wanted.length ? wanted : Object.keys(RUNS)
const logs = {}
let failed = 0
process.on('unhandledRejection', e => console.log('unhandled rejection in a client:', e?.message || e))
for (const name of names) {
	const server = await new MockServer({ log: m => console.log('   [server]', m) }).listen()
	console.log(`RUN ${name}`)
	const before = checks
	const t0 = Date.now()
	try {
		await flow(RUNS[name], server, name)
		console.log(`PASS ${name}: ${checks - before} checks, ${server.delivered} stanzas routed, ${Date.now() - t0} ms`)
	} catch (e) {
		failed++
		console.log(`FAIL ${name}: ${e.stack}`)
	}
	logs[name] = server.stanzaLog
	await server.close()
}
if (logs['rust-rust'] && logs['baileys-baileys']) {
	const diffs = compare(logs['rust-rust'], logs['baileys-baileys'])
	const total = [...logs['rust-rust'].values()].reduce((a, l) => a + l.length, 0)
	console.log(`\nSTANZA COMPARE rust-rust vs baileys-baileys: ${total} rust stanzas, ${diffs.length} differences`)
	for (const d of diffs) console.log('  ' + d.slice(0, 600))
}
rmSync(baseTmp, { recursive: true, force: true })
console.log(failed ? `\n${failed} run(s) FAILED` : '\nALL RUNS PASSED')
process.exit(failed ? 1 : 0)
