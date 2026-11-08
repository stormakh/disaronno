// Builds bench/report.html from measured results only. Usage: node scripts/report.mjs <rust-speed.txt> <rust-memory.json> [--preliminary "why"]
import { existsSync, readFileSync, writeFileSync } from 'fs'

const args = process.argv.slice(2)
const prelimAt = args.indexOf('--preliminary')
const prelim = prelimAt >= 0 ? args.splice(prelimAt, 2)[1] : null
const [speedFile, memFile] = args
const json = p => (existsSync(p) ? JSON.parse(readFileSync(p, 'utf8')) : null)

const node = json('bench/results/node-speed.json')
const rust = Object.fromEntries(readFileSync(speedFile, 'utf8').trim().split('\n').map(l => l.split(' ')).map(([k, v]) => [k, +v]))
const nodeMem = json('bench/results/node-memory.json')
const rustMem = JSON.parse(readFileSync(memFile, 'utf8'))
const nodeIdle = json('bench/results/node-idle.json')
const rustIdle = json('bench/results/rust-idle.json')
const startup = json('bench/results/startup.json')
const e2eMem = json('bench/results/e2e-memory.json')
const tests = json('bench/results/tests.json')
const nodeCompact = json('bench/results/node-compact.json')
const rustCompact = json('bench/results/rust-compact.json')
const tls = json('bench/results/tls-memory.json')
const liveRust = json('bench/results/live-rust.json')
const liveNode = json('bench/results/live-baileys.json')
const longRust = json('bench/results/live-long-rust.json')
const longNode = json('bench/results/live-long-baileys.json')
const longRustBefore = json('bench/results/live-long-rust-before.json')
const probes = [
	['No fix', json('bench/results/live-probe-rust-before.json')],
	['Fixed mmap threshold', json('bench/results/live-probe-rust-threshold.json')],
	['Fixed threshold and trim when a lane is idle', json('bench/results/live-probe-rust-trim.json')]
].filter(p => p[1])

// measured limits, from the byte and time accounting of each workload
const WHY = {
	curve_agree: '99.5% of the time is inside the aws-lc X25519 assembly, at 20 µs. 10X needs 17 µs.',
	lthash_64: 'Each item is 15 SHA-256 blocks. Eight-way AVX2 takes about 340 ns per block, and 10X needs 240 ns.',
	binary_decode: 'Each field is fully decoded. With an almost free allocator it still took 1,301 ns, and 10X needs 698 ns.',
	proto_decode: 'Each field is fully decoded. With an almost free allocator it still took 483 ns, and 10X needs 193 ns.',
	media_encrypt_1mb: 'One SHA-256 pass takes 2.1 ms per MiB and cannot be split. This CPU has no SHA-NI, so the limit is about 3.7X.',
	history_decode: 'Each field is fully decoded. With an almost free allocator it still took 1.2 ms, and 10X needs 411 µs.'
}

const LABELS = {
	receive_pipeline: ['Receive a message', 'Noise decrypt, node decode, Signal decrypt, protobuf decode'],
	signal_roundtrip: ['Signal encrypt and decrypt', 'One message, both directions of the ratchet'],
	group_roundtrip: ['Group encrypt and decrypt', 'Sender keys, with a signature'],
	appstate_roundtrip: ['App-state patch', 'Encode and decode one syncd patch'],
	binary_encode: ['Binary node encode', 'A message stanza of about 1.7 KB'],
	binary_decode: ['Binary node decode', 'The same stanza'],
	proto_encode: ['Protobuf encode', 'WebMessageInfo of about 1.3 KB'],
	proto_decode: ['Protobuf decode', 'The same message'],
	history_decode: ['History sync decode', '2,000 messages in 200 chats'],
	lthash_64: ['LT hash', '64 items'],
	curve_sign: ['Curve signature', 'XEdDSA sign'],
	curve_agree: ['Curve agreement', 'X25519'],
	media_encrypt_1mb: ['Media encrypt', '1 MiB, with hashes and a file write']
}
const rows = Object.keys(LABELS).filter(k => node[k] && rust[k]).map(k => ({ k, name: LABELS[k][0], what: LABELS[k][1], node: node[k], rust: rust[k], x: rust[k] / node[k] }))
rows.sort((a, b) => b.x - a.x)
const geo = Math.exp(rows.reduce((s, r) => s + Math.log(r.x), 0) / rows.length)
const met = rows.filter(r => r.x >= 10).length
const fmt = n => (n >= 1000 ? Math.round(n).toLocaleString('en-US') : n.toFixed(1))
const fx = x => (x >= 100 ? Math.round(x) : x >= 10 ? x.toFixed(0) : x.toFixed(1)) + 'X'
const mb = kb => (kb / 1024).toFixed(1) + ' MB'
const esc = s => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;')

// log scale from 1X (Node's speed) to the largest ratio
const maxX = Math.max(1000, ...rows.map(r => r.x))
const pos = x => (Math.log10(Math.max(x, 1)) / Math.log10(maxX)) * 100
const ticks = [1, 10, 100, 1000].filter(t => t <= maxX)

const speedRows = rows.map(r => `<div class="row" tabindex="0" data-tip="${esc(r.name)}: Rust ${fmt(r.rust)} ops/s, Node ${fmt(r.node)} ops/s, ${fx(r.x)}">
	<div class="lab"><span>${esc(r.name)}</span><small>${esc(r.what)}</small></div>
	<div class="track"><div class="bar ${r.x >= 10 ? 'ok' : 'under'}" style="width:max(${pos(r.x).toFixed(2)}%,4px)"></div></div>
	<div class="val">${fx(r.x)}</div>
</div>`).join('\n')

const memBars = (title, nodeKb, rustKb, note) => {
	const max = Math.max(nodeKb, rustKb)
	const hit = esc(title)
	return `<figure class="mem"><figcaption>${hit}<small>${esc(note)}</small></figcaption>
	<div class="m" data-tip="${hit}: Node ${mb(nodeKb)}"><span class="who">Node</span><div class="mt"><div class="b node" style="width:${(100 * nodeKb / max).toFixed(1)}%"></div></div><span class="mv">${mb(nodeKb)}</span></div>
	<div class="m" data-tip="${hit}: Rust ${mb(rustKb)}"><span class="who">Rust</span><div class="mt"><div class="b rust" style="width:max(${(100 * rustKb / max).toFixed(1)}%,4px)"></div></div><span class="mv">${mb(rustKb)}</span></div>
	<p class="mr">${(nodeKb / rustKb).toFixed(1)} times less memory</p></figure>`
}

const row = (name, n, r, unit, ratio = true) => `<tr><td>${esc(name)}</td><td>${n.toLocaleString('en-US')}${unit}</td><td>${r.toLocaleString('en-US')}${unit}</td><td>${ratio ? (n / r).toFixed(1) + 'X' : ''}</td></tr>`
const mbn = kb => +(kb / 1024).toFixed(1)

// one measure of the long run, against hours, for both clients. Each band holds the hover text of its 10 minutes.
const longChart = (title, note, value, unit, maxY, stepY, withBefore = false) => {
	const old = withBefore && longRustBefore
	const W = 920, H = 230, L = 44, R = 150, T = 10, B = 26
	const x = s => L + (s / 14400) * (W - L - R)
	const y = v => T + (1 - v / maxY) * (H - T - B)
	const line = (r, color) => `<polyline points="${r.timeline.map(p => `${x(p.s).toFixed(1)},${y(value(p)).toFixed(1)}`).join(' ')}" fill="none" stroke="var(--${color})" stroke-width="2" stroke-linejoin="round"/>`
	const end = (r, name) => {
		const v = value(r.timeline.at(-1))
		return `<text x="${W - R + 8}" y="${y(v) + 4}" font-size="13" fill="var(--ink)">${name} ${v.toFixed(unit === ' s' ? 2 : 1)}${unit}</text>`
	}
	const near = (r, s) => r.timeline.reduce((a, b) => (Math.abs(b.s - s) < Math.abs(a.s - s) ? b : a))
	const bands = Array.from({ length: 24 }, (_, i) => {
		const s = (i + 0.5) * 600
		const tip = `${(s / 3600).toFixed(1)} h: Baileys ${value(near(longNode, s)).toFixed(1)}${unit}, ${old ? `Rust before fixes ${value(near(old, s)).toFixed(1)}${unit}, ` : ''}Rust ${value(near(longRust, s)).toFixed(1)}${unit}`
		return `<rect x="${x(i * 600).toFixed(1)}" y="${T}" width="${(x(600) - x(0)).toFixed(1)}" height="${H - T - B}" data-tip="${tip}"/>`
	}).join('')
	const grid = []
	for (let v = 0; v <= maxY; v += stepY) grid.push(`<line x1="${L}" x2="${W - R}" y1="${y(v)}" y2="${y(v)}" stroke="var(--line)"/><text x="${L - 6}" y="${y(v) + 4}" text-anchor="end" font-size="12" fill="var(--ink2)">${v}</text>`)
	const hours = [0, 1, 2, 3, 4].map(h => `<text x="${x(h * 3600)}" y="${H - 8}" text-anchor="middle" font-size="12" fill="var(--ink2)">${h} h</text>`).join('')
	return `<figure class="long"><figcaption>${esc(title)}<small>${esc(note)}</small></figcaption><div class="tw"><svg viewBox="0 0 ${W} ${H}" role="img" aria-label="${esc(title)}">${grid.join('')}<g class="bands">${bands}</g><g pointer-events="none">${line(longNode, 'node')}${old ? line(old, 'under') : ''}${line(longRust, 'good')}</g>${end(longNode, 'Baileys')}${old ? end(old, 'Rust before') : ''}${end(longRust, 'Rust')}${hours}</svg></div></figure>`
}

const tile = (label, value, note) => `<div class="tile"><div class="tl">${esc(label)}</div><div class="tv">${esc(value)}</div><div class="tn">${esc(note)}</div></div>`
const passed = tests ? tests.passed : null
const total = tests ? tests.total : 407

const html = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Baileys Rust Comparison</title>
<style>
:root{color-scheme:light;--bg:#fcfcfb;--ink:#0b0b0b;--ink2:#52514e;--line:#e4e3de;--track:#f0efec;--good:#2a78d6;--under:#eb6834;--node:#8a897f}
@media (prefers-color-scheme:dark){:root:where(:not([data-theme="light"])){color-scheme:dark;--bg:#1a1a19;--ink:#f0efec;--ink2:#c3c2b7;--line:#3a3a37;--track:#2a2a28;--good:#3987e5;--under:#d95926;--node:#8f8e84}}
:root[data-theme="dark"]{color-scheme:dark;--bg:#1a1a19;--ink:#f0efec;--ink2:#c3c2b7;--line:#3a3a37;--track:#2a2a28;--good:#3987e5;--under:#d95926;--node:#8f8e84}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 system-ui,sans-serif}
main{max-width:980px;margin:0 auto;padding:32px 16px 64px}h1{font-size:28px;margin:0 0 4px}h2{font-size:19px;margin:40px 0 4px}p{margin:6px 0;color:var(--ink2)}
.warn{border:1px solid var(--under);border-radius:8px;padding:10px 14px;margin:16px 0;color:var(--ink)}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px;margin:20px 0}.tile{border:1px solid var(--line);border-radius:8px;padding:14px}.tl{font-size:13px;color:var(--ink2)}.tv{font-size:30px;font-weight:650;line-height:1.2;margin:2px 0}.tn{font-size:13px;color:var(--ink2)}
.legend{display:flex;gap:16px;flex-wrap:wrap;font-size:13px;color:var(--ink2);margin:10px 0}.legend i{display:inline-block;width:12px;height:12px;border-radius:3px;margin-right:6px;vertical-align:-1px}
.chart{position:relative;margin-top:8px}.row{display:grid;grid-template-columns:minmax(150px,240px) 1fr 58px;gap:12px;align-items:center;padding:7px 0;border-top:1px solid var(--line)}.row:focus,.row:hover{background:var(--track);outline:none}
.lab span{display:block;font-weight:550}.lab small{color:var(--ink2);font-size:12px;line-height:1.3;display:block}.track{height:14px;position:relative}.bar{height:14px;border-radius:0 4px 4px 0}.bar.ok{background:var(--good)}.bar.under{background:var(--under)}.val{text-align:right;font-weight:650;font-variant-numeric:tabular-nums}
.axis{display:grid;grid-template-columns:minmax(150px,240px) 1fr 58px;gap:12px;font-size:12px;color:var(--ink2)}.ticks{position:relative;height:18px}.ticks span{position:absolute;transform:translateX(-50%)}.ticks span:first-child{transform:none}
.mems{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:20px;margin-top:12px}.mem{margin:0;border:1px solid var(--line);border-radius:8px;padding:14px}.mem figcaption{font-weight:550;margin-bottom:8px}.mem small{display:block;font-weight:400;color:var(--ink2);font-size:12px}.m{display:grid;grid-template-columns:40px 1fr 72px;gap:8px;align-items:center;margin:6px 0;font-size:13px}.mt{height:14px}.b{height:14px;border-radius:0 4px 4px 0}.b.node{background:var(--node)}.b.rust{background:var(--good)}.mv{text-align:right;font-variant-numeric:tabular-nums}.mr{font-weight:550;color:var(--ink)}
.tw{overflow-x:auto}table{border-collapse:collapse;width:100%;font-size:14px;margin-top:12px;font-variant-numeric:tabular-nums}th,td{padding:7px 8px;text-align:right;border-bottom:1px solid var(--line);white-space:nowrap}th:first-child,td:first-child{text-align:left}th{color:var(--ink2);font-weight:550}
.why td{white-space:normal;text-align:left}.why td:nth-child(2){text-align:right;white-space:nowrap}.why th:last-child{text-align:left}ul{color:var(--ink2);padding-left:20px}li{margin:6px 0}li strong{color:var(--ink)}
.long{margin:16px 0 0}.long figcaption{font-weight:550}.long small{display:block;font-weight:400;color:var(--ink2);font-size:12px}.long svg{display:block;width:100%;min-width:560px;height:auto}.bands rect{fill:transparent}.bands rect:hover{fill:var(--track)}
#tip{position:fixed;pointer-events:none;background:var(--ink);color:var(--bg);padding:5px 9px;border-radius:6px;font-size:13px;display:none;max-width:320px;z-index:5}
@media (max-width:600px){.row,.axis{grid-template-columns:120px 1fr 48px;gap:8px}.lab small{display:none}}
</style></head><body><main>
<h1>Baileys: Node vs Rust</h1>
<p>The same 13 workloads, on the same machine: an Intel i7-8700 with 12 threads and no SHA-NI. Node runs the real Baileys build. The Node numbers were recorded before any Rust was written.</p>
${prelim ? `<div class="warn"><strong>Preliminary.</strong> ${esc(prelim)}</div>` : ''}
<div class="tiles">
${tile('Workloads at 10X or more', `${met} of ${rows.length}`, 'The rest are listed below')}
${tile('Typical speedup', fx(geo), 'Geometric mean of all workloads')}
${tile('Receive a message, end to end', fx(rows.find(r => r.k === 'receive_pipeline').x), 'The path a live client runs most')}
${tile('Memory, loaded client', `${(nodeMem.VmHWM_kB / rustMem.VmHWM_kB).toFixed(1)} times less`, `Decoded form, like for like: ${mb(nodeMem.VmHWM_kB)} vs ${mb(rustMem.VmHWM_kB)}`)}
${rustCompact ? tile('Memory, compact form', `${(nodeMem.VmHWM_kB / rustCompact.VmHWM_kB).toFixed(1)} times less`, 'Against decoded Node. Not like for like, see below') : ''}
${e2eMem ? tile('Memory, live client flow', `${(e2eMem.node_kB / e2eMem.rust_kB).toFixed(1)} times less`, `${mb(e2eMem.node_kB)} vs ${mb(e2eMem.rust_kB)}, on the mock server`) : ''}
${passed !== null ? tile('Upstream tests passing', `${passed} of ${total}`, (100 * passed / total).toFixed(2) + '%') : ''}
</div>
<h2>Speed: how many times faster than Node</h2>
<p>The scale is logarithmic. The left edge is Node's speed, and each labeled step on the axis is 10 times faster.</p>
<div class="legend"><span><i style="background:var(--good)"></i>10X or more</span><span><i style="background:var(--under)"></i>Under 10X</span></div>
<div class="chart">${speedRows}
<div class="axis"><span></span><div class="ticks">${ticks.map(t => `<span style="left:${pos(t).toFixed(1)}%">${t}X</span>`).join('')}</div><span></span></div></div>
<h2>Memory</h2><div class="mems">
${memBars('Loaded client, decoded form', nodeMem.VmHWM_kB, rustMem.VmHWM_kB, 'Like for like: 1,000 Signal sessions and 10,000 decoded messages. Peak of the process.')}
${rustCompact ? memBars('Loaded client, compact form against decoded Node', nodeMem.VmHWM_kB, rustCompact.VmHWM_kB, 'Not like for like. Rust holds checked encoded bytes and decodes again on each read. Node holds decoded objects.') : ''}
${rustCompact && nodeCompact ? memBars('Loaded client, compact form on both sides', nodeCompact.memory_compact.VmHWM_kB, rustCompact.VmHWM_kB, 'Like for like: both sides hold checked encoded bytes.') : ''}
${nodeIdle && rustIdle ? memBars('Empty process', nodeIdle.VmHWM_kB, rustIdle.VmHWM_kB, 'Library loaded, no work done.') : ''}
${e2eMem ? memBars('Live client flow on the mock server', e2eMem.node_kB, e2eMem.rust_kB, 'Same connect and message flow for both clients, each in its own process, over ws:// with no TLS.') : ''}
</div>
${startup ? `<h2>Startup</h2><p>Time for a process to start and load the library, median of 20 runs: Node ${startup.node_ms} ms, Rust ${startup.rust_ms} ms.</p>` : ''}
${longRust && longNode ? (() => {
	const after = r => r.timeline.filter(p => p.s > r.lastHistoryS + 60)
	const last = r => r.timeline.at(-1)
	const cpuAfter = r => +(last(r).cpuS - after(r)[0].cpuS).toFixed(2)
	const live = r => r.upsertMessages - after(r)[0].upserts
	const hourPoints = (r, h) => r.timeline.filter(p => p.s >= (h ? h * 3600 : 600) && p.s < (h + 1) * 3600)
	const mean = (ps, k) => ps.reduce((a, p) => a + p[k], 0) / ps.length / 1024
	const growth = r => mean(hourPoints(r, 3), 'anonKb') - mean(hourPoints(r, 0), 'anonKb')
	const old = longRustBefore
	const runs = [['Baileys', longNode], ...(old ? [['Rust before fixes', old]] : []), ['Rust', longRust]]
	const row3 = (name, f, unit, ratio = true) => {
		const v = runs.map(([, r]) => f(r))
		return `<tr><td>${esc(name)}</td>${v.map(x => `<td>${x.toLocaleString('en-US')}${unit}</td>`).join('')}<td>${ratio ? (v[0] / v.at(-1)).toFixed(1) + 'X' : ''}</td></tr>`
	}
	const hourRows = [0, 1, 2, 3].map(h => {
		const cells = r => {
			const ps = hourPoints(r, h)
			return `<td>${mean(ps, 'rssKb').toFixed(1)} MB</td><td>${mean(ps, 'anonKb').toFixed(1)} MB</td><td>${(ps.at(-1).cpuS - ps[0].cpuS).toFixed(2)} s</td>`
		}
		return `<tr><td>Hour ${h + 1}${h ? '' : ' (from 10 min)'}</td>${runs.map(([, r]) => cells(r)).join('')}</tr>`
	}).join('\n')
	const errors = r => Object.entries(r.logs).filter(([k]) => k.startsWith('50 ') && k !== '50 stream errored out').reduce((a, [, n]) => a + n, 0)
	const reconnects = runs.filter(([, r]) => r.connections > 1).map(([name, r]) => `${name} reconnected ${r.connections - 1} time${r.connections > 2 ? 's' : ''}, with close codes ${r.closeCodes.slice(1, -1).join(', ')}.`)
	const color = { Baileys: 'node', 'Rust before fixes': 'under', Rust: 'good' }
	return `<h2>Four hours on a real account: memory and CPU of each process</h2>
<p>Each client ran on the same personal account, over real TLS, for 4 hours after the first connection. Each did a full history sync in the first minutes. ${old ? 'Baileys and Rust before the memory fixes ran at the same time, with the same traffic. Rust with the fixes ran alone, a day later, so its live traffic was different.' : 'Both ran at the same time, with the same traffic.'} No client stored messages. A sample was taken every 30 seconds, and the peak was read every 100 ms. Memory means memory in RAM (RSS). Private memory leaves out the program files, which the system can load again.</p>
<div class="legend">${runs.map(([name]) => `<span><i style="background:var(--${color[name]})"></i>${name}</span>`).join('')}</div>
${longChart('Memory in RAM, MB', `Peaks fall between samples: ${runs.map(([name, r]) => `${name} ${mb(r.peakKb)}`).join(', ')}.`, p => p.rssKb / 1024, ' MB', 250, 50, true)}
${longChart('Private memory, MB', 'This is where a leak shows.', p => p.anonKb / 1024, ' MB', 200, 50, true)}
${longChart('CPU time used since start, seconds', 'A flat line means an idle process.', p => p.cpuS, ' s', 10, 2)}
<div class="tw"><table><thead><tr><th>Measure</th>${runs.map(([name]) => `<th>${name}</th>`).join('')}<th>Rust better by</th></tr></thead><tbody>
${row3('Peak memory', r => mbn(r.peakKb), ' MB')}
${row3('Memory after 4 hours', r => mbn(last(r).rssKb), ' MB')}
${row3('Private memory after 4 hours', r => mbn(last(r).anonKb), ' MB')}
${row3('Private memory growth, hour 1 to hour 4', r => +growth(r).toFixed(1) + 0, ' MB', false)}
${row3('CPU time, 4 hours', r => r.cpuS, ' s')}
${row3('CPU time, after the sync', cpuAfter, ' s')}
${row3('Threads, peak', r => r.peakThreads, '')}
${row3('Open files, at the end', r => last(r).fds, '')}
${row3('Reconnects', r => r.connections - 1, '', false)}
${row3('Login keys on disk, at the end', r => last(r).diskKb, ' kB', false)}
${row3('History messages', r => r.messages, '', false)}
${row3('Live messages after the sync', live, '', false)}
${row3('Error log lines, other than the restart', errors, '', false)}
</tbody></table></div>
<h3>Each hour, as a mean</h3>
<div class="tw"><table><thead><tr><th></th>${runs.map(([name]) => `<th>${name} memory</th><th>${name} private</th><th>${name} CPU</th>`).join('')}</tr></thead><tbody>
${hourRows}
</tbody></table></div>
<ul>
${reconnects.length ? `<li><strong>Reconnects:</strong> ${reconnects.join(' ')} Code 428 means that the server or the network closed the connection. The cause is unknown. Memory did not change at a reconnect.</li>` : ''}
${old ? `<li><strong>Memory after the sync:</strong> before the fixes, Rust kept about ${mbn(last(old).rssKb)} MB after the sync, with no messages stored. The next section shows why, and the fix.</li>` : ''}
<li><strong>Program code in RAM:</strong> in Rust with the fixes, the program code in RAM went from ${mbn(longRust.timeline.find(p => p.s > longRust.lastHistoryS + 60).rssKb - longRust.timeline.find(p => p.s > longRust.lastHistoryS + 60).anonKb)} MB to ${mbn(last(longRust).rssKb - last(longRust).anonKb)} MB in the second hour. The kernel removed code pages that were not used, and loads them again when they are needed. Other programs on the machine affect this. The private memory does not change with it, so it is the better measure of what the client keeps.</li>
</ul>`
})() : ''}
${probes.length ? (() => {
	const settled = r => r.mem.filter(m => m.step === 'now').at(-1)
	const rows = probes.map(([name, r]) => {
		const m = settled(r)
		const noSocket = r.mem.find(x => x.step === 'no socket')
		return `<tr><td>${esc(name)}</td><td>${mb(m.rssKb)}</td><td>${mb(m.anonKb)}</td><td>${mb(m.usedKb)}</td><td>${mb(m.freeKb)}</td><td>${mb(r.peakKb)}</td><td>${noSocket ? mb(noSocket.rssKb) : ''}</td></tr>`
	}).join('\n')
	return `<h2>Why Rust kept memory after the sync, and the fix</h2>
<p>Three short runs of Rust on the same account, each with a full history sync, measured 4 minutes after the sync. The allocator counts show that almost all of the memory was free memory that glibc kept, not data that the client held. There were no huge pages.</p>
<div class="tw"><table><thead><tr><th>Build</th><th>Memory</th><th>Private</th><th>Heap in use</th><th>Heap free, kept</th><th>Peak</th><th>No socket</th></tr></thead><tbody>
${rows}
</tbody></table></div>
<ul>
<li><strong>Fixed mmap threshold:</strong> glibc raises its mmap threshold each time a large block is freed. Then the large buffers of a sync come from a thread heap and stay in RAM. The socket now sets the threshold to the glibc default, so that the threshold stays fixed.</li>
<li><strong>Trim when a lane is idle:</strong> the blocks of a decoded history chunk are small. glibc gives back only the top of a heap, and a few long-lived blocks keep the rest. When a lane has had no work for 5 seconds, the socket calls <code>malloc_trim</code>, once after each burst of work.</li>
<li><strong>What is left, 4 minutes after the sync:</strong> about 6.5 MB of program code, which the kernel later removes in part (see the 4-hour run above), and a heap of about 7.5 MB that holds 1.7 MB of live blocks spread over its pages. A trim cannot give back a page that holds a live block. "No socket" is the memory after logout, with the socket dropped and a trim.</li>
<li><strong>Cost:</strong> on the mock live flow, the Rust peak went from about 4.7 MB to about 5.0 MB, because the code layout moved. Both settings apply to Linux with glibc only. Each sync is a little different, so the "No fix" row and the other rows did not get exactly the same data.</li>
</ul>`
})() : ''}
${liveRust && liveNode ? `<h2>Real account: Rust and Baileys on the same WhatsApp account</h2>
<p>Each client linked to one personal account in turn, over real TLS, and did a full history sync. Baileys ran second. Neither client stored the messages, and an app that stores them uses more memory. The amount of data is almost the same for both clients, but it is not identical.</p>
<div class="tw"><table><thead><tr><th>Measure</th><th>Baileys</th><th>Rust</th><th>Rust better by</th></tr></thead><tbody>
${row('History messages', liveNode.messages, liveRust.messages, '', false)}
${row('Chats', liveNode.chats, liveRust.chats, '', false)}
${row('Peak memory, whole run', mbn(liveNode.peakKb), mbn(liveRust.peakKb), ' MB')}
${row('Peak memory, when first connected', mbn(liveNode.peakAtOpenKb), mbn(liveRust.peakAtOpenKb), ' MB')}
${row('Memory at the end of the run', mbn(liveNode.lastRssKb), mbn(liveRust.lastRssKb), ' MB')}
${row('CPU time, whole run', liveNode.cpuS, liveRust.cpuS, ' s')}
${row('Threads, peak', liveNode.peakThreads, liveRust.peakThreads, '')}
</tbody></table></div>
<p>This is one run of each client. Wall-clock sync time is left out, because it depends mostly on the phone and the network.</p>` : ''}
<h2>Why some workloads are under 10X</h2>
<div class="tw"><table class="why"><thead><tr><th>Workload</th><th>Speedup</th><th>Limit</th></tr></thead><tbody>
${rows.filter(r => r.x < 10).map(r => `<tr><td>${esc(r.name)}</td><td>${fx(r.x)}</td><td>${esc(WHY[r.k] || 'No limit recorded.')}</td></tr>`).join('\n')}
</tbody></table></div>
<h2>What these numbers do not prove</h2>
<ul>
<li><strong>Real WhatsApp:</strong> ${liveRust ? 'one real account linked, did a full history sync, received live messages and logged out. No test sent a real message or transferred media through the socket. The other client flows ran against a local mock server.' : 'no test logged in to WhatsApp. One connection stopped at the QR step, with no account. The client flows ran against a local mock server with no phone. History sync and media did not run through the socket.'}</li>
${longRust ? `<li><strong>Long run:</strong> this is one 4-hour run, not weeks. About 150 live messages arrived after the sync, so a leak that grows slowly per message may not show. The clients stored no messages, sent none and transferred no media. An app does these things and uses more memory. The Baileys growth is not proof of a leak, because a later garbage collection can free it.</li>` : ''}
<li><strong>TLS:</strong> the live flow uses ws://, with no TLS.${tls ? ` One real connection to WhatsApp passed the real certificate check, reached the QR step, and peaked at ${mb(tls.rust_kB)}. A logged-in client over TLS will use more than the flow number.` : ''}</li>
<li><strong>Memory settings:</strong> the static build and function ordering apply to the binaries in this workspace, and the bench uses the system allocator. A program that depends on this crate must set these itself, or it uses more memory. With mimalloc, the compact form is 11.1X, under 12X.</li>
<li><strong>Host lookups:</strong> the static build reads only /etc/hosts and /etc/resolv.conf. It ignores other system lookup modules, such as mDNS.</li>
<li><strong>Compact form:</strong> each read costs one full decode. It is a separate type for held messages, not the normal message type.</li>
<li><strong>Compression:</strong> nothing here uses compression or shares data between messages.</li>
<li><strong>Different behavior:</strong> work that Baileys starts at the same time runs in order on two queues. Protobuf and binary node decode reject input with more than 64 nested levels, so that a peer cannot crash the process.</li>
<li><strong>Tests:</strong> ${passed !== null ? `${passed} of ${total} is a count of named tests. ` : ''}A second review found that a concurrent Noise test became sequential, a string-in-long-field test became a parsing test, and three upstream token tests check only their own setup. Upstream's 4 live end-to-end test files did not run and are not in this count.</li>
<li><strong>Not ported:</strong> proxy agents and <code>uploadWithFetch</code>. Image and audio work uses ffmpeg in place of sharp, jimp and music-metadata.</li>
</ul>
<h2>All numbers</h2>
<div class="tw"><table><thead><tr><th>Workload</th><th>Node ops/s</th><th>Rust ops/s</th><th>Speedup</th><th>10X?</th></tr></thead><tbody>
${rows.map(r => `<tr><td>${esc(r.name)}</td><td>${fmt(r.node)}</td><td>${fmt(r.rust)}</td><td>${fx(r.x)}</td><td>${r.x >= 10 ? 'Yes' : 'No'}</td></tr>`).join('\n')}
</tbody></table></div>
<div id="tip" role="status"></div>
</main><script>
const tip=document.getElementById('tip');
function show(e,t){tip.textContent=t;tip.style.display='block';const r=e.getBoundingClientRect?e.getBoundingClientRect():null;const x=(e.clientX!==undefined?e.clientX:r.left)+12,y=(e.clientY!==undefined?e.clientY:r.top)+12;tip.style.left=Math.min(x,innerWidth-tip.offsetWidth-8)+'px';tip.style.top=y+'px'}
document.querySelectorAll('[data-tip]').forEach(n=>{n.addEventListener('mousemove',e=>show(e,n.dataset.tip));n.addEventListener('mouseleave',()=>tip.style.display='none');n.addEventListener('focus',()=>show(n,n.dataset.tip));n.addEventListener('blur',()=>tip.style.display='none')});
</script></body></html>`
writeFileSync('bench/report.html', html)
console.log(`bench/report.html: ${met}/${rows.length} at 10X, geomean ${fx(geo)}`)
