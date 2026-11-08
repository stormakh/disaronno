// Runs the Rust tests and scores them against the fixed ledger of upstream Jest tests.
import { execSync } from 'child_process'
import { readFileSync, existsSync } from 'fs'
const ledger = JSON.parse(readFileSync('tests-data/ledger.json', 'utf8'))
let raw = ''
try {
	raw = execSync('mise exec -- cargo test -p baileys --no-fail-fast 2>&1', { encoding: 'utf8', maxBuffer: 1 << 30 })
} catch (e) { raw = e.stdout + e.stderr }
const running = /Running (?:unittests )?tests\/([a-z0-9_]+)\.rs/
let cur = '', ok = new Set(), bad = new Set()
for (const l of raw.split('\n')) {
	const m = l.match(running)
	if (m) cur = m[1]
	const t = l.match(/^test (\S+) \.\.\. (ok|FAILED|ignored)/)
	if (!t) continue
	const k = cur + '::' + t[1].split('::').pop()
	if (t[2] === 'ok') ok.add(k); else bad.add(k)
}
const per = {}
let pass = 0
const missing = [], failed = []
for (const e of ledger) {
	const k = e.file + '::' + e.name
	per[e.suite] ??= { pass: 0, total: 0 }
	per[e.suite].total++
	if (ok.has(k)) { pass++; per[e.suite].pass++ } else if (bad.has(k)) failed.push(e.suite + ': ' + e.fullName); else missing.push(e.suite + ': ' + e.fullName)
}
for (const [s, v] of Object.entries(per)) console.log(`${v.pass === v.total ? 'PASS' : 'part'} ${String(v.pass).padStart(3)}/${String(v.total).padEnd(3)} ${s}`)
console.log(`\nSCORE ${pass}/${ledger.length} = ${(100 * pass / ledger.length).toFixed(1)}% (target 95% = ${Math.ceil(ledger.length * 0.95)})`)
if (failed.length) console.log('\nFAILED:\n' + failed.slice(0, 40).join('\n'))
if (missing.length && process.argv[2] === '-v') console.log('\nNOT PORTED:\n' + missing.join('\n'))
else if (missing.length) console.log(`\n${missing.length} not ported yet (use -v to list)`)
if (/^error(\[|:)/m.test(raw) && !ok.size) console.log(raw.slice(0, 3000))
