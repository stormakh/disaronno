// Fixes the list of upstream tests from a real Jest run. Each one gets a stable Rust test name.
import { readFileSync, writeFileSync } from 'fs'
const [, , input, output] = process.argv
const r = JSON.parse(readFileSync(input, 'utf8'))
const slug = s => s.toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '').slice(0, 150)
const out = []
const seen = new Set()
for (const t of r.testResults) {
	const suite = t.name.replace(/.*__tests__\//, '').replace(/\.test\.ts$/, '')
	const file = suite.toLowerCase().replace(/[^a-z0-9]+/g, '_')
	for (const a of t.assertionResults) {
		if (a.status !== 'passed') throw new Error('baseline test did not pass: ' + a.fullName)
		let name = 't_' + slug(a.fullName)
		for (let i = 2; seen.has(file + '::' + name); i++) name = 't_' + slug(a.fullName) + '_' + i
		seen.add(file + '::' + name)
		out.push({ suite, file, name, fullName: a.fullName })
	}
}
out.sort((a, b) => (a.suite + a.name).localeCompare(b.suite + b.name))
writeFileSync(output, JSON.stringify(out, null, 1))
console.log(out.length, 'tests in', new Set(out.map(o => o.suite)).size, 'suites')
