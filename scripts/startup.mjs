// Times 20 process runs of each bench program in `idle` mode, from process start to exit, and saves the medians.
// `idle` loads the library and stops. The `startup` mode of the Node bench also builds the fixtures, so it does not measure load time.
import { spawnSync } from 'child_process'
import { writeFileSync } from 'fs'
import { dirname, join } from 'path'
import { fileURLToPath } from 'url'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const median = a => a.slice().sort((x, y) => x - y)[a.length >> 1]
const time = (cmd, args) => {
	const samples = []
	for (let i = 0; i < 20; i++) {
		const t = process.hrtime.bigint()
		const r = spawnSync(cmd, args, { cwd: root, stdio: 'ignore' })
		if (r.status !== 0) throw new Error(`${cmd} failed: ${r.status ?? r.error}`)
		samples.push(Number(process.hrtime.bigint() - t) / 1e6)
	}
	return +median(samples).toFixed(1)
}
const out = {
	node_ms: time(process.execPath, ['bench/node/bench.mjs', 'idle']),
	rust_ms: time(join(root, 'target/release/baileys-bench'), ['idle'])
}
writeFileSync(join(root, 'bench/results/startup.json'), JSON.stringify(out) + '\n')
console.log(JSON.stringify(out))
