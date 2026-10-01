'use strict'

// Run Wappalyzer's signature engine against evidence already collected by
// PROWL. This process never opens a browser or makes a network request.
const fs = require('fs')
const path = require('path')

const root = process.env.PROWL_WAPPALYZER_ROOT
if (!root) throw new Error('Wappalyzer root is not configured')
const engine = require(path.join(root, 'src', 'wappalyzer.js'))
const technologyDir = path.join(root, 'src', 'technologies')
const technologies = {}
for (const file of fs.readdirSync(technologyDir).filter((name) => name.endsWith('.json'))) {
  Object.assign(technologies, JSON.parse(fs.readFileSync(path.join(technologyDir, file), 'utf8')))
}
engine.setTechnologies(technologies)
engine.setCategories(JSON.parse(fs.readFileSync(path.join(root, 'src', 'categories.json'), 'utf8')))

const input = JSON.parse(fs.readFileSync(0, 'utf8'))
const scriptSrc = Array.isArray(input.scriptSrc) ? input.scriptSrc.filter((value) => typeof value === 'string').slice(0, 100) : []
const detections = engine.analyze({ scriptSrc, url: String(input.url || '') })
const direct = new Set(detections.map(({ technology }) => technology.name))
const matches = engine.resolve(detections)
  .filter(({ name, confidence }) => direct.has(name) && confidence >= 80)
  .slice(0, 20)
  .map(({ name, confidence, version }) => ({ name, confidence, version }))
process.stdout.write(JSON.stringify(matches))
