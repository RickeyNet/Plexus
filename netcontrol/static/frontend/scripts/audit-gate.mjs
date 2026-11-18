#!/usr/bin/env node
/**
 * npm audit gate with a narrow, expiring allowlist.
 *
 * Runs `npm audit --json` and fails on every advisory at or above the audit
 * level (default high), except one listed in audit-allowlist.json. An entry
 * excuses one advisory ID in one package, and only while all of these hold:
 *
 * - its `recheck_by` date has not passed;
 * - the newest published version of the package is still inside the
 *   advisory's vulnerable range (once a fix ships, upgrade instead);
 * - the advisory is still reported (a stale entry fails, so it gets removed).
 *
 * Usage: node scripts/audit-gate.mjs [--audit-level=high]
 */

import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export const SEVERITIES = ['info', 'low', 'moderate', 'high', 'critical'];

/** The advisories in an `npm audit --json` report at or above `level`, one per ID and package. */
export function findings(report, level = 'high') {
  const floor = SEVERITIES.indexOf(level);
  if (floor < 0) throw new Error(`unknown audit level: ${level}`);
  const seen = new Map();
  for (const vuln of Object.values(report.vulnerabilities ?? {})) {
    for (const via of vuln.via ?? []) {
      // A string `via` points at another vulnerable package, reported on its own.
      if (typeof via !== 'object' || SEVERITIES.indexOf(via.severity) < floor) continue;
      const id = advisoryId(via.url) ?? String(via.source);
      const key = `${id} ${via.name}`;
      if (!seen.has(key)) {
        seen.set(key, { id, package: via.name, severity: via.severity, title: via.title, range: via.range, url: via.url });
      }
    }
  }
  return [...seen.values()];
}

export function advisoryId(url) {
  const m = /GHSA(-[23456789cfghjmpqrvwx]{4}){3}/.exec(url ?? '');
  return m ? m[0] : null;
}

function parseVersion(v) {
  const m = /^v?(\d+)\.(\d+)\.(\d+)(-[0-9A-Za-z.-]+)?/.exec(String(v).trim());
  return m ? { nums: [Number(m[1]), Number(m[2]), Number(m[3])], pre: m[4] ?? '' } : null;
}

function compare(a, b) {
  for (let i = 0; i < 3; i += 1) if (a.nums[i] !== b.nums[i]) return a.nums[i] - b.nums[i];
  if (a.pre === b.pre) return 0;
  if (!a.pre) return 1;
  if (!b.pre) return -1;
  return a.pre < b.pre ? -1 : 1;
}

/**
 * Whether `version` is inside an advisory range such as `<=4.0.7`,
 * `>=7.0.0 <11.0.1`, `*` or `<1.2.3 || >=2.0.0 <2.0.5`. Returns null for a
 * range it cannot read, so the caller fails safe.
 */
export function inRange(version, range) {
  const v = parseVersion(version);
  if (!v) return null;
  let any = false;
  for (const alt of String(range).split('||')) {
    let all = true;
    for (const part of alt.trim().split(/\s+/)) {
      if (part === '*' || part === '') continue;
      const m = /^(<=|>=|<|>|=)?(.+)$/.exec(part);
      const bound = m && parseVersion(m[2]);
      if (!bound) return null;
      const c = compare(v, bound);
      const op = m[1] ?? '=';
      const ok = op === '<' ? c < 0 : op === '<=' ? c <= 0 : op === '>' ? c > 0 : op === '>=' ? c >= 0 : c === 0;
      if (!ok) all = false;
    }
    if (all) any = true;
  }
  return any;
}

/**
 * The gate's verdict. `latest(pkg)` gives the newest published version of a
 * package (or null when unknown); `today` is YYYY-MM-DD.
 */
export function evaluate(found, allowlist, { today, latest }) {
  const failures = [];
  const excused = [];
  for (const e of allowlist) {
    if (!e.id || !e.package || !e.reason || !/^\d{4}-\d{2}-\d{2}$/.test(e.recheck_by ?? '')) {
      failures.push(`allowlist entry ${JSON.stringify(e)} needs id, package, reason and recheck_by (YYYY-MM-DD)`);
    }
  }
  for (const f of found) {
    const label = `${f.severity} ${f.id} in ${f.package} (${f.title}) ${f.url ?? ''}`.trim();
    const entry = allowlist.find((e) => e.id === f.id && e.package === f.package);
    if (!entry) {
      failures.push(`${label}: not allowlisted`);
      continue;
    }
    if (entry.recheck_by < today) {
      failures.push(`${label}: allowlist exception expired on ${entry.recheck_by}; recheck it`);
      continue;
    }
    const newest = latest(f.package);
    const stillVulnerable = newest == null ? null : inRange(newest, f.range);
    if (stillVulnerable === false) {
      failures.push(`${label}: ${f.package}@${newest} is outside the vulnerable range ${f.range}; upgrade and drop the entry`);
      continue;
    }
    if (stillVulnerable === null) {
      failures.push(`${label}: cannot tell whether a fix exists (latest ${newest ?? 'unknown'}, range ${f.range})`);
      continue;
    }
    excused.push(`${label}: allowlisted until ${entry.recheck_by} (${entry.reason})`);
  }
  for (const e of allowlist) {
    if (e.id && !found.some((f) => f.id === e.id && f.package === e.package)) {
      failures.push(`allowlist entry ${e.id} (${e.package}) matches no reported advisory; remove it`);
    }
  }
  return { failures, excused };
}

function npm(args) {
  const opts = { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 };
  // Under `npm run`, npm_execpath is npm's own CLI script: run it with this node.
  const cli = process.env.npm_execpath;
  if (cli && /\.[cm]?js$/.test(cli)) return spawnSync(process.execPath, [cli, ...args], opts);
  if (process.platform !== 'win32') return spawnSync('npm', args, opts);
  // npm.cmd needs a shell on Windows; the arguments are fixed words and package names.
  return spawnSync(['npm', ...args].join(' '), { ...opts, shell: true });
}

function main() {
  const levelArg = process.argv.find((a) => a.startsWith('--audit-level='));
  const level = levelArg ? levelArg.split('=')[1] : 'high';
  const here = dirname(fileURLToPath(import.meta.url));
  const allowlist = JSON.parse(readFileSync(join(here, '..', 'audit-allowlist.json'), 'utf8')).advisories ?? [];

  // npm audit exits non-zero when it finds anything; the JSON is what counts.
  const run = npm(['audit', '--json']);
  let report;
  try {
    report = JSON.parse(run.stdout);
  } catch {
    console.error(`npm audit gave no JSON report:\n${run.stdout}\n${run.stderr}`);
    return 1;
  }
  if (report.error) {
    console.error(`npm audit failed: ${JSON.stringify(report.error)}`);
    return 1;
  }

  const latest = (pkg) => {
    const view = npm(['view', pkg, 'version', '--json']);
    try {
      return JSON.parse(view.stdout);
    } catch {
      return null;
    }
  };
  const today = new Date().toISOString().slice(0, 10);
  const { failures, excused } = evaluate(findings(report, level), allowlist, { today, latest });
  for (const line of excused) console.log(`excused: ${line}`);
  for (const line of failures) console.error(`FAIL: ${line}`);
  const counts = report.metadata?.vulnerabilities ?? {};
  console.log(`npm audit: ${JSON.stringify(counts)}; gate level ${level}: ${failures.length} failing, ${excused.length} excused`);
  return failures.length ? 1 : 0;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  process.exitCode = main();
}
