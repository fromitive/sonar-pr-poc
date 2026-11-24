#!/usr/bin/env python3
"""Single-module Gradle lockfile -> Sonar generic external issues (MQR)."""
import json, sys
from pathlib import Path


def convert(report, lock):
    lines = {}
    for n, line in enumerate(lock.splitlines(), 1):
        if line.startswith('#') or '=' not in line:
            continue
        coord = line.split('=', 1)[0]
        if coord.count(':') == 2:
            lines[coord] = n
    if not lines:
        raise ValueError('Expected nonempty Gradle lockfile for this PoC')
    results = [r for r in report.get('Results', []) if r.get('Type') == 'gradle' and Path(r.get('Target', '')).name == 'gradle.lockfile']
    if not results:
        raise ValueError('Trivy did not report a Gradle lockfile target')
    rules, issues, seen = {}, [], set()
    levels = {'CRITICAL':'BLOCKER', 'HIGH':'HIGH', 'MEDIUM':'MEDIUM', 'LOW':'LOW', 'UNKNOWN':'HIGH'}
    packages = {f"{p['Name']}:{p['Version']}" for r in results for p in r.get('Packages', []) if 'Name' in p and 'Version' in p}
    if not packages:
        raise ValueError('No Gradle packages reported; use --list-all-pkgs and verify scanner support')
    missing = set(lines) - packages
    if missing:
        raise ValueError(f'Lockfile packages not scanned: {sorted(missing)}')
    for r in results:
        for v in r.get('Vulnerabilities') or []:
            cve, pkg, ver = (v[k] for k in ('VulnerabilityID','PkgName','InstalledVersion'))
            coord = f'{pkg}:{ver}'
            if coord not in lines:
                raise ValueError(f'Cannot map finding to lockfile: {coord}')
            key = (cve, coord)
            if key in seen:
                continue
            seen.add(key)
            # Separate rule per advisory/package to avoid cross-package severity collisions.
            rid = f'{cve}:{pkg}'
            severity = levels.get(v.get('Severity'), 'HIGH')
            rank = ['LOW','MEDIUM','HIGH','BLOCKER']
            if rid in rules:
                old = rules[rid]['impacts'][0]['severity']
                severity = max((old,severity), key=rank.index)
            rules[rid] = {'id':rid,'engineId':'trivy-gradle','name':f'{cve} / {pkg}',
                'description':v.get('Title') or cve,'cleanCodeAttribute':'CONVENTIONAL',
                'impacts':[{'softwareQuality':'SECURITY','severity':severity}]}
            issues.append({'ruleId':rid,'primaryLocation':{'filePath':'gradle.lockfile',
                'message':f'{cve} | {coord} | Trivy {v.get("Severity","UNKNOWN")} | fixed: {v.get("FixedVersion") or "not reported"}',
                'textRange':{'startLine':lines[coord],'endLine':lines[coord]}}})
    return {'rules':list(rules.values()),'issues':issues}

if __name__ == '__main__':
    if len(sys.argv) != 4:
        sys.exit('Usage: trivy-to-sonar.py TRIVY_JSON LOCKFILE SONAR_JSON')
    src, lock, dest = map(Path, sys.argv[1:])
    result = convert(json.loads(src.read_text()), lock.read_text())
    dest.write_text(json.dumps(result, ensure_ascii=False, indent=2)+'\n')
    print(f'Imported candidates: {len(result["issues"])}')
