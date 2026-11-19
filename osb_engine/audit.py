"""Bounded snapshot scan with versioned persistent blob cache and explicit coverage."""
from dataclasses import asdict
import subprocess
from . import analysis
from .store import identity
from .controls import evaluate


def _in_process(items):
    return {key: analysis.analyse(kind, data) for key, kind, data in items}


def scan(repo, store, catalogue, max_blob=2*1024*1024, max_total=32*1024*1024, analyser=None):
    """analyser(items) analyses cache misses; the CLI supplies an isolated one (S03-001)."""
    if not 0 < max_blob <= max_total <= 128*1024*1024:
        raise ValueError('invalid analysis byte budget')
    files, findings = [], []
    remaining = max_total
    hits = misses = 0
    pending, order = {}, []
    for blob in repo.inventory():
        kind = analysis.language(blob.path)
        row = {**asdict(blob), 'language': kind, 'status': 'unsupported_language'}
        files.append(row)
        if blob.kind != 'blob' or blob.mode not in ('100644','100755'):
            row['status'] = 'special_file'
            continue
        if kind is None:
            continue
        if blob.size > max_blob:
            row['status'] = 'oversized'
            continue
        # Budget emitted analysis too, not just newly parsed data.
        if blob.size > remaining:
            row['status'] = 'budget_blocked'
            continue
        remaining -= blob.size
        cached = store.cached(blob.oid, kind, analysis.VERSION)
        key = kind + ':' + blob.oid
        if cached is None:
            misses += 1
            try:
                pending.setdefault(key, (key, kind, repo.read(blob)))
            except (OSError, subprocess.SubprocessError):
                row['status'] = 'read_blocked'
                continue
        else:
            hits += 1
        order.append((row, blob, kind, key, cached))
    results = (analyser or _in_process)(list(pending.values()))
    for row, blob, kind, key, cached in order:
        if cached is None:
            cached = results.get(key)
            if cached is None:
                row['status'] = 'analysis_failed'
                continue
            store.cache(blob.oid, kind, analysis.VERSION, cached)
        row['status'], row['analysis'] = cached
        for index, f in enumerate(row['analysis']['findings']):
            finding = {**f, 'path': blob.path, 'blob': blob.oid}
            finding['id'] = identity([repo.revision,blob.path,blob.oid,f,index])
            findings.append(finding)
    report = {'schema': 2, 'analyser': analysis.VERSION, 'revision': repo.revision,
              'files': files, 'findings': findings, 'dependencies': analysis.graph(files),
              'controls': evaluate(catalogue, files, findings), 'runtime_verification': 'not_performed',
              'semantic_review': 'not_performed', 'release_ready': False,
              'committed_scope_only': True, 'budget': {'max_blob':max_blob,'max_total':max_total,'remaining':remaining}}
    repo.assert_current()
    return report, {'cache_hits':hits,'cache_misses':misses}
