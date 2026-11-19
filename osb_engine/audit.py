"""Bounded snapshot scan with versioned persistent blob cache and explicit coverage."""
from dataclasses import asdict
import hashlib
from pathlib import Path
import subprocess
from . import analysis
from .store import identity
from .controls import evaluate


_BLOCKING = {
    'analysis_failed': 'Isolated analysis failed or ran out of budget; findings for this file are unknown.',
    'budget_blocked': 'Analysis byte budget exhausted before this file; findings are unknown.',
    'oversized': 'File exceeds the per-file analysis limit; findings are unknown.',
    'read_blocked': 'File could not be read from the pinned revision; findings are unknown.',
}


def _in_process(items):
    return {key: analysis.analyse(kind, data) for key, kind, data in items}


_SCHEMA_VERSION = 1


def scan(repo, store, catalogue, max_blob=2*1024*1024, max_total=32*1024*1024, analyser=None,
         cache_context=None, cache_limits=(100000, 256 * 1024 * 1024, 30)):
    """analyser(items) analyses cache misses; the CLI supplies an isolated one (S03-001)."""
    if not 0 < max_blob <= max_total <= 128*1024*1024:
        raise ValueError('invalid analysis byte budget')
    files, findings = [], []
    remaining = max_total
    hits = misses = 0
    from .sandboxed import _valid
    context = {'analyser_sha256': hashlib.sha256(Path(analysis.__file__).read_bytes()).hexdigest(),
               'schema': _SCHEMA_VERSION, **(cache_context or {'trust': 'in_process'})}
    store.evict(*cache_limits)
    store.cache_corrupt = 0
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
        cached = store.cached_v2(store.cache_key(blob.oid, kind, analysis.VERSION, context), _valid)
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
            store.cache_v2(store.cache_key(blob.oid, kind, analysis.VERSION, context), list(cached))
        row['status'], row['analysis'] = cached
        for index, f in enumerate(row['analysis']['findings']):
            finding = {**f, 'path': blob.path, 'blob': blob.oid}
            finding['id'] = identity([repo.revision,blob.path,blob.oid,f,index])
            findings.append(finding)
    counts = {}
    for row in files:
        counts[row['status']] = counts.get(row['status'], 0) + 1
        if row['language'] is not None and row['status'] in _BLOCKING:
            finding = {'rule': 'coverage.' + row['status'], 'line': 1, 'state': 'candidate',
                       'explanation': _BLOCKING[row['status']], 'path': row['path'], 'blob': row['oid']}
            finding['id'] = identity([repo.revision, row['path'], row['oid'], finding, 'coverage'])
            findings.append(finding)
    complete = not any(r['language'] is not None and r['status'] in _BLOCKING for r in files)
    report = {'schema': 2, 'analyser': analysis.VERSION, 'revision': repo.revision,
              'coverage': {'counts': dict(sorted(counts.items())), 'complete': complete},
              'files': files, 'findings': findings, 'dependencies': analysis.graph(files),
              'controls': evaluate(catalogue, files, findings), 'runtime_verification': 'not_performed',
              'semantic_review': 'not_performed', 'release_ready': False,
              'committed_scope_only': True, 'budget': {'max_blob':max_blob,'max_total':max_total,'remaining':remaining}}
    repo.assert_current()
    store.evict(*cache_limits)
    return report, {'cache_hits':hits,'cache_misses':misses,'cache_corrupt':store.cache_corrupt}
