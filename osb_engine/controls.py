"""Execute bounded static checks and retain every catalogue control without inventing passes."""
import csv
from pathlib import Path, PurePosixPath


def catalogue(path):
    with Path(path).open(encoding='utf-8', newline='') as stream:
        reader = csv.DictReader(stream, delimiter='\t')
        required = {'domain','activates_when','evidence','required_outcome'}
        if set(reader.fieldnames or []) != required:
            raise ValueError('invalid control catalogue')
        rows = list(reader)
    if not rows or len({r['domain'] for r in rows}) != len(rows) or any(not all(r.get(k) for k in required) for r in rows):
        raise ValueError('empty or duplicate controls')
    return rows


def evaluate(rows, files, findings):
    paths = [f['path'] for f in files]
    basenames = {PurePosixPath(p).name for p in paths}
    evidence = {
        'Build': ('manifest.missing_build','manifest.invalid'),
        'Quality': ('manifest.missing_test','manifest.missing_lint','python.parse_error'),
        'Security': ('python.unsafe_operation','python.shell_execution','python.disabled_verification'),
        'Reliability': ('python.swallowed_exception',),
        'Network': ('python.disabled_verification',),
        'Backend': ('python.placeholder_body',),
    }
    signals = {
        'Build': sorted(p for p in paths if PurePosixPath(p).name in ('package.json','pyproject.toml','Makefile','Cargo.toml')),
        'Quality': sorted(p for p in paths if PurePosixPath(p).name.startswith('test_') or p.startswith('tests/')),
        'SupplyChain': sorted(p for p in paths if PurePosixPath(p).name in ('package-lock.json','pnpm-lock.yaml','yarn.lock','uv.lock','Cargo.lock','requirements.txt')),
        'Infrastructure': sorted(p for p in paths if PurePosixPath(p).name in ('Dockerfile','compose.yaml','vercel.json') or p.endswith('.tf')),
        'Release': sorted(p for p in paths if p.startswith('.github/workflows/')),
        'Database': sorted(p for p in paths if p.endswith('.sql') or '/migrations/' in '/'+p),
        'Frontend': sorted(p for p in paths if p.endswith(('.tsx','.jsx','.vue','.svelte'))),
    }
    output = []
    for row in rows:
        domain = row['domain']
        refs = [f['id'] for f in findings if f['rule'] in evidence.get(domain, ())]
        relevant = signals.get(domain, [])
        ran = domain in evidence or domain in signals
        output.append({**row, 'status': 'unknown' if ran else 'not_performed',
                       'static_check': 'executed' if ran else 'not_supported',
                       'applicability': 'candidate' if refs or relevant else 'unknown',
                       'finding_ids': refs, 'path_signals': relevant,
                       'reason': 'Static indicators do not establish acceptance outcome.' if ran else 'No executable evaluator for this control yet.'})
    return output
