#!/usr/bin/env python3
"""Read-only Docker build-context and secret-named build-variable review."""
from __future__ import annotations

import argparse
import fnmatch
import json
import re
import shlex
import sys
from pathlib import Path

MAX_DOCKERFILE_BYTES=256*1024
MAX_IGNORE_BYTES=128*1024
MAX_CONTEXT_ITEMS=12000
SEVERITY={'low':1,'medium':2,'high':3,'critical':4}
SENSITIVE_KEYS=re.compile(r'(TOKEN|PASSWORD|PASSWD|SECRET|API[_-]?KEY|PRIVATE[_-]?KEY|CREDENTIAL|AUTH[_-]?KEY)',re.I)
SENSITIVE_FILE=re.compile(r'(^|/)(?:\.env(?:\.[^/]+)?|id_rsa|id_ed25519|credentials(?:\.[a-z0-9]+)?|[^/]+\.(?:pem|p12|pfx|key)|[^/]*secret[^/]*\.json)$',re.I)
SAFE_SAMPLES={'.env.example','.env.sample','.env.template','.env.defaults'}


class InputError(Exception): pass


def ignore_patterns(text):
    """Read Docker's ordered ignore/negation subset; no file contents are read."""
    entries=[]
    for raw in text.splitlines():
        line=raw.strip()
        if not line or line.startswith('#') or line=='.': continue
        neg=line.startswith('!')
        if neg: line=line[1:]
        line=line.strip().strip('/')
        if line: entries.append((line,neg))
    return entries


def match_pattern(path,pattern):
    path=path.strip('/')
    pattern=pattern.strip('/')
    if not path or not pattern: return False
    patterns=[pattern]
    if pattern.startswith('**/'):
        patterns.append(pattern[3:])
    for pat in patterns:
        if '/' not in pat:
            if any(fnmatch.fnmatchcase(seg,pat) for seg in path.split('/')):
                return True
        elif fnmatch.fnmatchcase(path,pat) or path.startswith(pat.rstrip('/')+'/'):
            return True
    return False


def is_included(path, patterns):
    ignored=False
    for pattern,neg in patterns:
        if match_pattern(path,pattern):
            ignored=not neg
    return not ignored


def dockerfile_instructions(text):
    acc='';lineno=0
    for i,line in enumerate(text.splitlines(),1):
        trimmed=line.strip()
        if not trimmed or trimmed.startswith('#'):
            continue
        if not acc:
            lineno=i
        if trimmed.endswith('\\'):
            acc += trimmed[:-1]+' '
            continue
        acc += trimmed
        m=re.match(r'^([A-Za-z]+)\s+(.+)$',acc,flags=re.S)
        if m:
            yield m.group(1).upper(), m.group(2),lineno
        acc=''
    if acc:
        raise InputError('Unterminated Dockerfile line continuation')


def parse_copy_source(body):
    """Best-effort context COPY/ADD detection, not a Dockerfile grammar validator."""
    if body.lstrip().startswith('['):
        try: rest=json.loads(body)
        except json.JSONDecodeError: return False,False
        return len(rest)>1, any(s in ('.','./','*','./*') for s in rest[:-1])
    try: tokens=shlex.split(body)
    except ValueError: return (False,False)
    if any(tok.startswith('--from=') or tok=='--from' for tok in tokens):
        return False,False
    rest=[t for t in tokens if not t.startswith('--')]
    if len(rest)==1 and rest[0].startswith('['):
        try: rest=json.loads(rest[0])
        except json.JSONDecodeError: return False,False
    if body.lstrip().startswith('['):
        try: rest=json.loads(body)
        except json.JSONDecodeError: return False,False
    sources=rest[:-1]
    return bool(sources),any(s in ('.','./','*','./*') for s in sources)


def sensitive_arg_env(body, instruction):
    try: tokens=shlex.split(body)
    except ValueError: return []
    if instruction=='ARG':
        return [tokens[0].split('=',1)[0]] if tokens else []
    if not tokens: return []
    if '=' in tokens[0]:
        return [x.split('=',1)[0] for x in tokens if '=' in x]
    return [tokens[0]] # ENV NAME value legacy form


def audit_context(context: Path, dockerfile: Path):
    if context.is_symlink() or dockerfile.is_symlink(): raise InputError('Symlink inputs are forbidden')
    if not context.is_dir() or not dockerfile.is_file(): raise InputError('Expected a context directory and a Dockerfile')
    if context.resolve() not in dockerfile.resolve().parents and context.resolve()!=dockerfile.parent.resolve():
        raise InputError('Dockerfile must be inside the context')
    if dockerfile.stat().st_size>MAX_DOCKERFILE_BYTES: raise InputError('Dockerfile too large')
    try: source=dockerfile.read_text(encoding='utf-8')
    except (OSError,UnicodeError) as e: raise InputError(f'Cannot read Dockerfile: {type(e).__name__}') from e
    explicit_ignore=dockerfile.with_name(dockerfile.name+'.dockerignore')
    default_ignore=context/'.dockerignore'
    ignore=explicit_ignore if explicit_ignore.exists() else default_ignore
    if ignore.is_symlink(): raise InputError('Ignore file is a symlink')
    patterns=[]
    if ignore.exists():
        if not ignore.is_file() or ignore.stat().st_size>MAX_IGNORE_BYTES: raise InputError('Invalid/oversized ignore file')
        try: patterns=ignore_patterns(ignore.read_text(encoding='utf-8'))
        except (OSError,UnicodeError) as e: raise InputError(f'Cannot read .dockerignore: {type(e).__name__}') from e
    rel=dockerfile.relative_to(context).as_posix()
    findings=[]
    def emit(rule,severity,path,line,message,recommendation):
        findings.append({'rule':rule,'severity':severity,'path':path,'line':line,'message':message,'recommendation':recommendation})
    copy_all=False
    for ins,body,line in dockerfile_instructions(source):
        if ins in ('ARG','ENV'):
            for key in sensitive_arg_env(body,ins):
                if SENSITIVE_KEYS.search(key):
                    emit('DC001','high',rel,line,f'Secret-like {ins} variable name: {key}',
                         'Use BuildKit secret mounts; never pass secrets through ARG/ENV.')
        if ins in ('COPY','ADD'):
            is_context,is_broad=parse_copy_source(body)
            if is_context and is_broad:
                copy_all=True
                emit('DC002','medium',rel,line,'Broad COPY/ADD may include unintended context files.',
                     'Minimize COPY paths and enforce a narrow .dockerignore.')
    if copy_all and not ignore.exists():
        emit('DC003','high',rel,1,'No .dockerignore found for a broad context COPY/ADD.',
             'Create .dockerignore and explicitly exclude sensitive/build metadata.')

    count=0
    for p in sorted(context.rglob('*')):
        if p.is_symlink():
            # Docker symlinks may affect real builds; report without resolving/reading.
            continue
        name=p.relative_to(context).as_posix()
        count+=1
        if count>MAX_CONTEXT_ITEMS: raise InputError('Too many context paths; limit 12000')
        if p.is_dir() and name=='.git' and copy_all and is_included(name,patterns):
            emit('DC004','medium','.dockerignore',1,'.git directory may enter the build context.',
                 'Exclude .git/ from the relevant .dockerignore or use a narrower context.')
        if not p.is_file(): continue
        if not SENSITIVE_FILE.search(name) or p.name in SAFE_SAMPLES: continue
        if not is_included(name,patterns): continue
        emit('DC005','high',name,1,'Sensitive-looking filename is included in Docker build context.',
             'Exclude it using an effective .dockerignore; do not assume it is safe to COPY.')
    return sorted(findings,key=lambda f:(f['path'],f['line'],f['rule']))


def scan(path: Path):
    if path.is_symlink():raise InputError('Symlink inputs are forbidden')
    if not path.exists():raise InputError('Input path does not exist')
    if path.is_file():return audit_context(path.parent,path)
    if not path.is_dir():raise InputError('Path must be a directory or Dockerfile')
    candidates=sorted(p for p in path.rglob('*') if p.is_file() and not p.is_symlink()
                      and (p.name=='Dockerfile' or p.name.endswith('.Dockerfile') or p.name.startswith('Dockerfile.')))
    if len(candidates)>12:raise InputError('Too many Dockerfiles (max 12); scan individually')
    return sorted([x for file in candidates for x in audit_context(path,file)],key=lambda f:(f['path'],f['line'],f['rule']))


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('path',help='Dockerfile path or directory containing Dockerfile(s)')
    parser.add_argument('--format',choices=('json','markdown'),default='markdown')
    parser.add_argument('--fail-on',choices=('none','low','medium','high','critical'),default='high')
    args=parser.parse_args(argv)
    try: findings=scan(Path(args.path))
    except InputError as e:
        print(f'ERROR: {e}',file=sys.stderr);return 1
    if args.format=='json':
        print(json.dumps({'findings':findings,'count':len(findings)},indent=2))
    else:
        print('# Docker context review\n\n| Severity | Rule | Location | Issue |\n|---|---|---|---|')
        for f in findings:
            print(f"| {f['severity'].upper()} | {f['rule']} | {f['path']}:{f['line']} | {f['message'].replace('|','/')} |")
        print(f'\n{len(findings)} finding(s), review manually; patterns are approximations.')
    return 2 if args.fail_on!='none' and any(SEVERITY[x['severity']]>=SEVERITY[args.fail_on] for x in findings) else 0

if __name__=='__main__':
    raise SystemExit(main())
