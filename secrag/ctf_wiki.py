"""CTF Wiki source inventory (local) and lossless document preparation (remote).

Inventory only reads paths and navigation. prepare is intended for the SSH job,
never automatically invoked by the local application.
"""
import argparse
import hashlib
import json
import posixpath
import re
from collections import Counter
from pathlib import Path
from urllib.parse import quote, urlsplit

import yaml

SOURCE = 'ctf-wiki'
class ConfigLoader(yaml.SafeLoader):
    """Keep MkDocs Python plugin tags as inert strings; never import them."""

ConfigLoader.add_multi_constructor('tag:yaml.org,2002:python/name:', lambda loader, suffix, node: suffix)
EXCLUDED = {'index.md': 'site landing page', 'usage.md': 'site usage guide',
            'discussion.md': 'community discussion'}


def sha(text):
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


def write_json(path, value):
    Path(path).write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding='utf-8')


def navigation(config):
    routes = {}
    def walk(node, path):
        if isinstance(node, list):
            for child in node:
                walk(child, path)
        elif isinstance(node, dict):
            for key, value in node.items():
                walk(value, path + [str(key)])
        elif isinstance(node, str) and node.endswith('.md') and not urlsplit(node).scheme:
            relative = posixpath.normpath(node)
            if relative.startswith('../') or relative.startswith('/'):
                raise ValueError('导航路径越界')
            routes.setdefault(relative, []).append(path)
    walk(config.get('nav', []), [])
    return routes


def inventory(entries, config, lock):
    prefix = lock['docs_root'].rstrip('/') + '/'
    paths = {e['path'][len(prefix):]: e for e in entries
             if e.get('type') == 'blob' and e['path'].startswith(prefix) and e['path'].endswith('.md')}
    nav = navigation(config)
    rows = []
    for relative, entry in sorted(paths.items()):
        reason = EXCLUDED.get(relative) or ('contribution documentation' if relative.startswith('contribute/') else '')
        if not reason and entry.get('size') == 0:
            reason = 'upstream empty placeholder; no text to index'
        groups = nav.get(relative, [])
        categories = sorted({g[0].lower() for g in groups if g}) or [relative.split('/')[0].lower()]
        route = relative[:-3]
        if route == 'index':
            route = ''
        elif route.endswith('/index'):
            route = route[:-5]
        else:
            route += '/'
        rows.append({'path': relative, 'status': 'excluded' if reason else 'pending', 'reason': reason,
                     'categories': categories, 'navigation': groups, 'in_navigation': relative in nav,
                     'git_blob': entry.get('sha', ''), 'bytes': entry.get('size', 0),
                     'url': config.get('site_url', 'https://ctf-wiki.org/').rstrip('/') + '/' + quote(route, safe='/'),
                     'source_url': lock['repository'] + '/blob/' + lock['commit'] + '/' + prefix + quote(relative, safe='/')})
    missing = sorted(set(nav) - set(paths))
    return {'schema_version': 1, 'commit': lock['commit'], 'pages': rows,
            'missing_navigation': missing, 'categories': dict(Counter(c for r in rows if not r['reason'] for c in r['categories'])),
            'counts': dict(Counter(r['status'] for r in rows)), 'complete': False}


def load_inventory(directory):
    directory = Path(directory)
    tree = json.loads((directory / 'upstream-tree.json').read_text(encoding='utf-8'))
    if tree.get('truncated'):
        raise ValueError('上游文件清单不完整')
    lock = json.loads((directory / 'source-lock.json').read_text(encoding='utf-8'))
    if not re.fullmatch('[a-f0-9]{40}', lock['commit']):
        raise ValueError('必须固定40位 commit')
    config = yaml.load((directory / 'mkdocs.yml').read_text(encoding='utf-8'), Loader=ConfigLoader)
    return inventory(tree['tree'], config, lock), lock


def prepare(repository, metadata, output, sample=0):
    """Run on remote repository checked out at source-lock commit; preserve source verbatim."""
    import subprocess
    if sample < 0:
        raise ValueError('sample 必须非负')
    repository, output = Path(repository).resolve(), Path(output)
    report, lock = load_inventory(metadata)
    snapshot = repository / '.ctf-source.json'
    actual = (json.loads(snapshot.read_text(encoding='utf-8'))['commit'] if snapshot.is_file() else
              subprocess.check_output(['git', '-C', str(repository), 'rev-parse', 'HEAD'], text=True).strip())
    if actual != lock['commit']:
        raise ValueError('资料 checkout 与 source-lock 不一致')
    if report['missing_navigation']:
        raise ValueError('导航引用缺失页面，先修复范围清单')
    output.mkdir(parents=True, exist_ok=False)
    docs, errors, selected = [], [], [r for r in report['pages'] if not r['reason']]
    if sample:
        ordered = sorted(selected, key=lambda r: sha(r['path']))
        anchors = list({next(r['path'] for r in ordered if c in r['categories']):
                        next(r for r in ordered if c in r['categories']) for c in report['categories']}.values())
        anchor_paths = {r['path'] for r in anchors}
        selected = (anchors + [r for r in ordered if r['path'] not in anchor_paths])[:sample]
    for row in selected:
        path = (repository / lock['docs_root'] / row['path']).resolve()
        try:
            if not path.is_relative_to(repository):
                raise ValueError('源路径越界')
            raw = path.read_bytes()
            blob = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
            if row['git_blob'] and blob != row['git_blob']:
                raise ValueError('源文件与固定清单哈希不一致')
            text = raw.decode('utf-8-sig')
            if not text.strip():
                raise ValueError('空知识页面')
            # Template expressions are often CTF examples, not build directives.
            # Only unresolved includes outside fenced examples block preparation.
            from secrag.ctf_chunker import fence_after
            fence, unresolved = None, False
            for line in text.splitlines():
                if fence is None and re.match(r'^\s*(?:\{%\s*(?:include|extends|import)\b|--8<--|!INCLUDE\b)', line):
                    unresolved = True
                fence = fence_after(line, fence)
            if unresolved:
                raise ValueError('需要人工处理模板/include，禁止静默跳过')
            title = next((m.group(1).strip() for m in re.finditer(r'(?m)^#\s+(.+)$', text)), Path(row['path']).stem)
            images = re.findall(r'!\[([^\]]*)\]\(([^)]+)\)', text)
            assets = []
            for alt, target in images:
                target = target.split()[0].strip('<>')
                url = target if urlsplit(target).scheme else lock['repository'] + '/raw/' + lock['commit'] + '/' + quote(posixpath.normpath(lock['docs_root'] + '/' + posixpath.dirname(row['path']) + '/' + target), safe='/')
                asset = {'alt': alt, 'target': target, 'url': url}
                if not urlsplit(target).scheme and not target.startswith('/'):
                    local = (path.parent / target.split('#')[0]).resolve()
                    if local.is_relative_to(repository) and local.is_file():
                        from shutil import copyfile
                        data = local.read_bytes()
                        relative_asset = 'assets/' + hashlib.sha256(data).hexdigest() + local.suffix.lower()
                        destination = output / relative_asset
                        destination.parent.mkdir(exist_ok=True)
                        copyfile(local, destination)
                        asset['bundle_path'] = relative_asset
                    else:
                        asset['missing_local_asset'] = True
                assets.append(asset)
            doc = {'id': SOURCE + ':' + row['path'], 'source': SOURCE, 'title': title, 'lang': 'zh', 'text': text,
                   'categories': row['categories'], 'meta': {**{k: row[k] for k in ('url', 'source_url', 'path', 'navigation')},
                       'version': lock['commit'], 'license': lock['license'], 'content_sha256': sha(text),
                       'git_blob': blob, 'images': assets, 'image_content_indexed': False}}
            docs.append(doc)
            row['status'], row['content_sha256'] = 'prepared', sha(text)
        except (OSError, ValueError) as exc:
            row['status'] = 'failed'
            errors.append({'path': row['path'], 'error': str(exc)})
    report.update({'sample': bool(sample), 'errors': errors, 'prepared': len(docs), 'complete': not sample and not errors})
    if snapshot.is_file():
        report['source_archive'] = json.loads(snapshot.read_text(encoding='utf-8'))
    report['counts'] = dict(Counter(r['status'] for r in report['pages']))
    (output / 'docs.jsonl').write_text(''.join(json.dumps(d, ensure_ascii=False) + '\n' for d in docs), encoding='utf-8')
    write_json(output / 'coverage.json', report)
    write_json(output / 'source-lock.json', lock)
    (output / 'LICENSE').write_bytes((Path(metadata) / 'LICENSE').read_bytes())
    if errors:
        raise ValueError(f'{len(errors)} 篇资料处理失败，详见 coverage.json；禁止宣称全覆盖')
    return report


def main():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest='command', required=True)
    inv = sub.add_parser('inventory'); inv.add_argument('--metadata', default='data/ctf')
    prep = sub.add_parser('prepare'); prep.add_argument('--repository', required=True)
    prep.add_argument('--metadata', default='data/ctf'); prep.add_argument('--output', required=True)
    prep.add_argument('--sample', type=int, default=0)
    args = p.parse_args()
    if args.command == 'inventory':
        report, _ = load_inventory(args.metadata)
        write_json(Path(args.metadata) / 'inventory.json', report)
        print(json.dumps({k: report[k] for k in ('commit', 'counts', 'categories', 'missing_navigation')}, ensure_ascii=False))
    else:
        prepare(args.repository, args.metadata, args.output, args.sample)


if __name__ == '__main__':
    main()
