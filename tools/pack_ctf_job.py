"""Package only explicit public code/config inputs. Never include .env or chats."""
import hashlib
import json
import sys
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def pack(output):
    output = Path(output)
    if output.exists():
        raise ValueError('作业包已存在，请使用新文件名')
    files = list((ROOT / 'secrag').glob('*.py'))
    files += [ROOT / p for p in ('requirements.txt', 'requirements-web.txt', 'requirements-ctf.txt', 'requirements-ctf-build.txt',
                                'tools/run_ctf_remote.py', 'tools/fetch_ctf_model.py', 'data/ctf/source-lock.json', 'data/ctf/upstream-tree.json',
                                'data/ctf/mkdocs.yml', 'data/ctf/LICENSE', 'data/ctf/inventory.json',
                                'data/ctf/model-lock.json')]
    output.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(output, 'w:gz') as archive:
        for path in files:
            archive.add(path, arcname=path.relative_to(ROOT).as_posix(), recursive=False)
    checksum = hashlib.sha256(output.read_bytes()).hexdigest()
    output.with_suffix(output.suffix + '.sha256').write_text(checksum + '  ' + output.name + '\n', encoding='utf-8')
    print(json.dumps({'path': str(output), 'files': len(files), 'sha256': checksum}))


if __name__ == '__main__':
    pack(sys.argv[1] if len(sys.argv) > 1 else ROOT / 'artifacts/ctf-job.tar.gz')
