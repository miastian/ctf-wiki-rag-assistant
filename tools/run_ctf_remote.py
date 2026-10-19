"""SSH-only job runner: fixed checkout, prepare, slice, encode. No LLM calls."""
import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stage', choices=['pilot', 'full'], required=True)
    parser.add_argument('--workdir', required=True)
    parser.add_argument('--batch-size', type=int, default=8)
    parser.add_argument('--snapshot', help='官方固定版本zip；网络受限时先上传原始快照')
    parser.add_argument('--snapshot-sha256', help='由下载端核对的原始快照SHA256')
    parser.add_argument('--model-path', help='已按模型锁文件核对的远程本地模型目录')
    args = parser.parse_args()
    if sys.platform == 'win32':
        parser.error('此命令仅在租用的 Linux 服务器运行，本地不要执行真实资料建库')
    if args.batch_size < 1:
        parser.error('batch-size 必须为正数')
    metadata = ROOT / 'data/ctf'
    lock = json.loads((metadata / 'source-lock.json').read_text())
    model = json.loads((metadata / 'model-lock.json').read_text())
    work = Path(args.workdir).resolve()
    work.mkdir(parents=True, exist_ok=True)
    if args.stage == 'full':
        from secrag.remote_build import digest
        pilots = []
        for manifest_path in work.glob('bundle-pilot-*/index_manifest.json'):
            manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
            if (manifest.get('source_commit') == lock['commit'] and manifest.get('model_revision') == model['revision']
                    and manifest.get('chunk_version') == 'ctf-v1' and manifest.get('complete') is False
                    and all(digest(manifest_path.parent / n) == h for n, h in manifest['files'].items())):
                pilots.append(manifest_path)
        if not pilots:
            raise RuntimeError('请先在相同 workdir 完成 pilot 并检查产物，再执行 full')
    repo = work / 'ctf-wiki'
    if args.snapshot:
        from secrag.remote_build import digest
        if not args.snapshot_sha256 or digest(args.snapshot) != args.snapshot_sha256:
            raise ValueError('上传的源快照哈希不一致')
        if not repo.exists():
            import zipfile
            from shutil import copyfileobj
            with zipfile.ZipFile(args.snapshot) as archive:
                repo.mkdir()
                for member in archive.infolist():
                    parts = Path(member.filename).parts[1:]
                    if not parts or member.is_dir():
                        continue
                    target = repo.joinpath(*parts).resolve()
                    if not target.is_relative_to(repo):
                        raise ValueError('源快照路径越界')
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with archive.open(member) as source, target.open('wb') as dest:
                        copyfileobj(source, dest)
            (repo / '.ctf-source.json').write_text(json.dumps({'commit': lock['commit'],
                'archive_sha256':args.snapshot_sha256, 'verification':'per-page Git blob hashes from pinned official tree'}), encoding='utf-8')
    else:
        if not repo.exists():
            subprocess.run(['git', 'init', str(repo)], check=True)
            subprocess.run(['git', '-C', str(repo), 'remote', 'add', 'origin', lock['repository']], check=True)
        subprocess.run(['git', '-C', str(repo), 'fetch', '--depth=1', 'origin', lock['commit']], check=True)
        subprocess.run(['git', '-C', str(repo), 'checkout', '--detach', lock['commit']], check=True)
    import torch
    if not torch.cuda.is_available():
        raise RuntimeError('CUDA 不可用，请先修复 GPU 环境')
    from secrag.ctf_wiki import prepare
    from secrag.remote_build import export_bundle
    prepared = work / ('prepared-' + args.stage)
    if not prepared.exists():
        prepare(repo, metadata, prepared, sample=20 if args.stage == 'pilot' else 0)
    else:
        report = json.loads((prepared / 'coverage.json').read_text(encoding='utf-8'))
        if report['commit'] != lock['commit'] or report['errors'] or report.get('sample') != (args.stage == 'pilot'):
            raise RuntimeError('已有准备目录不符合本次作业，换新的 workdir')
    # Use a fresh output directory on each resume; vector_cache is shared under work.
    from datetime import datetime, timezone
    output = work / ('bundle-' + args.stage + '-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ'))
    if args.model_path:
        from secrag.remote_build import digest
        for name, expected in model['files_sha256'].items():
            if digest(Path(args.model_path)/name)!=expected:
                raise ValueError('远程本地模型文件哈希不一致')
    export_bundle(prepared / 'docs.jsonl', output, model['model'], model['revision'], args.batch_size, 'cuda', 'ctf', args.model_path)
    print('产物目录：' + str(output))


if __name__ == '__main__':
    main()
