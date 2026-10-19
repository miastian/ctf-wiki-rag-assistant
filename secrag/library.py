"""Validate a CTF profile before any model/Chroma initialization."""
import json
from pathlib import Path


def validate_ctf_library(directory):
    from secrag.remote_build import digest
    directory = Path(directory)
    path = directory / 'index_manifest.json'
    if not path.is_file():
        raise ValueError('CTF 知识库尚未导入：请先执行远程构建并导入产物。')
    manifest = json.loads(path.read_text(encoding='utf-8'))
    if manifest.get('profile') != 'ctf' or manifest.get('schema_version') != 2:
        raise ValueError('当前目录不是 CTF 产物。')
    if not manifest.get('complete'):
        raise ValueError('当前是试构建或不完整资料，尚不能启用全量 CTF 应用。')
    required = {'chunks.jsonl', 'vectors.npy', 'docs.jsonl', 'coverage.json', 'source-lock.json', 'LICENSE'}
    if not required <= set(manifest.get('files', {})):
        raise ValueError('CTF 产物缺少必需文件，请重新导入。')
    for name, expected in manifest['files'].items():
        if name == 'vectors.npy':  # Import verified this; persisted query index is Chroma.
            continue
        target = (directory / name).resolve()
        if not target.is_relative_to(directory.resolve()) or not target.is_file() or digest(target) != expected:
            raise ValueError('CTF 产物校验失败，请重新导入到独立目录。')
    return manifest


def pending_options(root, reason):
    from secrag.ctf_chat import MODES
    inventory = Path(root) / 'data/ctf/inventory.json'
    report = json.loads(inventory.read_text(encoding='utf-8')) if inventory.is_file() else {}
    return {'profile': 'ctf', 'ready': False, 'reason': reason, 'sources': ['ctf-wiki'], 'languages': ['zh'],
            'categories': sorted(report.get('categories', {})), 'modes': MODES, 'max_input': 16000,
            'library': {'commit': report.get('commit', ''), 'image_content_indexed': False, 'documents': None}}


def verified_local_model(root, model, revision):
    """Reuse existing weights only after checking hashes pinned to the official revision."""
    from secrag.remote_build import digest
    root = Path(root)
    path = root / 'data/models/bge-m3'
    lock_path = root / 'data/ctf/model-lock.json'
    if not path.is_dir() or not lock_path.is_file():
        return None
    lock = json.loads(lock_path.read_text(encoding='utf-8'))
    if lock['model'] != model or lock['revision'] != revision:
        return None
    if not lock.get('files_sha256'):
        return None
    for name, expected in lock['files_sha256'].items():
        target = (path / name).resolve()
        if not target.is_relative_to(path.resolve()) or not target.is_file() or digest(target) != expected:
            raise ValueError('本机模型与固定版本哈希不一致，请修复模型文件。')
    return str(path)
