"""Download only locked model files, at the fixed revision, with hash verification."""
import concurrent.futures
import hashlib
import json
import os
import sys
import time
from pathlib import Path

import requests


def digest(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        while block:=f.read(1024*1024):h.update(block)
    return h.hexdigest()


def fetch_model(lock_path, output, endpoint='https://hf-mirror.com'):
    lock=json.loads(Path(lock_path).read_text(encoding='utf-8'));output=Path(output)
    output.mkdir(parents=True,exist_ok=True)
    for name, expected in lock['files_sha256'].items():
        target=output/name;target.parent.mkdir(parents=True,exist_ok=True)
        if target.is_file() and digest(target)==expected:
            continue
        size=lock['files_bytes'][name]
        url=f"{endpoint}/{lock['model']}/resolve/{lock['revision']}/{name}"
        temporary=target.with_name(target.name+'.download')
        # Resolve once, then use ranged requests on the storage CDN directly.
        # Hundreds of resolver requests otherwise exhaust the mirror rate limit.
        download_url=url
        if size>32*1024*1024:
            for attempt in range(4):
                probe=requests.get(url+'?download=true',headers={'Range':'bytes=0-0'},stream=True,timeout=(15,30))
                if probe.status_code!=429:
                    probe.raise_for_status();download_url=probe.url;probe.close();break
                delay=min(60,int(probe.headers.get('Retry-After','30'))) if probe.headers.get('Retry-After','30').isdigit() else 30
                probe.close()
                if attempt==3:raise RuntimeError('model mirror rate limited after bounded retries')
                print('resolver rate limited; retry in',delay,'seconds',flush=True);time.sleep(delay)
        def get_range(index):
            start=index*8*1024*1024;end=min(size,start+8*1024*1024)-1
            part=target.parent/(target.name+f'.part{index}')
            if part.exists() and part.stat().st_size==end-start+1:return part
            for attempt in range(3):
                try:
                    response=requests.get(download_url,headers={'Range':f'bytes={start}-{end}'},timeout=(15,90))
                    response.raise_for_status()
                    if response.status_code!=206 or len(response.content)!=end-start+1 or not response.headers.get('Content-Range','').startswith(f'bytes {start}-{end}/'):
                        raise RuntimeError('range response length/status mismatch')
                    part.write_bytes(response.content)
                    return part
                except (requests.RequestException,RuntimeError):
                    if attempt==2:raise
                    time.sleep(2*(attempt+1))
        if size>32*1024*1024:
            count=(size+8*1024*1024-1)//(8*1024*1024)
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                for i,_ in enumerate(pool.map(get_range,range(count)),1):
                    if i%16==0 or i==count:print(name,f'{i}/{count} parts',flush=True)
            with temporary.open('wb') as dest:
                for i in range(count):
                    with (target.parent/(target.name+f'.part{i}')).open('rb') as src:
                        while block:=src.read(1024*1024):dest.write(block)
        else:
            response=requests.get(url+'?download=true',timeout=(15,90));response.raise_for_status()
            temporary.write_bytes(response.content)
        if temporary.stat().st_size!=size or digest(temporary)!=expected:
            raise RuntimeError('fixed-revision model file hash mismatch: '+name)
        os.replace(temporary,target)
        for part in target.parent.glob(target.name+'.part*'):part.unlink()
        print('verified',name,flush=True)
    return output


if __name__=='__main__':
    fetch_model(sys.argv[1],sys.argv[2],sys.argv[3] if len(sys.argv)>3 else 'https://hf-mirror.com')
