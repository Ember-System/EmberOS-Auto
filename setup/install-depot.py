#!/usr/bin/env python3
"""Bootstrap Ember Depot on an already-running EmberOS Auto ARM64 system.

The adjacent signed bundle is used when present. Otherwise the 1.5.0 bundle
is fetched from the official repository. No partition or boot files are edited.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
import zipfile

VERSION = '1.5.0'
BASE = 'https://raw.githubusercontent.com/Ember-System/EmberOS-Auto/main'
MANIFEST_URL = BASE + '/update/v1.5.0/manifest.json'
PUBLIC_KEY = b'''-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAAuoEPun3QU9fNvyImLcA42rjLyUVojLd+Km4RTkRkFc=
-----END PUBLIC KEY-----
'''
UNIT = '''[Unit]
Description=Install the approved signed EmberOS Auto runtime update
After=local-fs.target
ConditionPathExists=/var/lib/emberos-auto/depot/staged/manifest.json

[Service]
Type=oneshot
User=root
WorkingDirectory=/
ExecStart=/usr/local/bin/emberos-auto --apply-staged-update
TimeoutStartSec=180
UMask=0077
NoNewPrivileges=yes
PrivateTmp=yes
RestrictSUIDSGID=yes
LockPersonality=yes
StandardOutput=journal
StandardError=journal
SyslogIdentifier=ember-depot-update
'''
MAX_PACKAGE = 64 * 1024 * 1024
MAX_BINARY = 128 * 1024 * 1024

def version_tuple(s):
    parts = s.split('.')
    if len(parts) != 3 or any(not p.isdecimal() or (len(p)>1 and p.startswith('0')) for p in parts):
        raise ValueError('Invalid release version')
    return tuple(map(int, parts))

def approved_url(url):
    u = urllib.parse.urlsplit(url)
    return (u.scheme == 'https' and u.netloc == 'raw.githubusercontent.com'
            and u.path.startswith('/Ember-System/EmberOS-Auto/main/')
            and not u.query and not u.fragment and not any(p in ('.','..') for p in u.path.split('/')) and '%' not in u.path)

class OfficialRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not approved_url(newurl):
            raise RuntimeError('Download redirected outside the Ember repository')
        return super().redirect_request(req, fp, code, msg, headers, newurl)

def fetch(url, destination, limit):
    if not approved_url(url):
        raise RuntimeError('The download address is not the Ember repository')
    req = urllib.request.Request(url, headers={'User-Agent':'EmberOS-Depot-Bootstrap/1.5.0', 'Cache-Control':'no-cache'})
    opener = urllib.request.build_opener(OfficialRedirects())
    size = 0
    with opener.open(req, timeout=30) as response, destination.open('wb') as out:
        while True:
            chunk = response.read(1024*1024)
            if not chunk: break
            size += len(chunk)
            if size > limit: raise RuntimeError('Download exceeded its allowed size')
            out.write(chunk)
    return size

def bounded_read(path, limit):
    st = path.lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_size > limit:
        raise RuntimeError('Unexpected file type or size: '+path.name)
    return path.read_bytes()

def verify_signature(manifest, signature, directory):
    key = directory/'trusted-public.pem'
    rawsig = directory/'signature.bin'
    exact = directory/'exact-manifest.json'
    key.write_bytes(PUBLIC_KEY)
    sig = base64.b64decode(signature.strip(), validate=True)
    if len(sig) != 64: raise RuntimeError('Invalid signature length')
    rawsig.write_bytes(sig)
    exact.write_bytes(manifest)
    result = subprocess.run(['openssl','pkeyutl','-verify','-pubin','-inkey',str(key),
        '-rawin','-in',str(exact),'-sigfile',str(rawsig)], capture_output=True, timeout=20)
    if result.returncode:
        raise RuntimeError('Ember signature verification failed; nothing installed')

def verify_arm64_elf(path):
    size=path.stat().st_size
    with path.open('rb') as f:
        h=f.read(64)
        if len(h)!=64 or h[:7]!=b'\x7fELF\x02\x01\x01':
            raise RuntimeError('Runtime is not a Linux ARM64 executable')
        kind,machine,version,entry,phoff,shoff,flags,ehsize,phsize,phnum,shsize,shnum,shstr=struct.unpack_from('<HHIQQQIHHHHHH',h,16)
        if kind not in (2,3) or machine!=183 or version!=1 or ehsize!=64 or phsize!=56 or not 0<phnum<=1024 or phoff<64 or phoff+phnum*phsize>size:
            raise RuntimeError('Runtime has an invalid ARM64 ELF header')
        executable=False
        for n in range(phnum):
            f.seek(phoff+n*phsize)
            ptype,pflags,offset,address,physical,filesz,memsz,align=struct.unpack('<IIQQQQQQ',f.read(56))
            if ptype==3: raise RuntimeError('Runtime must be a self-contained static executable')
            if offset>size or filesz>size-offset: raise RuntimeError('Runtime has a truncated ELF segment')
            if ptype==1 and pflags&1 and address<=entry<address+memsz: executable=True
        if not executable: raise RuntimeError('Runtime has no executable entry point')

def verified_binary(manifest_path, signature_path, package_path, work):
    raw = bounded_read(manifest_path, 256*1024)
    sig = bounded_read(signature_path, 4096)
    verify_signature(raw,sig,work)
    manifest = json.loads(raw)
    if (manifest.get('schema') != 1 or manifest.get('kind') != 'ember-runtime'
            or manifest.get('version') != VERSION or manifest.get('architecture') != 'linux-arm64'):
        raise RuntimeError('This bootstrap requires the signed EmberOS 1.5.0 ARM64 runtime')
    version_tuple(manifest['version'])
    if not approved_url(manifest['download_url']):
        raise RuntimeError('Invalid package address')
    size = manifest.get('size')
    if type(size) is not int or not 0<size<=MAX_PACKAGE:
        raise RuntimeError('Invalid signed package size')
    st=package_path.lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_size!=size:
        raise RuntimeError('Package size does not match its signed description')
    sha=hashlib.sha256()
    with package_path.open('rb') as f:
        for b in iter(lambda:f.read(1024*1024),b''): sha.update(b)
    if sha.hexdigest()!=manifest.get('sha256'):
        raise RuntimeError('Package checksum failed; nothing installed')
    destination=work/'emberos-auto'
    with zipfile.ZipFile(package_path) as archive:
        entries=archive.infolist()
        if len(entries)!=2 or {f.filename for f in entries}!={'package.json','emberos-auto'}:
            raise RuntimeError('Unexpected files in the runtime package')
        for entry in entries:
            mode=(entry.external_attr>>16)&0xffff
            if stat.S_IFMT(mode) not in (0,stat.S_IFREG) or entry.flag_bits&1:
                raise RuntimeError('Unsupported archive entry')
        info=archive.getinfo('package.json')
        if info.file_size>65536: raise RuntimeError('Package description too large')
        desc=json.loads(archive.read(info))
        expected={'schema':1,'kind':'ember-runtime','version':VERSION,'architecture':'linux-arm64'}
        if desc!=expected: raise RuntimeError('Package identity does not match its signature')
        info=archive.getinfo('emberos-auto')
        if not 64<info.file_size<=MAX_BINARY: raise RuntimeError('Runtime size is invalid')
        with archive.open(info) as inp,destination.open('wb') as out:
            remaining=info.file_size
            while remaining:
                b=inp.read(min(1024*1024,remaining))
                if not b: raise RuntimeError('Truncated runtime')
                out.write(b);remaining-=len(b)
            if inp.read(1): raise RuntimeError('Runtime grew during extraction')
        verify_arm64_elf(destination)
    return destination,manifest

def atomic_bytes(path, raw, mode):
    path.parent.mkdir(parents=True,exist_ok=True)
    fd,tmp=tempfile.mkstemp(prefix='.'+path.name+'-',dir=path.parent)
    try:
        with os.fdopen(fd,'wb') as f:
            f.write(raw);f.flush();os.fchmod(f.fileno(),mode);os.fsync(f.fileno())
        os.replace(tmp,path)
        d=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
        try: os.fsync(d)
        finally: os.close(d)
    finally:
        if os.path.exists(tmp): os.unlink(tmp)

def main():
    parser=argparse.ArgumentParser(description='Install signed Ember Depot 1.5.0 into the running Ember system')
    parser.add_argument('--verify-only',action='store_true',help='Verify an adjacent offline bundle without installing')
    parser.add_argument('--worker',action='store_true',help=argparse.SUPPRESS)
    args=parser.parse_args()
    if not args.verify_only:
        if os.geteuid()!=0: raise RuntimeError('Run this with sudo python3 install-depot.py')
        if platform.machine() not in ('aarch64','arm64'): raise RuntimeError('Run the installer on the CM5, not on the Windows PC')
        if not Path('/usr/local/bin/emberos-auto').is_file(): raise RuntimeError('An existing EmberOS installation was not found')
        if not Path('/etc/systemd/system/ember-auto-setup.service').is_file(): raise RuntimeError('The Ember interface service was not found')
    if not shutil.which('openssl'): raise RuntimeError('OpenSSL is required to verify the existing Ember signing key')
    print('EMBER DEPOT 1.5.0 - NVMe/SD runtime update',flush=True)
    here=Path(__file__).resolve().parent
    with tempfile.TemporaryDirectory(prefix='ember-depot-') as d:
        work=Path(d)
        names=('manifest.json','manifest.json.sig','package.zip')
        if all((here/n).is_file() for n in names):
            manifest_path,signature_path,package_path=(here/n for n in names)
            print('Using the adjacent offline bundle.',flush=True)
        else:
            manifest_path,signature_path,package_path=(work/n for n in names)
            print('Downloading the signed bootstrap description from GitHub...',flush=True)
            fetch(MANIFEST_URL,manifest_path,256*1024)
            fetch(MANIFEST_URL+'.sig',signature_path,4096)
            raw=bounded_read(manifest_path,256*1024)
            verify_signature(raw,bounded_read(signature_path,4096),work)
            desc=json.loads(raw)
            if desc.get('version')!=VERSION or type(desc.get('size')) is not int or not 0<desc['size']<=MAX_PACKAGE:
                raise RuntimeError('Unexpected bootstrap release')
            print('Signature verified. Downloading Ember Depot...',flush=True)
            fetch(desc['download_url'],package_path,desc['size'])
        binary,manifest=verified_binary(manifest_path,signature_path,package_path,work)
        print('Signature, checksum and ARM64 runtime verified.',flush=True)
        if args.verify_only:
            print('VERIFICATION PASSED. Nothing installed.');return
        marker=Path('/usr/share/emberos/depot-build.json')
        if marker.exists():
            prior=json.loads(marker.read_text())
            if version_tuple(prior['version'])>version_tuple(VERSION):
                raise RuntimeError('A newer Depot runtime is already installed; use Depot for future updates')
        if not args.worker:
            # The console and GUI services conflict. Run the actual installation
            # in a separate service so returning to Home cannot kill its process.
            jobs=Path('/var/lib/emberos-auto/depot')
            jobs.mkdir(parents=True,exist_ok=True)
            job=Path(tempfile.mkdtemp(prefix='bootstrap-',dir=jobs))
            try:
                shutil.copyfile(Path(__file__).resolve(),job/'install-depot.py')
                shutil.copyfile(manifest_path,job/'manifest.json')
                shutil.copyfile(signature_path,job/'manifest.json.sig')
                shutil.copyfile(package_path,job/'package.zip')
                os.sync()
                result=subprocess.run(['systemd-run','--unit=ember-depot-bootstrap','--collect',
                    '--property=Type=exec','/usr/bin/python3',str(job/'install-depot.py'),'--worker'],
                    check=True,capture_output=True,text=True,timeout=30)
            except Exception:
                shutil.rmtree(job,ignore_errors=True)
                raise
            print('Installation started. Ember Home will return when it finishes.',flush=True)
            print('If Home does not return, type: journalctl -u ember-depot-bootstrap -n 40 --no-pager',flush=True)
            return
        target=Path('/usr/local/bin/emberos-auto')
        unitpath=Path('/etc/systemd/system/ember-depot-update.service')
        if shutil.disk_usage(target.parent).free<binary.stat().st_size*2+8*1024*1024:
            raise RuntimeError('Not enough free space to install the runtime')
        # Hold the same lock used by future app/update operations.
        import fcntl
        lockdir=Path('/var/lib/emberos-auto/depot');lockdir.mkdir(parents=True,exist_ok=True)
        with (lockdir/'operation.lock').open('a') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            # Preserve only the currently running small executable until commit.
            backup=work/'previous-runtime';shutil.copyfile(target,backup)
            oldunit=unitpath.read_bytes() if unitpath.exists() else None
            oldmarker=marker.read_bytes() if marker.exists() else None
            stopped=False
            try:
                print('Installing Depot into the currently running Ember system...',flush=True)
                stopped=True
                subprocess.run(['systemctl','stop','ember-auto-setup.service'],check=True,timeout=30)
                atomic_bytes(target,binary.read_bytes(),0o755)
                atomic_bytes(unitpath,UNIT.encode(),0o644)
                record={'schema':1,'kind':'ember-runtime','version':VERSION,'installed_at':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'source':'bootstrap'}
                atomic_bytes(marker,(json.dumps(record,indent=2)+'\n').encode(),0o644)
                subprocess.run(['systemctl','daemon-reload'],check=True,timeout=30)
                os.sync()
                subprocess.run(['systemctl','start','ember-auto-setup.service'],check=True,timeout=30)
            except Exception:
                atomic_bytes(target,backup.read_bytes(),0o755)
                if oldunit is None: unitpath.unlink(missing_ok=True)
                else: atomic_bytes(unitpath,oldunit,0o644)
                if oldmarker is None: marker.unlink(missing_ok=True)
                else: atomic_bytes(marker,oldmarker,0o644)
                subprocess.run(['systemctl','daemon-reload'],timeout=30)
                if stopped: subprocess.run(['systemctl','start','ember-auto-setup.service'],timeout=30)
                raise
            print('INSTALLED: Ember Depot 1.5.0. Open Ember Depot on the head unit.',flush=True)
            if here.parent==lockdir and here.name.startswith('bootstrap-'):
                shutil.rmtree(here,ignore_errors=True)

if __name__=='__main__':
    try: main()
    except Exception as exc:
        print('\nInstallation stopped: '+str(exc),file=sys.stderr)
        sys.exit(1)
