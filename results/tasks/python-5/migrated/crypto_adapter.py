
from pathlib import Path
import argparse,subprocess,tempfile,shutil,os,time,json
import numpy as np

FLAGS=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0
class OpenSSL:
    def __init__(self,executable=None):
        if executable is None:
            executable=os.environ.get('QMIGRATE_OPENSSL')
            if executable is None and os.name=='nt':
                for parent in Path(__file__).resolve().parents:
                    candidate=parent/'runtime/windows/openssl.exe'
                    if candidate.exists():executable=str(candidate);break
        executable=executable or 'openssl'
        found=shutil.which(executable)
        if not found:raise RuntimeError('OpenSSL executable not found')
        self.exe=str(Path(found).resolve())
    def run(self,*args,check=True):
        r=subprocess.run([self.exe,*map(str,args)],capture_output=True,timeout=30,creationflags=FLAGS)
        if check and r.returncode:raise RuntimeError(r.stderr.decode(errors='replace'))
        return r
    def capabilities(self):
        version=self.run('version').stdout.decode().strip();algorithms=self.run('list','-signature-algorithms').stdout.decode()
        return dict(version=version,ml_dsa_65='ML-DSA-65' in algorithms.upper())
    def generate(self,directory,algorithm='ML-DSA-65'):
        root=Path(directory);root.mkdir(parents=True,exist_ok=True);priv=root/'private.pem';pub=root/'public.pem'
        args=['genpkey','-algorithm',algorithm,'-out',priv]
        if algorithm=='RSA':args+=['-pkeyopt','rsa_keygen_bits:2048']
        if algorithm=='EC':args+=['-pkeyopt','ec_paramgen_curve:P-256']
        self.run(*args);self.run('pkey','-in',priv,'-pubout','-out',pub)
        return priv,pub
    def sign(self,key,message,destination,algorithm='ML-DSA-65'):
        args=['pkeyutl','-sign','-rawin','-inkey',key,'-in',message,'-out',destination]
        if algorithm in ('RSA','EC'):args+=['-digest','sha256']
        if algorithm=='RSA':args+=['-pkeyopt','rsa_padding_mode:pss']
        self.run(*args)
    def verify(self,key,message,signature,algorithm='ML-DSA-65'):
        args=['pkeyutl','-verify','-rawin','-pubin','-inkey',key,'-in',message,'-sigfile',signature]
        if algorithm in ('RSA','EC'):args+=['-digest','sha256']
        if algorithm=='RSA':args+=['-pkeyopt','rsa_padding_mode:pss']
        return self.run(*args,check=False).returncode==0

def selftest(executable=None,algorithm='ML-DSA-65',repetitions=0):
    api=OpenSSL(executable);cap=api.capabilities()
    if algorithm=='ML-DSA-65' and not cap['ml_dsa_65']:return dict(status='unavailable',capabilities=cap,reason='Provider does not expose ML-DSA-65')
    with tempfile.TemporaryDirectory(prefix='qmigrate-') as d:
        root=Path(d);priv,pub=api.generate(root/'primary',algorithm);wrongpriv,wrongpub=api.generate(root/'wrong',algorithm)
        msg=root/'message.bin';msg.write_bytes(b'Q-Migrate validation payload\x00\xff');sig=root/'signature.bin';api.sign(priv,msg,sig,algorithm)
        checks={'valid_signature':api.verify(pub,msg,sig,algorithm)}
        altered=root/'altered.bin';altered.write_bytes(msg.read_bytes()+b'tamper');checks['modified_message_rejected']=not api.verify(pub,altered,sig,algorithm)
        checks['wrong_key_rejected']=not api.verify(wrongpub,msg,sig,algorithm)
        corrupt=root/'corrupt.sig';data=bytearray(sig.read_bytes());data[len(data)//2]^=1;corrupt.write_bytes(data);checks['corrupt_signature_rejected']=not api.verify(pub,msg,corrupt,algorithm)
        public_der=root/'public.der';public_roundtrip=root/'public-roundtrip.pem';api.run('pkey','-pubin','-in',pub,'-outform','DER','-out',public_der);api.run('pkey','-pubin','-inform','DER','-in',public_der,'-out',public_roundtrip)
        checks['public_key_roundtrip']=api.verify(public_roundtrip,msg,sig,algorithm)
        private_der=root/'private.der';private_roundtrip=root/'private-roundtrip.pem';api.run('pkey','-in',priv,'-outform','DER','-out',private_der);api.run('pkey','-inform','DER','-in',private_der,'-out',private_roundtrip);api.sign(private_roundtrip,msg,root/'roundtrip.sig',algorithm)
        checks['private_key_roundtrip']=api.verify(pub,msg,root/'roundtrip.sig',algorithm)
        timings=[]
        if repetitions:
            for _ in range(3):api.sign(priv,msg,sig,algorithm)
            for _ in range(repetitions):
                start=time.perf_counter_ns();api.sign(priv,msg,sig,algorithm);timings.append((time.perf_counter_ns()-start)/1e6)
        return dict(status='passed' if all(checks.values()) else 'failed',algorithm=algorithm,capabilities=cap,checks=checks,signature_bytes=sig.stat().st_size,public_der_bytes=public_der.stat().st_size,timing_ms=timings,timing_median_ms=float(np.median(timings)) if timings else None,timing_iqr_ms=float(np.percentile(timings,75)-np.percentile(timings,25)) if timings else None,timing_scope='Subprocess end-to-end timing including process startup and file I/O')

if __name__=='__main__':
    ap=argparse.ArgumentParser();ap.add_argument('--selftest',action='store_true');ap.add_argument('--openssl');ap.add_argument('--algorithm',choices=['ML-DSA-65','RSA','EC'],default='ML-DSA-65');ap.add_argument('--repetitions',type=int,default=0);a=ap.parse_args();r=selftest(a.openssl,a.algorithm,a.repetitions);print(json.dumps(r));raise SystemExit(0 if r['status']=='passed' else 2)
