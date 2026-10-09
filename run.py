import argparse,json,os,subprocess,sys,shutil
from pathlib import Path
from qmigrate import *
from crypto_adapter import OpenSSL,selftest,FLAGS
from numeric import write_json,environment

from fixture_templates import TEMPLATES

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--openssl');ap.add_argument('--output',default='results');ap.add_argument('--bench',type=int,default=0);a=ap.parse_args()
    api=OpenSSL(a.openssl);cap=api.capabilities();out=Path(a.output).resolve();out.mkdir(parents=True,exist_ok=True)
    env=dict(os.environ,QMIGRATE_OPENSSL=api.exe,QMIGRATE_PYTHON=sys.executable);tasks=[];fixture_rows=[]
    for language,base in TEMPLATES.items():
        suffix={'python':'py','java':'java','go':'go'}[language]
        for i in range(8):
            folder=out/'tasks'/f'{language}-{i}';folder.mkdir(parents=True,exist_ok=True);source=folder/('original.'+suffix);text=base.replace('controlled signature unit',f'controlled signature unit {i%6}').replace('2048','3072' if i%2 else '2048')

            source.write_text(text,encoding='utf-8');dest=folder/'migrated'
            decision=transform(source,language,dest,cap['ml_dsa_65'],policy={'external_verifier':i>=6})
            validation=dict(status='abstained')
            if decision['auto_applicable']:
                if language=='python':cmd=[sys.executable,'main.py']
                elif language=='java' and shutil.which('javac') and shutil.which('java'):
                    build=subprocess.run(['javac','Main.java'],cwd=dest,capture_output=True,text=True,creationflags=FLAGS)
                    cmd=['java','Main'] if build.returncode==0 else None
                    validation=dict(status='build_failed',stdout=build.stdout,stderr=build.stderr)
                elif language=='go' and shutil.which('go'):cmd=['go','run','main.go']
                else:cmd=None;validation=dict(status='toolchain_unavailable',toolchain=language)
                if cmd:
                    result=subprocess.run(cmd,cwd=dest,env=env,capture_output=True,text=True,timeout=60,creationflags=FLAGS)
                    validation=dict(status='passed' if result.returncode==0 else 'failed',returncode=result.returncode,stdout=result.stdout,stderr=result.stderr)
            tasks.append(dict(language=language,id=i,expected_supported=i<6,plan=decision['strategy'],validation=validation))
        for i in range(30):
            positive=i<20
            code=base if positive else ('# RSA GenerateKey sign\nx="RSA"\n' if language=='python' else '// RSA GenerateKey sign\n')
            if positive and i%2:code=code.replace('2048','3072')
            detected=bool(extract(code,language)['sites']);fixture_rows.append(dict(language=language,id=i,positive=positive,detected=detected,fixture_scope='Generated direct-use template variants'))
    bench={alg:selftest(api.exe,alg,a.bench) for alg in ['ML-DSA-65','RSA','EC']}
    report=dict(capabilities=cap,tasks=tasks,detector_fixtures=fixture_rows,cryptographic_checks=bench,environment=environment(),scope='Controlled sign/verify template variants; Java/Go execute through a Python subprocess adapter; build status recorded per task')
    write_json(out/'summary.json',report);print(json.dumps(dict(capabilities=cap,task_statuses={status:sum(t['validation']['status']==status for t in tasks) for status in {t['validation']['status'] for t in tasks}})))
if __name__=='__main__':main()
