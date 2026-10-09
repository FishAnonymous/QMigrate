
import argparse,json
from pathlib import Path
from qmigrate import transform
from crypto_adapter import OpenSSL
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('source');p.add_argument('--language',choices=['python','java','go'],required=True);p.add_argument('--output',required=True);p.add_argument('--openssl');p.add_argument('--external-verifier',action='store_true');a=p.parse_args()
    source=Path(a.source).resolve();destination=Path(a.output).resolve()
    if destination==source.parent:p.error('Choose a separate output directory')
    try:available=OpenSSL(a.openssl).capabilities()['ml_dsa_65']
    except RuntimeError:available=False
    r=transform(source,a.language,destination,available,policy={'external_verifier':a.external_verifier})
    print(json.dumps(dict(strategy=r['strategy'],reasons=r['reasons']),indent=2))
