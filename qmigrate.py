
from pathlib import Path
import ast,re,difflib,json,shutil

BOUNDARIES={'certificate_tls':r'\b(?:x509|Certificate|SSLContext|tls\.|ssl\.)', 'external_verifier':r'external[_ -]?verifier|remote[_ -]?verify','network':r'\b(?:requests\.|http\.|socket\.|net\.Dial|HttpClient)','persistence':r'\b(?:FileOutputStream|os\.WriteFile|open\([^)]*["\']w)', 'fixed_wire':r'\b(?:wire|frame|signature)\w*\s*(?:\[\s*\d+\s*\]|\.length\s*==\s*\d+)', 'hardware_key':r'\b(?:PKCS11|HSM|KeyStore)\b'}
def scrub_comments(text,language):
    if language=='python':return text
    tokens=re.compile(r'"(?:\\.|[^"\\])*"|`[^`]*`|//[^\n]*|/\*[\s\S]*?\*/')
    return tokens.sub(lambda m:re.sub(r'[^\n]',' ',m[0]) if m[0].startswith('/') else m[0],text)

def extract(text,language):
    sites=[];unresolved=[]
    if language=='python':
        tree=ast.parse(text);aliases={}
        for node in ast.walk(tree):
            if isinstance(node,ast.ImportFrom) and node.module:
                for a in node.names:aliases[a.asname or a.name]=node.module+'.'+a.name
            elif isinstance(node,ast.Import):
                for a in node.names:aliases[a.asname or a.name]=a.name
        def qualified(node):
            if isinstance(node,ast.Name):return aliases.get(node.id,node.id)
            if isinstance(node,ast.Attribute):return qualified(node.value)+'.'+node.attr
            return ''
        for node in ast.walk(tree):
            if not isinstance(node,ast.Call):continue
            name=qualified(node.func)
            if name in ('cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key','cryptography.hazmat.primitives.asymmetric.ec.generate_private_key','Crypto.PublicKey.RSA.generate'):
                sites.append(dict(line=node.lineno,primitive='RSA' if 'rsa.' in name.lower() else 'ECC',operation='keygen',evidence=name,confidence='AST import resolved'))
            elif isinstance(node.func,ast.Attribute) and node.func.attr in ('sign','verify') and sites:
                sites.append(dict(line=node.lineno,primitive='contextual',operation=node.func.attr,evidence=ast.unparse(node.func),confidence='local contextual candidate'))
        clean=text
    else:
        clean=scrub_comments(text,language)
        if language=='java':
            qualified_import=bool(re.search(r'import\s+java\.security\.(?:\*|KeyPairGenerator|Signature)\s*;',clean))
            if qualified_import:
                for m in re.finditer(r'\b(KeyPairGenerator|Signature)\s*\.\s*getInstance\(\s*"([^"]+)"',clean):
                    if re.search(r'RSA|EC|DSA',m[2],re.I):sites.append(dict(line=clean[:m.start()].count('\n')+1,primitive='RSA' if 'RSA' in m[2].upper() else 'ECC',operation='keygen' if m[1]=='KeyPairGenerator' else 'signature',evidence=m[0],confidence='import-supported syntax'))
        elif language=='go':
            imports={}
            for m in re.finditer(r'(?:(\w+)\s+)?"crypto/(rsa|ecdsa|ecdh)"',clean):imports[m[1] or m[2]]=m[2]

            masked=re.sub(r'"(?:\\.|[^"\\])*"|`[^`]*`',lambda m:' '*len(m[0]),clean)
            for alias,family in imports.items():
                for m in re.finditer(r'\b'+re.escape(alias)+r'\.(GenerateKey|SignPSS|SignPKCS1v15|SignASN1|VerifyPSS|VerifyASN1)\s*\(',masked):sites.append(dict(line=clean[:m.start()].count('\n')+1,primitive=family.upper(),operation='keygen' if m[1]=='GenerateKey' else 'signature',evidence=m[0],confidence='import-supported syntax'))
        else:raise ValueError('Supported languages: python/java/go')
    boundaries=[dict(kind=k,evidence=m[0],line=clean[:m.start()].count('\n')+1) for k,p in BOUNDARIES.items() for m in re.finditer(p,clean,re.I)]
    nodes=[dict(id=f's{i}',kind='operation',**s) for i,s in enumerate(sites)]+[dict(id=f'b{i}',kind='boundary',boundary=b['kind'],**{k:v for k,v in b.items() if k!='kind'}) for i,b in enumerate(boundaries)]
    edges=[dict(source=f's{i}',target=f'b{j}',kind='file-context-indicator',resolved=False) for i in range(len(sites)) for j in range(len(boundaries))]
    return dict(language=language,sites=sites,boundaries=boundaries,cug=dict(nodes=nodes,edges=edges),analysis_scope='Python AST import resolution; Java/Go import-supported syntax; file-context CUG indicators')

def plan(text,language,provider_available,policy=None):
    inventory=extract(text,language);reasons=[]
    if not inventory['sites']:reasons.append('no recognized vulnerable crypto site')
    if inventory['boundaries']:reasons.append('unresolved compatibility boundary: '+','.join(sorted({b['kind'] for b in inventory['boundaries']})))
    from fixture_templates import TEMPLATES
    if language=='python':
        canonical=lambda t:ast.dump(ast.parse(t),include_attributes=False)
    else:
        canonical=lambda t:re.sub(r'\s+','',scrub_comments(t,language))
    supported=any(canonical(text)==canonical(TEMPLATES[language].replace('2048',size).replace('controlled signature unit',message)) for size in ('2048','3072') for message in ['controlled signature unit']+[f'controlled signature unit {i}' for i in range(6)])
    if not supported:reasons.append('unit does not match a supported complete template')
    if (policy or {}).get('external_verifier'):reasons.append('policy: external verifier compatibility unknown')
    if not provider_available:reasons.append('ML-DSA-65 provider unavailable')
    return dict(inventory=inventory,strategy='abstain' if reasons else 'direct',auto_applicable=not reasons,reasons=reasons,target='ML-DSA-65',candidate_strategies=['direct','hybrid-profile-required','compatibility-preserving-policy-required','abstain'],validation_obligations=['build','sign_verify','wrong_message','wrong_key','corrupt_signature','key_serialization_roundtrip'],supported_scope='Supported transformations: complete sign/verify fixture templates; other units return abstain')

def generated_source(language):
    if language=='python':return 'from crypto_adapter import selftest\nimport json\n\ndef main():\n    result = selftest()\n    print(json.dumps(result))\n    if result["status"] != "passed":\n        raise SystemExit(2)\n\nif __name__ == "__main__":\n    main()\n'
    if language=='java':return '''import java.io.File;
public class Main {
    public static void main(String[] args) throws Exception {
        String python = System.getenv().getOrDefault("QMIGRATE_PYTHON", "python");
        Process process = new ProcessBuilder(python, "crypto_adapter.py", "--selftest")
            .directory(new File(".")).inheritIO().start();
        int code = process.waitFor();
        if (code != 0) throw new IllegalStateException("Cryptographic validation failed: " + code);
    }
}
'''
    if language=='go':return '''package main
import ("os"; "os/exec"; "fmt")
func main() {
    python := os.Getenv("QMIGRATE_PYTHON")
    if python == "" { python = "python" }
    cmd := exec.Command(python, "crypto_adapter.py", "--selftest")
    cmd.Stdout = os.Stdout; cmd.Stderr = os.Stderr
    if err := cmd.Run(); err != nil { fmt.Fprintln(os.Stderr, err); os.Exit(2) }
}
'''
    raise ValueError(language)

def transform(source,language,destination,provider_available,policy=None):
    source=Path(source);text=source.read_text(encoding='utf-8');decision=plan(text,language,provider_available,policy)
    out=Path(destination);out.mkdir(parents=True,exist_ok=True)
    if decision['auto_applicable']:
        name={'python':'main.py','java':'Main.java','go':'main.go'}[language];new=generated_source(language)
        (out/name).write_text(new,encoding='utf-8')
        shutil.copyfile(Path(__file__).with_name('crypto_adapter.py'),out/'crypto_adapter.py')
        (out/'migration.patch').write_text(''.join(difflib.unified_diff(text.splitlines(True),new.splitlines(True),fromfile='a/'+source.name,tofile='b/'+name)),encoding='utf-8')
        decision['patch_scope']='Whole sign/verify fixture unit; Java/Go use a Python subprocess provider adapter'
    (out/'plan.json').write_text(json.dumps(decision,indent=2),encoding='utf-8')
    return decision
