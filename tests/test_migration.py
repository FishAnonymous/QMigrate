import unittest,tempfile
from pathlib import Path
from qmigrate import *
from run import TEMPLATES
class MigrationTests(unittest.TestCase):
    def test_three_frontends(self):
        for lang,source in TEMPLATES.items():self.assertTrue(extract(source,lang)['sites'])
    def test_comments_strings_negative(self):
        self.assertFalse(extract('x="rsa.generate_private_key()"\n# RSA\n','python')['sites'])
        self.assertFalse(extract('// Signature.getInstance("RSA")','java')['sites'])
        self.assertFalse(extract('package main\nimport "crypto/rsa"\nvar s = "rsa.GenerateKey("','go')['sites'])
    def test_python_alias(self):
        s='from cryptography.hazmat.primitives.asymmetric import rsa as r\nk=r.generate_private_key(public_exponent=65537,key_size=2048)'
        self.assertTrue(extract(s,'python')['sites'])
    def test_guards(self):
        self.assertFalse(plan(TEMPLATES['python'],'python',False)['auto_applicable'])
        self.assertFalse(plan(TEMPLATES['python']+'\nremote_verify = external_verifier\n','python',True)['auto_applicable'])
        self.assertFalse(plan(TEMPLATES['python'].replace('key_size=2048','key_size=1024'),'python',True)['auto_applicable'])
    def test_source_unchanged(self):
        with tempfile.TemporaryDirectory() as d:
            source=Path(d,'original.py');source.write_text(TEMPLATES['python']);out=Path(d,'out');r=transform(source,'python',out,True)
            self.assertTrue(r['auto_applicable']);self.assertEqual(source.read_text(),TEMPLATES['python']);ast.parse((out/'main.py').read_text());self.assertTrue((out/'migration.patch').exists())
    def test_template_rejects_additional_statements(self):
        self.assertFalse(plan(TEMPLATES['python']+'\nprint("unrelated application logic")\n','python',True)['auto_applicable'])
    def test_explicit_peer_policy(self):
        self.assertFalse(plan(TEMPLATES['go'],'go',True,policy={'external_verifier':True})['auto_applicable'])
