import io, tempfile, unittest, zipfile
from contextlib import redirect_stdout
from pathlib import Path
from ctf_copilot.cli import build_parser
from ctf_copilot.crypto.analyzer import analyze
from ctf_copilot.forensics.recurse import inspect

class V08Tests(unittest.TestCase):
    def test_structural_chain_beats_caesar_noise(self):
        rows=analyze('4d6a41784e444d3d')
        self.assertTrue(rows)
        self.assertEqual(rows[0].output,'20143')
        self.assertEqual([c.kind for c in rows[0].chain],['hex','base64'])
        self.assertFalse(any(r.chain[-1].kind=='caesar' for r in rows[:5]))

    def test_recursive_zip_finds_flag(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            inner_bytes=io.BytesIO()
            with zipfile.ZipFile(inner_bytes,'w') as z:
                z.writestr('clue.txt','666c61677b646565705f746573747d')
            outer=root/'outer.zip'
            with zipfile.ZipFile(outer,'w') as z:
                z.writestr('inner.zip',inner_bytes.getvalue())
            text=inspect(str(outer))
            self.assertIn('flag{deep_test}',text)

    def test_new_commands_parse(self):
        parser=build_parser()
        samples=[
            ['commands'],['forensics','recurse','x.zip'],['reverse','imports','./a'],
            ['reverse','functions','./a'],['web','js','http://localhost/a.js'],
            ['web','params','http://localhost'],['pwn','cyclic','create','100'],
        ]
        for argv in samples:
            with self.subTest(argv=argv):
                ns=parser.parse_args(argv)
                self.assertTrue(callable(ns.fn))

if __name__=='__main__': unittest.main()
