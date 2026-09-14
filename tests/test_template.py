import tempfile
import unittest
from pathlib import Path
from ctf_copilot.crypto.template import generate

class TemplateTests(unittest.TestCase):
    def test_generates_without_executing_source(self):
        with tempfile.TemporaryDirectory() as d:
            source=Path(d)/'cipher.py'; source.write_text('key = "test"\nprint("never run")\n')
            output=Path(d)/'solve.py'
            text=generate(str(source),str(output))
            self.assertTrue(output.exists())
            self.assertIn('Generated editable scaffold',text)
