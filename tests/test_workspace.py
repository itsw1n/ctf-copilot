import os
import tempfile
import unittest
from pathlib import Path

class WorkspaceTests(unittest.TestCase):
    def test_new_workspace_is_flat(self):
        with tempfile.TemporaryDirectory() as d:
            old=os.environ.get('CTF_COPILOT_HOME'); os.environ['CTF_COPILOT_HOME']=d
            from ctf_copilot.workspace.manager import new
            root=new('demo')
            self.assertTrue((root/'notes.md').exists())
            self.assertFalse((root/'files').exists())
            if old is None: del os.environ['CTF_COPILOT_HOME']
            else: os.environ['CTF_COPILOT_HOME']=old
