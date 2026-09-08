COMMANDS = r"""
==============================
CTF COPILOT v0.5 COMMANDS
==============================

START HERE
  ctf solve <target>                     Unknown file/URL/text? Start here.
  ctf tools                              Check useful Kali tools.
  ctf commands                           Show this compact reference.

CRYPTO
  ctf crypto analyze <text>              Detect/follow likely encoding layers.
  ctf crypto decode <text>               Auto-decode recursively.
  ctf crypto decode <text> --kind hex    Decode a specific format.
  ctf crypto xor <hex>                   Try single-byte XOR candidates.
  ctf crypto frequency <text>            Character-frequency analysis.

Rule of thumb:
  Don't know the category? -> ctf solve
  Know the category?       -> ctf <category> <action>

Use active network/web features only on CTF targets, your own systems, or systems you are explicitly authorized to test.
""".strip()
