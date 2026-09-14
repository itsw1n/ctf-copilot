"""Compatibility facade for older imports. New code should import category modules directly."""
from .crypto.encodings.base import decode
from .crypto.classical.caesar import all_shifts as caesar
from .crypto.analyzer import analyze as recursive
from .crypto.xor.single_byte import candidates as xor_candidates
from .shared.flags import find_flags as flags
from .network.resolve import resolve
from .network.scan import scan
