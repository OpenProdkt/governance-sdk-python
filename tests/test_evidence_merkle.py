# Test-only RFC 9162 reference, not a public SDK API.
import hashlib
import json
import unittest
from pathlib import Path

VECTORS = Path(__file__).resolve().parents[2] / "testdata" / "evidence-merkle-vectors.json"
def digest(b):
    return hashlib.sha256(b).digest()
def node(a, b):
    return digest(bytes([1]) + a + b)
def split(n):
    return 1 << ((n - 1).bit_length() - 1)
def root(leaves):
    if not leaves:
        return digest(b"")
    if len(leaves) == 1:
        return leaves[0]
    k = split(len(leaves))
    return node(root(leaves[:k]), root(leaves[k:]))
def inclusion(leaves, i):
    if len(leaves) == 1:
        return []
    k = split(len(leaves))
    if i < k:
        return inclusion(leaves[:k], i) + [root(leaves[k:])]
    return inclusion(leaves[k:], i-k) + [root(leaves[:k])]
def consistency(leaves, m, complete=True):
    if not m:
        return []
    if m == len(leaves):
        return [] if complete else [root(leaves)]
    k = split(len(leaves))
    if m <= k:
        return consistency(leaves[:k], m, complete) + [root(leaves[k:])]
    return consistency(leaves[k:], m-k, False) + [root(leaves[:k])]
def encoded(d):
    return "sha256:" + d.hex()

class EvidenceMerkleTests(unittest.TestCase):
    def test_shared_vectors(self):
        fixture = json.loads(VECTORS.read_text())
        self.assertEqual(fixture["format"], "opk.evidence.merkle.v1")
        self.assertEqual(len(fixture["trees"]), 12)
        for tree in fixture["trees"]:
            leaves = [digest(bytes([0]) + bytes.fromhex(e[7:])) for e in tree["events"]]
            self.assertEqual(encoded(root(leaves)), tree["root"])
            for proof in tree["inclusion"]:
                self.assertEqual([encoded(p) for p in inclusion(leaves, proof["index"])], proof["path"])
            for proof in tree["consistency"]:
                m = proof["old_size"]
                self.assertEqual(encoded(root(leaves[:m])), proof["old_root"])
                self.assertEqual([encoded(p) for p in consistency(leaves, m)], proof["path"])

if __name__ == "__main__":
    unittest.main()
