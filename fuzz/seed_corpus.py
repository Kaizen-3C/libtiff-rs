"""Bootstrap fuzz/corpus/differential/ from the checked-in curated envelope
(tests/vectors/tiff_inputs.txt) — 538 op-script lines decoded to raw files. corpus/ is
gitignored (cargo-fuzz convention), so a fresh clone needs to run this once before fuzzing;
libFuzzer will grow the corpus from here via mutation.

Usage: python3 fuzz/seed_corpus.py
"""
import os

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "..", "tests", "vectors", "tiff_inputs.txt")
DST = os.path.join(HERE, "corpus", "differential")

os.makedirs(DST, exist_ok=True)
n = 0
with open(SRC, encoding="utf-8") as f:
    for line in f:
        line = line.rstrip("\r\n")
        if not line.strip():
            continue
        with open(os.path.join(DST, f"seed_{n:04d}"), "wb") as out:
            out.write(line.encode("utf-8"))
        n += 1
print(f"seeded {n} cases into {DST}")
