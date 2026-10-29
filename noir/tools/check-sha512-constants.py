#!/usr/bin/env python3
"""Check the SHA-512 constants in xproof/src/sha512.nr against their FIPS 180-4 definitions:
IV = first 64 bits of the fractional parts of the square roots of the first 8 primes,
K  = first 64 bits of the fractional parts of the cube roots of the first 80 primes."""
import re
from decimal import Decimal, getcontext
from pathlib import Path

getcontext().prec = 80
src = Path(__file__).resolve().parent.parent.joinpath("xproof/src/sha512.nr").read_text()

def block(name):
    body = re.search(rf"{name}: \[u64; \d+\] = \[(.*?)\];", src, re.S).group(1)
    return [int(h, 16) for h in re.findall(r"0x[0-9a-f]+", body)]

primes, k = [], 2
while len(primes) < 80:
    if all(k % p for p in primes):
        primes.append(k)
    k += 1
frac64 = lambda d: int((d - int(d)) * 2**64)
iv_ok = block("IV") == [frac64(Decimal(p).sqrt()) for p in primes[:8]]
k_ok = block("K") == [frac64(Decimal(p) ** (Decimal(1) / 3)) for p in primes]
print(f"IV {'ok' if iv_ok else 'MISMATCH'} · K {'ok' if k_ok else 'MISMATCH'}")
raise SystemExit(0 if iv_ok and k_ok else 1)
