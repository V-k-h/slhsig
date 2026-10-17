"""Reference SLH-DSA-SHAKE-128f (FIPS 205) in Python, for the slides' running example.

Re-derives the key from the seeds, re-signs deterministically, checks the result byte-for-byte
against slhsig's output (running_example.json), verifies it, and prints a trace of every
intermediate value the slides use plus hash-call counts for signing and verification.

Run: python3 -I docs/slides/trace.py docs/slides/running_example.json
"""

import hashlib
import json
import sys
from collections import Counter

# SLH-DSA-SHAKE-128f, FIPS 205 Table 2.
N, H, D, HP, A, K, LG_W, M = 16, 66, 22, 3, 6, 33, 4, 34
W = 1 << LG_W
LEN1, LEN2 = 2 * N, 3
LEN = LEN1 + LEN2

CALLS = Counter()

WOTS_HASH, WOTS_PK, TREE, FORS_TREE, FORS_ROOTS, WOTS_PRF, FORS_PRF = range(7)


def shake(data, nbytes):
    return hashlib.shake_256(data).digest(nbytes)


class Adrs:
    def __init__(self):
        self.b = bytearray(32)

    def copy(self):
        a = Adrs()
        a.b[:] = self.b
        return a

    def _put(self, at, value, width=4):
        self.b[at:at + width] = value.to_bytes(width, "big")

    def set_layer(self, x):
        self._put(0, x)

    def set_tree(self, x):
        self._put(4, x, 12)

    def set_type_and_clear(self, t):
        self._put(16, t)
        self.b[20:32] = bytes(12)

    def set_key_pair(self, x):
        self._put(20, x)

    def set_chain(self, x):
        self._put(24, x)

    set_tree_height = set_chain

    def set_hash(self, x):
        self._put(28, x)

    set_tree_index = set_hash

    def key_pair(self):
        return int.from_bytes(self.b[20:24], "big")

    def tree_index(self):
        return int.from_bytes(self.b[28:32], "big")


# Section 11.1: every function is SHAKE256.
def F(pk_seed, adrs, m1):
    CALLS["F"] += 1
    return shake(pk_seed + bytes(adrs.b) + m1, N)


def Hn(pk_seed, adrs, m2):
    CALLS["H"] += 1
    return shake(pk_seed + bytes(adrs.b) + m2, N)


def T(pk_seed, adrs, ml):
    CALLS["T"] += 1
    return shake(pk_seed + bytes(adrs.b) + b"".join(ml), N)


def PRF(pk_seed, sk_seed, adrs):
    CALLS["PRF"] += 1
    return shake(pk_seed + bytes(adrs.b) + sk_seed, N)


def PRF_msg(sk_prf, opt_rand, msg):
    CALLS["PRF_msg"] += 1
    return shake(sk_prf + opt_rand + msg, N)


def H_msg(r, pk_seed, pk_root, msg):
    CALLS["H_msg"] += 1
    return shake(r + pk_seed + pk_root + msg, M)


def base_2b(x, b, out_len):  # Algorithm 4
    i, bits, total, out = 0, 0, 0, []
    for _ in range(out_len):
        while bits < b:
            total = (total << 8) + x[i]
            i += 1
            bits += 8
        bits -= b
        out.append((total >> bits) % (1 << b))
    return out


def chain(x, i, s, pk_seed, adrs):  # Algorithm 5
    for j in range(i, i + s):
        adrs.set_hash(j)
        x = F(pk_seed, adrs, x)
    return x


def wots_digits(m):  # lines 1-7 of Algorithms 7 and 8
    msg = base_2b(m, LG_W, LEN1)
    csum = sum(W - 1 - d for d in msg)
    csum <<= (8 - ((LEN2 * LG_W) % 8)) % 8
    return msg + base_2b(csum.to_bytes((LEN2 * LG_W + 7) // 8, "big"), LG_W, LEN2), csum


def wots_pkgen(sk_seed, pk_seed, adrs):  # Algorithm 6
    sk_adrs = adrs.copy()
    sk_adrs.set_type_and_clear(WOTS_PRF)
    sk_adrs.set_key_pair(adrs.key_pair())
    tmp = []
    for i in range(LEN):
        sk_adrs.set_chain(i)
        sk = PRF(pk_seed, sk_seed, sk_adrs)
        adrs.set_chain(i)
        tmp.append(chain(sk, 0, W - 1, pk_seed, adrs))
    pk_adrs = adrs.copy()
    pk_adrs.set_type_and_clear(WOTS_PK)
    pk_adrs.set_key_pair(adrs.key_pair())
    return T(pk_seed, pk_adrs, tmp)


def wots_sign(m, sk_seed, pk_seed, adrs):  # Algorithm 7
    msg, _ = wots_digits(m)
    sk_adrs = adrs.copy()
    sk_adrs.set_type_and_clear(WOTS_PRF)
    sk_adrs.set_key_pair(adrs.key_pair())
    sig = []
    for i in range(LEN):
        sk_adrs.set_chain(i)
        sk = PRF(pk_seed, sk_seed, sk_adrs)
        adrs.set_chain(i)
        sig.append(chain(sk, 0, msg[i], pk_seed, adrs))
    return b"".join(sig)


def wots_pk_from_sig(sig, m, pk_seed, adrs):  # Algorithm 8
    msg, _ = wots_digits(m)
    tmp = []
    for i in range(LEN):
        adrs.set_chain(i)
        tmp.append(chain(sig[i * N:(i + 1) * N], msg[i], W - 1 - msg[i], pk_seed, adrs))
    pk_adrs = adrs.copy()
    pk_adrs.set_type_and_clear(WOTS_PK)
    pk_adrs.set_key_pair(adrs.key_pair())
    return T(pk_seed, pk_adrs, tmp)


def xmss_node(sk_seed, i, z, pk_seed, adrs):  # Algorithm 9
    if z == 0:
        adrs.set_type_and_clear(WOTS_HASH)
        adrs.set_key_pair(i)
        return wots_pkgen(sk_seed, pk_seed, adrs)
    left = xmss_node(sk_seed, 2 * i, z - 1, pk_seed, adrs)
    right = xmss_node(sk_seed, 2 * i + 1, z - 1, pk_seed, adrs)
    adrs.set_type_and_clear(TREE)
    adrs.set_tree_height(z)
    adrs.set_tree_index(i)
    return Hn(pk_seed, adrs, left + right)


def xmss_sign(m, sk_seed, idx, pk_seed, adrs):  # Algorithm 10
    auth = [xmss_node(sk_seed, (idx >> j) ^ 1, j, pk_seed, adrs) for j in range(HP)]
    adrs.set_type_and_clear(WOTS_HASH)
    adrs.set_key_pair(idx)
    return wots_sign(m, sk_seed, pk_seed, adrs) + b"".join(auth)


def xmss_pk_from_sig(idx, sig, m, pk_seed, adrs):  # Algorithm 11
    adrs.set_type_and_clear(WOTS_HASH)
    adrs.set_key_pair(idx)
    node = wots_pk_from_sig(sig[:LEN * N], m, pk_seed, adrs)
    auth = sig[LEN * N:]
    adrs.set_type_and_clear(TREE)
    adrs.set_tree_index(idx)
    for k in range(HP):
        adrs.set_tree_height(k + 1)
        a = auth[k * N:(k + 1) * N]
        if (idx >> k) % 2 == 0:
            adrs.set_tree_index(adrs.tree_index() // 2)
            node = Hn(pk_seed, adrs, node + a)
        else:
            adrs.set_tree_index((adrs.tree_index() - 1) // 2)
            node = Hn(pk_seed, adrs, a + node)
    return node


def fors_skgen(sk_seed, pk_seed, adrs, idx):  # Algorithm 14
    sk_adrs = adrs.copy()
    sk_adrs.set_type_and_clear(FORS_PRF)
    sk_adrs.set_key_pair(adrs.key_pair())
    sk_adrs.set_tree_index(idx)
    return PRF(pk_seed, sk_seed, sk_adrs)


def fors_node(sk_seed, i, z, pk_seed, adrs):  # Algorithm 15
    if z == 0:
        sk = fors_skgen(sk_seed, pk_seed, adrs, i)
        adrs.set_tree_height(0)
        adrs.set_tree_index(i)
        return F(pk_seed, adrs, sk)
    left = fors_node(sk_seed, 2 * i, z - 1, pk_seed, adrs)
    right = fors_node(sk_seed, 2 * i + 1, z - 1, pk_seed, adrs)
    adrs.set_tree_height(z)
    adrs.set_tree_index(i)
    return Hn(pk_seed, adrs, left + right)


def fors_sign(md, sk_seed, pk_seed, adrs):  # Algorithm 16
    indices = base_2b(md, A, K)
    out = b""
    for i in range(K):
        out += fors_skgen(sk_seed, pk_seed, adrs, i * (1 << A) + indices[i])
        for j in range(A):
            s = (indices[i] >> j) ^ 1
            out += fors_node(sk_seed, i * (1 << (A - j)) + s, j, pk_seed, adrs)
    return out


def fors_pk_from_sig(sig, md, pk_seed, adrs, trace=None):  # Algorithm 17
    indices = base_2b(md, A, K)
    roots = []
    for i in range(K):
        sk = sig[i * (A + 1) * N:(i * (A + 1) + 1) * N]
        auth = sig[(i * (A + 1) + 1) * N:(i + 1) * (A + 1) * N]
        adrs.set_tree_height(0)
        adrs.set_tree_index(i * (1 << A) + indices[i])
        node = F(pk_seed, adrs, sk)
        for j in range(A):
            adrs.set_tree_height(j + 1)
            a = auth[j * N:(j + 1) * N]
            if (indices[i] >> j) % 2 == 0:
                adrs.set_tree_index(adrs.tree_index() // 2)
                node = Hn(pk_seed, adrs, node + a)
            else:
                adrs.set_tree_index((adrs.tree_index() - 1) // 2)
                node = Hn(pk_seed, adrs, a + node)
        roots.append(node)
    pk_adrs = adrs.copy()
    pk_adrs.set_type_and_clear(FORS_ROOTS)
    pk_adrs.set_key_pair(adrs.key_pair())
    if trace is not None:
        trace["fors_roots"] = [r.hex() for r in roots[:3]]
    return T(pk_seed, pk_adrs, roots)


def split_digest(digest):  # Algorithm 19, lines 6-10
    md_len = (K * A + 7) // 8
    tree_len = (H - HP + 7) // 8
    leaf_len = (HP + 7) // 8
    md = digest[:md_len]
    idx_tree = int.from_bytes(digest[md_len:md_len + tree_len], "big") % (1 << (H - HP))
    idx_leaf = int.from_bytes(digest[md_len + tree_len:md_len + tree_len + leaf_len], "big") % (1 << HP)
    return md, idx_tree, idx_leaf, (md_len, tree_len, leaf_len)


def ht_sign(m, sk_seed, pk_seed, idx_tree, idx_leaf):  # Algorithm 12
    adrs = Adrs()
    adrs.set_tree(idx_tree)
    sig = xmss_sign(m, sk_seed, idx_leaf, pk_seed, adrs)
    out = sig
    root = xmss_pk_from_sig(idx_leaf, sig, m, pk_seed, adrs)
    for j in range(1, D):
        idx_leaf = idx_tree % (1 << HP)
        idx_tree >>= HP
        adrs.set_layer(j)
        adrs.set_tree(idx_tree)
        sig = xmss_sign(root, sk_seed, idx_leaf, pk_seed, adrs)
        out += sig
        if j < D - 1:
            root = xmss_pk_from_sig(idx_leaf, sig, root, pk_seed, adrs)
    return out


def ht_verify(m, sig_ht, pk_seed, idx_tree, idx_leaf, pk_root, trace=None):  # Algorithm 13
    adrs = Adrs()
    adrs.set_tree(idx_tree)
    xlen = (HP + LEN) * N
    node = xmss_pk_from_sig(idx_leaf, sig_ht[:xlen], m, pk_seed, adrs)
    layers = [(0, idx_tree, idx_leaf, node.hex())]
    for j in range(1, D):
        idx_leaf = idx_tree % (1 << HP)
        idx_tree >>= HP
        adrs.set_layer(j)
        adrs.set_tree(idx_tree)
        node = xmss_pk_from_sig(idx_leaf, sig_ht[j * xlen:(j + 1) * xlen], node, pk_seed, adrs)
        layers.append((j, idx_tree, idx_leaf, node.hex()))
    if trace is not None:
        trace["layers"] = layers
    return node == pk_root


def keygen(sk_seed, sk_prf, pk_seed):  # Algorithm 18
    adrs = Adrs()
    adrs.set_layer(D - 1)
    return xmss_node(sk_seed, 0, HP, pk_seed, adrs)


def sign(msg, sk_seed, sk_prf, pk_seed, pk_root):  # Algorithm 19, deterministic
    r = PRF_msg(sk_prf, pk_seed, msg)
    digest = H_msg(r, pk_seed, pk_root, msg)
    md, idx_tree, idx_leaf, _ = split_digest(digest)
    adrs = Adrs()
    adrs.set_tree(idx_tree)
    adrs.set_type_and_clear(FORS_TREE)
    adrs.set_key_pair(idx_leaf)
    sig_fors = fors_sign(md, sk_seed, pk_seed, adrs)
    pk_fors = fors_pk_from_sig(sig_fors, md, pk_seed, adrs)
    return r + sig_fors + ht_sign(pk_fors, sk_seed, pk_seed, idx_tree, idx_leaf)


def verify(msg, sig, pk_seed, pk_root, trace):  # Algorithm 20
    if len(sig) != (1 + K * (1 + A) + H + D * LEN) * N:
        return False
    r = sig[:N]
    sig_fors = sig[N:(1 + K * (1 + A)) * N]
    sig_ht = sig[(1 + K * (1 + A)) * N:]
    digest = H_msg(r, pk_seed, pk_root, msg)
    md, idx_tree, idx_leaf, lens = split_digest(digest)
    trace.update(
        R=r.hex(), digest=digest.hex(), md=md.hex(), lens=lens,
        idx_tree=idx_tree, idx_leaf=idx_leaf, fors_indices=base_2b(md, A, K),
    )
    adrs = Adrs()
    adrs.set_tree(idx_tree)
    adrs.set_type_and_clear(FORS_TREE)
    adrs.set_key_pair(idx_leaf)
    pk_fors = fors_pk_from_sig(sig_fors, md, pk_seed, adrs, trace)
    digits, csum = wots_digits(pk_fors)
    trace.update(pk_fors=pk_fors.hex(), wots_digits=digits, wots_csum=csum)
    return ht_verify(pk_fors, sig_ht, pk_seed, idx_tree, idx_leaf, pk_root, trace)


def main():
    ex = json.load(open(sys.argv[1]))
    sk = bytes.fromhex(ex["sk"])
    sk_seed, sk_prf, pk_seed, pk_root = sk[:N], sk[N:2 * N], sk[2 * N:3 * N], sk[3 * N:]
    msg, ctx = bytes.fromhex(ex["msg"]), bytes.fromhex(ex["ctx"])
    m_prime = bytes([0, len(ctx)]) + ctx + msg  # Algorithm 22, line 8

    CALLS.clear()
    assert keygen(sk_seed, sk_prf, pk_seed) == pk_root, "PK.root mismatch"
    keygen_calls = dict(CALLS)

    CALLS.clear()
    sig = sign(m_prime, sk_seed, sk_prf, pk_seed, pk_root)
    sign_calls = dict(CALLS)
    assert sig.hex() == ex["sig"], "signature differs from slhsig"

    CALLS.clear()
    trace = {}
    assert verify(m_prime, sig, pk_seed, pk_root, trace)
    verify_calls = dict(CALLS)

    out = {
        "m_prime": m_prime.hex(),
        "keygen_calls": keygen_calls,
        "sign_calls": sign_calls,
        "verify_calls": verify_calls,
        **trace,
    }
    json.dump(out, sys.stdout, indent=1)
    print()


if __name__ == "__main__":
    main()
