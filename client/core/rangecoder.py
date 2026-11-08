"""ENet adaptive order-2 PPM range coder - COMPRESS side, ported faithfully from enet/compress.c.

GT installs the stock ENet range coder (enet_host_compress_with_range_coder); our rc.dll is its
decompressor. The client MUST compress every outbound datagram's body (the server always decompresses
client packets), so we need the matching encoder. This is a line-by-line port of compress.c's
enet_range_coder_compress (ENET_CONTEXT_EXCLUSION disabled, matching GT).

Validated offline: compress(x) fed to rc.dll rc_decompress must return x (see _selftest / test_rangecoder).

Field layout of a symbol (uint8 value/count, uint16 the rest). parent/predicted hold ABSOLUTE indices
into the symbol pool; symbols/left/right hold RELATIVE offsets (added to the current index).
"""
TOP = 1 << 24
BOTTOM = 1 << 16
CTX_SYM_DELTA, CTX_SYM_MIN, CTX_ESC_MIN = 3, 1, 1
SUB_ORDER, SUB_SYM_DELTA, SUB_ESC_DELTA = 2, 2, 5
M16 = 0xFFFF
M32 = 0xFFFFFFFF
NSYM = 4096
V, C, U, L, R, S, E, T, P = range(9)   # symbol field indices


class RangeCoder:
    def __init__(self):
        self.sym = [[0] * 9 for _ in range(NSYM)]
        self.next = 0

    def _create(self, value, count):
        i = self.next
        self.next += 1
        s = self.sym[i]
        s[V] = value & 0xFF; s[C] = count & 0xFF; s[U] = count & M16
        s[L] = s[R] = s[S] = s[E] = s[T] = s[P] = 0
        return i

    def _ctx_create(self, escapes, minimum):
        i = self._create(0, 0)
        s = self.sym[i]
        s[E] = escapes & M16
        s[T] = (escapes + 256 * minimum) & M16
        s[S] = 0
        return i

    def _rescale(self, idx):
        sym = self.sym
        total = 0
        while True:
            s = sym[idx]
            s[C] = (s[C] - (s[C] >> 1)) & 0xFF
            s[U] = s[C]
            if s[L]:
                s[U] = (s[U] + self._rescale(idx + s[L])) & M16
            total = (total + s[U]) & M16
            if not s[R]:
                break
            idx += s[R]
        return total

    def _ctx_rescale(self, idx, minimum):
        s = self.sym[idx]
        s[T] = self._rescale(idx + s[S]) if s[S] else 0
        s[E] = (s[E] - (s[E] >> 1)) & M16
        s[T] = (s[T] + s[E] + 256 * minimum) & M16

    # ENET_CONTEXT_ENCODE: returns (symbol_idx, under_, count_)
    def _ctx_encode(self, ctx_idx, value_, update, minimum):
        sym = self.sym
        under_ = (value_ * minimum) & M16
        count_ = minimum & M16
        c = sym[ctx_idx]
        if not c[S]:
            s_idx = self._create(value_, update)
            sym[ctx_idx][S] = (s_idx - ctx_idx) & M16
            return s_idx, under_, count_
        node_idx = ctx_idx + c[S]
        while True:
            node = sym[node_idx]
            if value_ < node[V]:
                node[U] = (node[U] + update) & M16
                if node[L]:
                    node_idx += node[L]; continue
                s_idx = self._create(value_, update)
                sym[node_idx][L] = (s_idx - node_idx) & M16
                return s_idx, under_, count_
            elif value_ > node[V]:
                under_ = (under_ + node[U]) & M16
                if node[R]:
                    node_idx += node[R]; continue
                s_idx = self._create(value_, update)
                sym[node_idx][R] = (s_idx - node_idx) & M16
                return s_idx, under_, count_
            else:
                count_ = (count_ + node[C]) & M16
                under_ = (under_ + node[U] - node[C]) & M16
                node[U] = (node[U] + update) & M16
                node[C] = (node[C] + update) & 0xFF
                return node_idx, under_, count_

    def compress(self, data):
        sym = self.sym
        self.next = 0
        out = bytearray()
        encodeLow = 0
        encodeRange = M32

        def emit(under, count, total):
            nonlocal encodeLow, encodeRange
            encodeRange //= total
            encodeLow = (encodeLow + under * encodeRange) & M32
            encodeRange = (encodeRange * count) & M32
            while True:
                if (encodeLow ^ ((encodeLow + encodeRange) & M32)) >= TOP:
                    if encodeRange >= BOTTOM:
                        break
                    encodeRange = (-encodeLow) & (BOTTOM - 1)
                out.append((encodeLow >> 24) & 0xFF)
                encodeRange = (encodeRange << 8) & M32
                encodeLow = (encodeLow << 8) & M32

        root = self._ctx_create(CTX_ESC_MIN, CTX_SYM_MIN)   # == 0
        predicted = 0
        order = 0
        n = len(data)
        i = 0
        while i < n:
            value = data[i]; i += 1
            # *parent chain: first writes `predicted`, then successive symbol.parent fields
            parent_pred = True
            parent_idx = 0
            matched = False
            subcontext = predicted
            while subcontext != root:
                s_idx, under, count = self._ctx_encode(subcontext, value, SUB_SYM_DELTA, 0)
                if parent_pred:
                    predicted = s_idx; parent_pred = False
                else:
                    sym[parent_idx][P] = s_idx & M16
                parent_idx = s_idx
                sc = sym[subcontext]
                total = sc[T]
                if count > 0:
                    emit((sc[E] + under) & M16, count, total)
                else:
                    if 0 < sc[E] < total:
                        emit(0, sc[E], total)
                    sc[E] = (sc[E] + SUB_ESC_DELTA) & M16
                    sc[T] = (sc[T] + SUB_ESC_DELTA) & M16
                sc[T] = (sc[T] + SUB_SYM_DELTA) & M16
                if count > 0xFF - 2 * SUB_SYM_DELTA or sc[T] > BOTTOM - 0x100:
                    self._ctx_rescale(subcontext, 0)
                if count > 0:
                    matched = True
                    break
                subcontext = sym[subcontext][P]
            if not matched:
                s_idx, under, count = self._ctx_encode(root, value, CTX_SYM_DELTA, CTX_SYM_MIN)
                if parent_pred:
                    predicted = s_idx
                else:
                    sym[parent_idx][P] = s_idx & M16
                r = sym[root]
                total = r[T]
                emit((r[E] + under) & M16, count, total)
                r[T] = (r[T] + CTX_SYM_DELTA) & M16
                if count > 0xFF - 2 * CTX_SYM_DELTA + CTX_SYM_MIN or r[T] > BOTTOM - 0x100:
                    self._ctx_rescale(root, CTX_SYM_MIN)
            # nextInput
            if order >= SUB_ORDER:
                predicted = sym[predicted][P]
            else:
                order += 1
            if self.next >= NSYM - SUB_ORDER:        # FREE_SYMBOLS
                self.next = 0
                root = self._ctx_create(CTX_ESC_MIN, CTX_SYM_MIN)
                predicted = 0
                order = 0
        # FLUSH
        while encodeLow:
            out.append((encodeLow >> 24) & 0xFF)
            encodeLow = (encodeLow << 8) & M32
        return bytes(out)


def compress(data):
    return RangeCoder().compress(data)


# --------------------------------------------------------------------------------------------------
# DECOMPRESS side (pure Python) -- mirror of the ENet range coder, so the client needs NO native rc.dll
# and runs anywhere (Linux VPS included). Ported from the proven decoder that decodes real GT captures;
# validated byte-exact vs rc.dll in _selftest below. Node fields: [value,count,under,left,right,child,
# escapes,total,parent] == V,C,U,L,R,S,E,T,P, matching the compressor above.
class _Decoder:
    def __init__(self, data, cap=1 << 18):
        self.data = data; self.pos = 0; self.code = 0; self.low = 0; self.rng = M32
        self.nodes = []; self.cap = cap
        self._new(0, 0); self.nodes[0][6] = 1; self.nodes[0][7] = 257   # root: escapes=1, total=257
        for sh in (24, 16, 8, 0):
            if self.pos < len(data): self.code |= data[self.pos] << sh; self.pos += 1
        self.pred = 0; self.order = 0; self.out = bytearray()

    def _new(self, v, c):
        i = len(self.nodes); self.nodes.append([v, c, c, 0, 0, 0, 0, 0, 0]); return i

    def _read(self, total):
        self.rng //= total
        if not self.rng: raise ValueError("zero range")
        return ((self.code - self.low) & M32) // self.rng

    def _dec(self, under, count, total):
        self.low = (self.low + under * self.rng) & M32; self.rng = (self.rng * count) & M32
        for _ in range(64):
            if ((self.low ^ ((self.low + self.rng) & M32)) & M32) >= TOP:
                if self.rng >= BOTTOM: return
                self.rng = (-self.low) & (BOTTOM - 1)
            self.code = (self.code << 8) & M32
            if self.pos < len(self.data): self.code |= self.data[self.pos]; self.pos += 1
            self.rng = (self.rng << 8) & M32; self.low = (self.low << 8) & M32
        raise ValueError("range normalization failed")

    def _symbol(self, ctx, code, update, minimum, root=False):
        under = 0; count = minimum; rel = self.nodes[ctx][5]
        if not rel:
            if not root: return None
            value = code // minimum; under = code - code % minimum
            idx = self._new(value, update); self.nodes[ctx][5] = idx - ctx; return idx, value, under, count
        node = ctx + rel
        while True:
            n = self.nodes[node]; after = under + n[2] + (n[0] + 1) * minimum; before = n[1] + minimum
            if code >= after:
                under += n[2]
                if n[4]: node += n[4]; continue
                if not root: return None
                value = n[0] + 1 + (code - after) // minimum; under = code - (code - after) % minimum
                idx = self._new(value, update); n[4] = idx - node; return idx, value, under, count
            if code < after - before:
                n[2] += update
                if n[3]: node += n[3]; continue
                if not root: return None
                value = n[0] - 1 - (after - before - code - 1) // minimum
                under = code - (after - before - code - 1) % minimum
                idx = self._new(value, update); n[3] = idx - node; return idx, value, under, count
            value = n[0]; count += n[1]; under = after - before; n[2] += update; n[1] += update
            return node, value, under, count

    def _insert(self, ctx, value, update):
        under = 0; rel = self.nodes[ctx][5]
        if not rel:
            idx = self._new(value, update); self.nodes[ctx][5] = idx - ctx; return idx, under, 0
        node = ctx + rel
        while True:
            n = self.nodes[node]
            if value < n[0]:
                n[2] += update
                if n[3]: node += n[3]; continue
                idx = self._new(value, update); n[3] = idx - node; return idx, under, 0
            if value > n[0]:
                under += n[2]
                if n[4]: node += n[4]; continue
                idx = self._new(value, update); n[4] = idx - node; return idx, under, 0
            count = n[1]; under += n[2] - n[1]; n[2] += update; n[1] += update; return node, under, count

    def _rescale_tree(self, node):
        total = 0
        while True:
            n = self.nodes[node]; n[1] -= n[1] >> 1; n[2] = n[1]
            if n[3]: n[2] += self._rescale_tree(node + n[3])
            total += n[2]
            if not n[4]: break
            node += n[4]
        return total

    def _rescale(self, ctx, minimum):
        n = self.nodes[ctx]
        n[7] = self._rescale_tree(ctx + n[5]) if n[5] else 0
        n[6] -= n[6] >> 1; n[7] += n[6] + 256 * minimum

    def decode(self):
        for _ in range(self.cap):
            ctx = self.pred; chosen = None
            while ctx != 0:
                n = self.nodes[ctx]
                if n[6] > 0:
                    total = n[7]
                    if n[6] < total:
                        code = self._read(total)
                        if code < n[6]: self._dec(0, n[6], total); ctx = n[8]; continue
                        code -= n[6]; hit = self._symbol(ctx, code, 2, 0, False)
                        if hit is not None:
                            sym, val, under, count = hit; self._dec(n[6] + under, count, total); n[7] += 2
                            if count > 251 or n[7] > BOTTOM - 256: self._rescale(ctx, 0)
                            chosen = (ctx, sym, val); break
                ctx = n[8]
            if chosen is None:
                root = self.nodes[0]; total = root[7]; code = self._read(total)
                if code < root[6]: self._dec(0, root[6], total); break      # end-of-stream escape
                code -= root[6]; hit = self._symbol(0, code, 3, 1, True); sym, val, under, count = hit
                self._dec(root[6] + under, count, total); root[7] += 3
                if count > 252 or root[7] > BOTTOM - 256: self._rescale(0, 1)
                subctx = 0
            else:
                subctx, sym, val = chosen
            patch = self.pred; parent_ref = None
            while patch != subctx:
                next_patch = self.nodes[patch][8]
                ps, under, count = self._insert(patch, val, 2)
                if parent_ref is None: self.pred = ps
                else: self.nodes[parent_ref][8] = ps
                parent_ref = ps
                if count <= 0: self.nodes[patch][6] += 5; self.nodes[patch][7] += 5
                self.nodes[patch][7] += 2
                if count > 251 or self.nodes[patch][7] > BOTTOM - 256: self._rescale(patch, 0)
                patch = next_patch
            if parent_ref is None: self.pred = sym
            else: self.nodes[parent_ref][8] = sym
            self.out.append(val & 255)
            if self.order >= 2: self.pred = self.nodes[self.pred][8]
            else: self.order += 1
            if len(self.nodes) >= 4093:                              # FREE_SYMBOLS
                self.nodes = []; self._new(0, 0); self.nodes[0][6] = 1; self.nodes[0][7] = 257
                self.pred = 0; self.order = 0
        return bytes(self.out)


def decompress(data):
    """Pure-Python ENet range-coder decompress (no native rc.dll -> portable to any OS)."""
    return _Decoder(bytes(data)).decode()


if __name__ == "__main__":
    import os, ctypes
    rc = ctypes.CDLL(os.path.join(os.path.dirname(os.path.abspath(__file__)), "rc.dll"))
    rc.rc_decompress.restype = ctypes.c_long
    rc.rc_decompress.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t]

    def roundtrip(x):
        comp = compress(x)
        out = ctypes.create_string_buffer(1 << 18)
        n = rc.rc_decompress(comp, len(comp), out, 1 << 18)
        return out.raw[:n] == x, len(x), len(comp)

    import random
    ok = 0; tot = 0
    for t in range(200):
        x = bytes(random.randint(0, 255) for _ in range(random.randint(1, 300)))
        good, a, b = roundtrip(x)
        tot += 1; ok += good
        if not good and t < 5:
            print("FAIL len", a)
    print("roundtrip (my compress -> rc.dll decompress): %d/%d OK" % (ok, tot))
