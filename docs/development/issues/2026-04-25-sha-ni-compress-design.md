# SHA-NI compress — 2.9.3 design doc

**Status:** design — pre-implementation. No bytes hit `src/sha_ni.cyr` until this is signed off.

**Scope:** replace the `sha256_transform_ni` stub (returns -1) with a byte-encoded SHA-NI single-block compress so `sha256_transform`'s dispatcher (already wired in 2.9.2) actually accelerates SHA-256 on hosts where `sha_ni_available()` returns 1.

**Trust-boundary constraint (CLAUDE.md):** wrong opcode bytes in a SHA-256 transform produce digests that look right superficially but differ from the FIPS 180-4 spec. The whole module exists to be the trust boundary, so the verification gate (FIPS 180-4 vectors + cross-path NI vs software) must be in place *before* the asm flips from -1 to 0.

## Sources

- Intel SDM Vol 2A §3.2 (CPUID detection — already in 2.9.2)
- Intel SDM Vol 2A §5 — SHA256RNDS2 / SHA256MSG1 / SHA256MSG2 instruction descriptions
- Intel "Intel® SHA Extensions" whitepaper, Aug 2013 (Sean Gulley et al.) — the canonical reference compression sequence and the standard SoftwareDevelopersGuide-shaped sample code that every public implementation derives from
- FIPS 180-4 §6.2 — SHA-256 message schedule + compression function (the spec the result must match byte-for-byte)

## Instruction semantics — what each opcode actually does

```
SHA256RNDS2 xmm1, xmm2/m128, <XMM0>     0F 38 CB /r
    Two SHA-256 rounds.
    xmm1 = current CDGH state (4 dwords: [H, G, D, C] low→high)
    xmm2 = current ABEF state (4 dwords: [F, E, B, A] low→high)
    XMM0 = K+W broadcast — only LOW 64 bits used, two K+W values.
    Result written to xmm1 = new CDGH after 2 rounds.

SHA256MSG1 xmm1, xmm2/m128               0F 38 CC /r
    Intermediate message-schedule step:
    xmm1 holds W[i..i+3]; xmm2 holds W[i+4..i+7]
    Result xmm1 = W[i..i+3] + sigma0(W[i+1..i+4])
    where sigma0(x) = ROTR(x,7) XOR ROTR(x,18) XOR SHR(x,3).

SHA256MSG2 xmm1, xmm2/m128               0F 38 CD /r
    Final schedule step:
    xmm1 holds W[i..i+3] + sigma0(W[i+1..i+4]) + W[i+9..i+12]
    xmm2 holds W[i+12..i+15]
    Result xmm1 = next 4 schedule words W[i+16..i+19]
    (adds sigma1(W[i+14..i+17]) where sigma1(x) = ROTR(x,17) XOR ROTR(x,19) XOR SHR(x,10)).
```

Plus generic SSE/SSE2 ops we need:
```
MOVDQU  xmm, m128 / m128, xmm    F3 0F 6F /r ; F3 0F 7F /r
MOVDQA  xmm, m128                66 0F 6F /r
PSHUFB  xmm, m128                66 0F 38 00 /r
PSHUFD  xmm, m128, imm8          66 0F 70 /r ib
PADDD   xmm, m128                66 0F FE /r
PALIGNR xmm, m128, imm8          66 0F 3A 0F /r ib
PXOR    xmm, m128                66 0F EF /r   (already used in aes_ni.cyr)
PUNPCKLQDQ xmm, m128             66 0F 6C /r
PUNPCKHQDQ xmm, m128             66 0F 6D /r
PBLENDW xmm, m128, imm8          66 0F 3A 0E /r ib
```

We will use the disp32 ModR/M form (`/r` byte = `mod=10, reg=xmm_n, rm=base_reg`) for every memory operand to avoid the disp8/disp32 size-encoding traps.

## State-layout impedance: ctx vs XMM

This is the load-bearing detail and the highest-risk source of silent wrong digests if I get it wrong.

**Sigil ctx layout (sha256.cyr):**
```
ctx + 0   : h0   (8 bytes; 32-bit word in low 4 bytes via store64)
ctx + 8   : h1   (8 bytes)
...
ctx + 56  : h7   (8 bytes)
ctx + 64  : block buffer (64 bytes)
```

Total state: 8 × 8 = 64 bytes for h0..h7. The actual hash word is the LOW 32 bits of each 64-bit slot; high 32 bits are zero.

**SHA-NI XMM layout:**
```
STATE0 (ABEF): xmm holding 4 packed 32-bit dwords [F, E, B, A] (low dword → high dword)
STATE1 (CDGH): xmm holding 4 packed 32-bit dwords [H, G, D, C]
```

**A direct MOVDQU [ctx] would load [a, 0, b, 0]** — wrong. We need to pack the 8 sparse dwords into 8 packed dwords first.

### Mitigation: inline pack into stack scratch

At entry to `sha256_transform_ni` we write a 32-byte scratch buffer on the stack with:
```
[h0, h1, h2, h3, h4, h5, h6, h7]   (eight contiguous packed dwords)
```

via 8 `mov edx, [rdi + 8*i]` / `mov [rsp + 4*i], edx` pairs. Then MOVDQU the two halves into XMM. After the compress, write back: 8 `mov edx, [rsp + 4*i]` / `mov [rdi + 8*i], edx` (zero-extending; the top 32 bits of each 64-bit ctx slot stay zero because `mov edx, m32` zero-extends rdx implicitly under x86-64 — wait, no, `mov [m64], edx` stores 4 bytes only, leaves bytes 4..7 untouched. Since ctx slots are written with `store64` whose top half is already 0, this is fine.).

Actually safer: store64 writes 8 bytes including the zero top half on every block, so we need to either preserve that invariant or restore the zero high half. Easiest: keep using the original `store64` shape — write back via 8 `mov rdx, m32 (zero-extended)` / `mov [rdi + 8*i], rdx` pairs. That preserves the invariant. **Decision: write back as 64-bit zero-extended stores.**

Pack overhead per block: 8 small 32-bit moves on each side = 16 instructions. Compared to the ~70-instruction SHA-NI compress that replaces a ~200-instruction software round body, this is fine.

### Block-buffer layout

`ctx + 64` holds 64 bytes of message in big-endian dword order (FIPS 180-4 wire format). SHA-NI consumes message dwords with each in big-endian byte order in memory — but the XMM register holds them as packed *little-endian* dwords. So we MOVDQU the 16 bytes and PSHUFB with the BSWAP mask to get the dword values into native order.

**BSWAP_MASK** (16 bytes, in memory order):
```
0x03 0x02 0x01 0x00   ; reverse bytes of dword 0
0x07 0x06 0x05 0x04   ; reverse bytes of dword 1
0x0B 0x0A 0x09 0x08   ; reverse bytes of dword 2
0x0F 0x0E 0x0D 0x0C   ; reverse bytes of dword 3
```

Allocated once at module init, like `_sha_ni_probe_out`. Aligned naturally because `alloc()` returns 16-aligned blocks (per Cyrius 5.5.21+ array-global alignment fix).

## State setup — the standard Intel sequence

After packing ctx into a contiguous 32-byte buffer at scratch+0:
```
movdqu xmm6, [scratch + 0]       ; xmm6 = [h0, h1, h2, h3] = ABCD (a low → d high)
movdqu xmm7, [scratch + 16]      ; xmm7 = [h4, h5, h6, h7] = EFGH

pshufd xmm6, xmm6, 0xB1          ; 0xB1 = 10_11_00_01 → [B, A, D, C]
pshufd xmm7, xmm7, 0x1B          ; 0x1B = 00_01_10_11 → [H, G, F, E]
movdqa xmm5, xmm6                ; save copy
palignr xmm6, xmm7, 8            ; xmm6 = (xmm6:xmm7)>>64 = [F, E, B, A] = ABEF -> STATE0
pblendw xmm7, xmm5, 0xF0         ; xmm7 high-half from xmm5: [H, G, D, C] = CDGH -> STATE1
```

Encoding `0xB1 = 10_11_00_01`:
- dword0 ← src[01] = src dword 1 = B
- dword1 ← src[00] = src dword 0 = A
- dword2 ← src[11] = src dword 3 = D
- dword3 ← src[10] = src dword 2 = C
Result: [B, A, D, C] ✓

Encoding `0x1B = 00_01_10_11`:
- dword0 ← src[11] = H
- dword1 ← src[10] = G
- dword2 ← src[01] = F
- dword3 ← src[00] = E
Result: [H, G, F, E] ✓

PALIGNR with imm=8: result = ((xmm6:xmm7) >> 64)[127:0]
The high 128 bits are xmm6 = [B,A,D,C], low 128 bits are xmm7 = [H,G,F,E].
Shift right 64 bits: low 64 = xmm7 high 64 = [F, E]; high 64 = xmm6 low 64 = [B, A].
Result xmm6 = [F, E, B, A] = ABEF ✓

PBLENDW with imm=0xF0: top four 16-bit lanes (lanes 4..7) come from src (xmm5), bottom four (0..3) from dst (xmm7). That means high 64 bits ← xmm5 high 64 = [B,A]…wait.

xmm5 was the saved copy of `pshufd xmm6 0xB1` BEFORE the palignr. So xmm5 = [B, A, D, C].
xmm7 currently = [H, G, F, E].
After PBLENDW 0xF0: low 64 from xmm7 = [H, G]; high 64 from xmm5 = [D, C].
Wait — PBLENDW lane 4..7 are the *high* four 16-bit lanes = high 64 bits. xmm5's high 64 bits = [D, C] (dwords 2 and 3 = D, C).
Result xmm7 = [H, G, D, C] = CDGH ✓

Save copies for the final add:
```
movdqa xmm8, xmm6   ; ABEF_save
movdqa xmm9, xmm7   ; CDGH_save
```

Wait — sigil's environment may not preserve XMM8..15 across calls. Need to verify: this asm block is inside one `fn`, no calls, so register allocation is local. Using xmm0..xmm9 inside one asm block is fine. (The asm block is not re-entered or interrupted — it's a single straight-line sequence.)

Actually, simpler: save ABEF/CDGH back to scratch+32 / scratch+48 instead of into XMM regs we may not have. Decision deferred to Bite C — both work; saving to memory is more conservative.

## Compress loop — 16 message-schedule iterations × 4 rounds

64 SHA-256 rounds = 16 iterations of (4 rounds + 1 message-schedule step). Each iteration consumes one 16-byte K-block and one 16-byte W-block.

**Iterations 0..3** (no schedule extension yet — W comes from the message):
```
For i in 0..4:
    msg = pshufb(movdqu(block + 16*i), bswap_mask)   ; W[4i..4i+3]
    msg_save = msg                                   ; (saved as MSGi for schedule chain)
    msg = paddd(msg, [K + 16*i])                     ; K+W
    movdqa xmm0, msg                                 ; XMM0 holds K+W (low 64 bits used)
    sha256rnds2 STATE1, STATE0, <XMM0>               ; rounds 4i+0, 4i+1
    pshufd xmm0, xmm0, 0x0E                          ; high 64 bits → low 64
    sha256rnds2 STATE0, STATE1, <XMM0>               ; rounds 4i+2, 4i+3
    ; now STATE0 / STATE1 are swapped semantically — this is the standard ping-pong
    ; (next iter uses them in the opposite direction; the encoding handles this with the
    ;  argument order to sha256rnds2)
```

Wait — sha256rnds2 takes (xmm1=dst-and-CDGH, xmm2/m128=ABEF). If I do `sha256rnds2 STATE1, STATE0`, STATE1 becomes the new CDGH. Then for rounds 2..3, the new CDGH is STATE1, and ABEF should become the *previous* CDGH from before this round-pair. But after one RNDS2, the "old CDGH" is gone — STATE1 holds the new CDGH.

The standard trick: the SHA-NI compress alternates which register is "STATE0/ABEF" and which is "STATE1/CDGH" between round-pairs. After 2 rounds, the state has shifted: what was ABEF[0..3] = (A, B, E, F) becomes ABEF[2..3] = (C, D, G, H) of the new state. So the *new* CDGH is in STATE1, and the *new* ABEF is the *old* CDGH from one round-pair earlier.

The conventional encoding handles this by keeping an "even" and "odd" form of the loop body where the rnds2 argument order differs. Each iteration becomes:
```
; Round-pair "even" (rounds 0,1 — and 4,5 — and ...)
;   sha256rnds2 STATE1, STATE0, <XMM0>       ; STATE1 ← rounds based on (CDGH=STATE1, ABEF=STATE0)
; Round-pair "odd" (rounds 2,3 ...)
;   pshufd xmm0, xmm0, 0x0E
;   sha256rnds2 STATE0, STATE1, <XMM0>       ; STATE0 ← rounds based on (CDGH=STATE0, ABEF=STATE1)
```

After both round-pairs in one iteration, STATE0/STATE1 hold ABEF/CDGH of the *new* state correctly. The roles haven't actually flipped — they end up where they started naming-wise.

(This is the part most worth re-verifying against Intel's whitepaper code in Bite C — I'm working from semantic understanding here. If anything in the doc is wrong, this paragraph is the most likely culprit, and Bite B's cross-path test will catch it deterministically.)

**Iterations 4..15** (W comes from the message schedule):
```
; After the first 4 iterations, MSG0..MSG3 hold W[0..3], W[4..7], W[8..11], W[12..15].
; Iteration j (j=4..15):
;   tmp = palignr(MSGj_minus_1, MSGj_minus_2, 4)         ; xmm = W[i-7..i-4]
;   MSGj = paddd(MSGj_minus_4, tmp)                       ; W[i..i+3] + W[i-7..i-4]
;   MSGj = sha256msg2(MSGj, MSGj_minus_1)                 ; finishes the +sigma1 step
;   sha256msg1(MSGj_minus_4, MSGj_minus_3)                ; precomputes for next iter
;   ; (rounds:)
;   movdqa xmm0, MSGj
;   paddd xmm0, [K + 16*j]
;   sha256rnds2 STATE1, STATE0, <XMM0>
;   pshufd xmm0, xmm0, 0x0E
;   sha256rnds2 STATE0, STATE1, <XMM0>
```

Naming the four message regs as a rotating set across iterations means we use 4 XMMs for MSG0..MSG3 plus 2 for STATE0/STATE1 plus 1 for XMM0 plus 1 for the BSWAP_MASK = 8 XMMs (xmm0..xmm7). We can fit without dipping into xmm8..xmm15 — important if the compiler/runtime treats those as caller-saved across our asm block (it shouldn't, but staying low is safer).

**Final add:**
```
paddd STATE0, ABEF_save     ; new ABEF += saved
paddd STATE1, CDGH_save     ; new CDGH += saved

; Unpack STATE0=[F,E,B,A], STATE1=[H,G,D,C] back to [a,b,c,d,e,f,g,h] in scratch:
pshufd xmm6, STATE0, 0x1B    ; [A, B, E, F] — wait, 0x1B reverses: [src[3], src[2], src[1], src[0]] = [A, B, E, F]
pshufd xmm7, STATE1, 0xB1    ; [C, D, G, H]? Let's verify: 0xB1 = 10_11_00_01 → [src[1], src[0], src[3], src[2]]
                              ; src[1]=G, src[0]=H, src[3]=C, src[2]=D → [G, H, C, D]. That's not CDGH.
```

I need to re-derive the unpack. Goal: scratch[0..3] = [a, b, c, d] (low to high dwords), scratch[4..7] = [e, f, g, h].

STATE0 = [F, E, B, A]  →  ABCD = [A, B, _, _]
STATE1 = [H, G, D, C]  →  ABCD = [_, _, C, D]
EFGH from STATE0 = [_, _, E, F] (high dwords); from STATE1 = [G, H, _, _] (low dwords).

We want:
- ABCD_packed = [A, B, C, D] (low→high)
- EFGH_packed = [E, F, G, H]

Permutations:
- PSHUFD STATE0 with 0x1B: 0x1B = 00_01_10_11 → [src[3], src[2], src[1], src[0]] = [A, B, E, F]
- PSHUFD STATE1 with 0x1B → [C, D, G, H]
- PUNPCKLQDQ tmp_AB_EF, tmp_CD_GH: low quad of each = [A,B] and [C,D] → [A, B, C, D] = ABCD ✓
- PUNPCKHQDQ tmp_AB_EF, tmp_CD_GH: high quad of each = [E,F] and [G,H] → [E, F, G, H] = EFGH ✓

Or simpler:
```
pshufd xmm6, STATE0, 0x1B          ; xmm6 = [A, B, E, F]
pshufd xmm7, STATE1, 0x1B          ; xmm7 = [C, D, G, H]
movdqa xmm8, xmm6
punpcklqdq xmm6, xmm7              ; xmm6 = [A, B, C, D]
punpckhqdq xmm8, xmm7              ; xmm8 = [E, F, G, H]
movdqu [scratch + 0], xmm6
movdqu [scratch + 16], xmm8
```

Then unpack scratch[0..7] back to ctx h0..h7 with 8 zero-extended-quadword stores.

## Encoding plan

We will byte-encode every opcode using:
- `0xF3 0x0F 0x6F /r` for MOVDQU load
- `0xF3 0x0F 0x7F /r` for MOVDQU store
- `0x66 0x0F 0x6F /r` for MOVDQA load
- `0x66 0x0F 0x70 /r ib` for PSHUFD
- `0x66 0x0F 0x38 0x00 /r` for PSHUFB
- `0x66 0x0F 0x3A 0x0F /r ib` for PALIGNR
- `0x66 0x0F 0x3A 0x0E /r ib` for PBLENDW
- `0x66 0x0F 0xFE /r` for PADDD
- `0x66 0x0F 0x6C /r` for PUNPCKLQDQ
- `0x66 0x0F 0x6D /r` for PUNPCKHQDQ
- `0x0F 0x38 0xCB /r` for SHA256RNDS2 (XMM0 implicit)
- `0x0F 0x38 0xCC /r` for SHA256MSG1
- `0x0F 0x38 0xCD /r` for SHA256MSG2

ModR/M for memory operands: `mod=10` (disp32), `reg=xmm_n`, `rm=base_reg_id`. For RDI base, rm=7. For RSP base with disp, we need a SIB byte (rsp/r12 special case): rm=4 + SIB byte 0x24 (scale=00, index=100 (none), base=100 (rsp)).

For register-register operand: `mod=11`, `reg=dst`, `rm=src`.

Disp32 immediates encoded LSB-first.

Each opcode in the final asm block will get:
- A comment with the disassembly
- The byte sequence
- A reference to the SDM table that pinned the encoding

## Stack frame

Function takes `ctx` only, so prologue: `[rbp-8] = ctx`. We need ~64 bytes of stack scratch:
- `[rsp+0..31]`  — packed state in/out (8 dwords)
- `[rsp+32..47]` — ABEF_save
- `[rsp+48..63]` — CDGH_save

Allocate by `sub rsp, 64`, align to 16 (ABI keeps rsp 16-aligned at function entry — rbp prologue may have shifted; we'll re-align with `and rsp, -16` at the top of the asm block). Restore with `mov rsp, rbp` / `pop rbp` style at the bottom — actually simpler: stash old rsp in a callee-saved reg (rbx, push it first), align, do work, restore from stashed rsp.

**Decision deferred to Bite C:** verify exact stack discipline by reading the aes_ni.cyr asm block again and matching its conventions. AES-NI doesn't need stack scratch (operates in-place on caller buffers), so this is genuinely new territory for sigil. Worst-case fallback: allocate the scratch buffers as module-level globals at init time (like `_sha_ni_probe_out`), one per call site — simpler stack discipline, slightly worse cache locality.

**Recommendation: use module globals.** Sigil is single-threaded today; the scratch buffer can be a module-level alloc. This sidesteps the stack-alignment question entirely and matches the precedent set by `_sha_ni_probe_out` and `_sha_ni_cache`. Cost: one extra cache line per process. Benefit: zero stack discipline complexity, no alignment-and-restore dance.

## Test plan (lands in Bite B, before any asm flips)

`tests/tcyr/sha_ni.tcyr` grows to:

1. **Probe still works** (existing — keep)
2. **Stub contract flips** — change expectation from -1 to 0 (deferred to Bite C; Bite B leaves it expecting -1 still so software-only tests pass)
3. **FIPS 180-4 vectors via dispatcher** — software-path (force `_sha_ni_cache=0`):
   - empty string → `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`
   - "abc" → `ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad` (already covered, keep)
   - "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" (56 bytes, two-block) → `248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1`
   - 1KB of `0x61` → `2edc986847e209b4016e141a6dc8716d3207350f416969382d431539bf292e4a` (computed offline, will verify with python in Bite B)
   - 64KB of `0x61` → digest computed offline, will verify in Bite B
4. **Cross-path equality** — for each of 64B / 1KB / 64KB inputs:
   - Hash via dispatcher with `_sha_ni_cache=0` → digest_sw
   - Reset, hash with `_sha_ni_cache=1` → digest_ni
   - `assert_eq(bytes_eq(digest_sw, digest_ni, 32), 1)`
   - Skipped if `sha_ni_available()` returns 0 (host has no SHA-NI)

## Verification gates

| Bite | Gate | Pass criterion |
|------|------|----------------|
| A | This doc | Robert signs off |
| B | `cyrius test tests/tcyr/sha_ni.tcyr` | All assertions pass with stub still returning -1; cross-path test gated on probe and currently a no-op |
| B | `cyrius test` (full suite) | All existing tests still pass |
| C | `cyrius test tests/tcyr/sha_ni.tcyr` | Stub-contract flips to 0; FIPS vectors AND cross-path test pass; on a SHA-NI-less host the cross-path test skips cleanly |
| C | `cyrius test` (full suite) | All passing |
| D | `cyrius bench` SHA-256 rows on this host | NI strictly faster than software at 1KB and 64KB; identical digests verified by C |
| E | `rm -rf build && cyrius deps && cyrius build` | Clean build |

## Open questions for Bite C

1. **SHA256RNDS2 register-argument order** — verify `xmm1 = CDGH (dst)` vs `xmm1 = ABEF` against SDM Vol 2A §5 instruction page directly before encoding. The doc above states "xmm1 = CDGH" per Intel whitepaper convention; double-check on the SDM page.
2. **PSHUFD encoding** — verify `0x66 0x0F 0x70 /r ib` is the correct opcode (vs PSHUFLW 0xF2 0F 70 / PSHUFHW 0xF3 0F 70). Triple-check against SDM §3.2 PSHUFD page.
3. **Stack vs globals for scratch** — the doc recommends globals; final call in Bite C.
4. **Can Cyrius's `asm { ... }` block survive ~80 instructions?** AES-NI's block is ~30 bytes; SHA-NI compress will be ~400+ bytes of opcodes. Verify no fixup-table cap issue (per CLAUDE.md: cap is 16384 bytes, well above what we need; per-block cap concerns exist but unlikely to bite at this size).

## Deferred (out of scope for 2.9.3)

- ARMv8 SHA2 hardware path (separate bite when AGNOS targets ARM)
- SHA-NI multi-block compress (process N blocks in one call) — gives a bigger win but requires re-shaping `sha256_update`'s call site; scope creep
- Software-path micro-optimizations
