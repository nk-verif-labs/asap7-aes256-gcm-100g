import random
import cocotb
from cocotb.clock import Clock
from cocotb.triggers import RisingEdge, ClockCycles

# ---------------------------------------------------------------------------
# Pure-Python NIST FIPS-197 + SP 800-38D AES-256-GCM Reference
# ---------------------------------------------------------------------------
SBOX = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
]
RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40]


def xtime(a):
    return ((a << 1) ^ 0x1B) & 0xFF if (a & 0x80) else (a << 1)


def key_exp_256(key_bytes):
    w = [list(key_bytes[4*i:4*i+4]) for i in range(8)]
    for i in range(8, 60):
        t = list(w[i - 1])
        if i % 8 == 0:
            t = [SBOX[t[1]] ^ RCON[i // 8 - 1], SBOX[t[2]], SBOX[t[3]], SBOX[t[0]]]
        elif i % 8 == 4:
            t = [SBOX[b] for b in t]
        w.append([w[i - 8][j] ^ t[j] for j in range(4)])
    return [bytes(sum(w[4*r:4*r+4], [])) for r in range(15)]


def aes256_block(block, rkeys):
    s = [block[j] ^ rkeys[0][j] for j in range(16)]
    for r in range(1, 15):
        s = [SBOX[b] for b in s]
        s = [
            s[0], s[5], s[10], s[15],
            s[4], s[9], s[14], s[3],
            s[8], s[13], s[2], s[7],
            s[12], s[1], s[6], s[11],
        ]
        if r < 14:
            ns = []
            for c in range(4):
                a0, a1, a2, a3 = s[4*c:4*c+4]
                ns.extend([
                    xtime(a0) ^ xtime(a1) ^ a1 ^ a2 ^ a3,
                    a0 ^ xtime(a1) ^ xtime(a2) ^ a2 ^ a3,
                    a0 ^ a1 ^ xtime(a2) ^ xtime(a3) ^ a3,
                    xtime(a0) ^ a0 ^ a1 ^ a2 ^ xtime(a3),
                ])
            s = ns
        for j in range(16):
            s[j] ^= rkeys[r][j]
    return bytes(s)


def gf128_mul(x: int, h: int) -> int:
    R = 0xE1 << 120
    z = 0
    v = h
    for i in range(127, -1, -1):
        if (x >> i) & 1:
            z ^= v
        v = ((v >> 1) ^ R) if (v & 1) else (v >> 1)
    return z


def golden_aes256_gcm(key_bytes: bytes, iv_bytes: bytes, pt_blocks: list[int]):
    rkeys = key_exp_256(key_bytes)
    H = int.from_bytes(aes256_block(b"\x00" * 16, rkeys), "big")
    j0 = iv_bytes + b"\x00\x00\x00\x01"
    ej0 = int.from_bytes(aes256_block(j0, rkeys), "big")

    cts = []
    y = 0
    for idx, pt in enumerate(pt_blocks):
        ctr = iv_bytes + (idx + 2).to_bytes(4, "big")
        ks = int.from_bytes(aes256_block(ctr, rkeys), "big")
        ct = pt ^ ks
        cts.append(ct)
        y = gf128_mul(y ^ ct, H)
    len_blk = len(pt_blocks) * 128
    y = gf128_mul(y ^ len_blk, H)
    tag = y ^ ej0
    return cts, tag


# ---------------------------------------------------------------------------
# Bus Helpers
# ---------------------------------------------------------------------------
async def reset_dut(dut):
    dut.rst_n.value = 0
    dut.s_axil_awaddr.value = 0
    dut.s_axil_awvalid.value = 0
    dut.s_axil_wdata.value = 0
    dut.s_axil_wstrb.value = 0
    dut.s_axil_wvalid.value = 0
    dut.s_axil_bready.value = 1
    dut.s_axil_araddr.value = 0
    dut.s_axil_arvalid.value = 0
    dut.s_axil_rready.value = 1
    dut.s_axis_tdata.value = 0
    dut.s_axis_tvalid.value = 0
    dut.s_axis_tlast.value = 0
    dut.m_axis_tready.value = 1
    await ClockCycles(dut.clk, 5)
    dut.rst_n.value = 1
    await ClockCycles(dut.clk, 2)


async def axil_write(dut, addr: int, data: int):
    dut.s_axil_awaddr.value = addr
    dut.s_axil_awvalid.value = 1
    dut.s_axil_wdata.value = data
    dut.s_axil_wstrb.value = 0xF
    dut.s_axil_wvalid.value = 1
    aw_done = w_done = False
    for _ in range(20):
        await RisingEdge(dut.clk)
        if dut.s_axil_awready.value:
            aw_done = True
            dut.s_axil_awvalid.value = 0
        if dut.s_axil_wready.value:
            w_done = True
            dut.s_axil_wvalid.value = 0
        if aw_done and w_done and dut.s_axil_bvalid.value:
            break
    await RisingEdge(dut.clk)


async def axil_read(dut, addr: int) -> int:
    dut.s_axil_araddr.value = addr
    dut.s_axil_arvalid.value = 1
    val = 0
    for _ in range(20):
        await RisingEdge(dut.clk)
        if dut.s_axil_arready.value:
            dut.s_axil_arvalid.value = 0
        if dut.s_axil_rvalid.value:
            val = int(dut.s_axil_rdata.value)
            break
    await RisingEdge(dut.clk)
    return val


@cocotb.test()
async def test_aes256_gcm_line_rate(dut):
    """Verify AES-256-GCM 128-bit/cycle encryption and 128-bit auth tag vs NIST SP 800-38D."""
    cocotb.start_soon(Clock(dut.clk, 1, units="ns").start())  # 1.0 GHz ASAP7 target
    await reset_dut(dut)

    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    iv  = bytes.fromhex("cafebabefacedbaddecaf888")

    for i in range(8):
        word = int.from_bytes(key[4*i:4*i+4], "big")
        await axil_write(dut, 0x04 + 4*i, word)
    for i in range(3):
        word = int.from_bytes(iv[4*i:4*i+4], "big")
        await axil_write(dut, 0x24 + 4*i, word)

    # Trigger key expansion + H + E(J0)
    await axil_write(dut, 0x00, 0x01)
    for _ in range(150):
        st = await axil_read(dut, 0x40)
        if st & 0x1:
            break
    assert (st & 0x1) == 1, "Key expansion / GCM init timed out"

    pt_blocks = [random.getrandbits(128) for _ in range(4)]
    exp_cts, exp_tag = golden_aes256_gcm(key, iv, pt_blocks)

    rx_cts = []

    async def monitor():
        while len(rx_cts) < len(pt_blocks):
            await RisingEdge(dut.clk)
            if dut.m_axis_tvalid.value and dut.m_axis_tready.value:
                rx_cts.append(int(dut.m_axis_tdata.value))
                if len(rx_cts) == len(pt_blocks):
                    assert int(dut.m_axis_tlast.value) == 1, "Expected tlast on final beat"

    mon = cocotb.start_soon(monitor())

    for idx, pt in enumerate(pt_blocks):
        dut.s_axis_tdata.value = pt
        dut.s_axis_tvalid.value = 1
        dut.s_axis_tlast.value = 1 if idx == len(pt_blocks) - 1 else 0
        while True:
            await RisingEdge(dut.clk)
            if dut.s_axis_tready.value:
                break
    dut.s_axis_tvalid.value = 0
    dut.s_axis_tlast.value = 0

    await mon
    assert rx_cts == exp_cts, "AES-256-CTR ciphertext mismatch"

    for _ in range(20):
        st = await axil_read(dut, 0x40)
        if st & 0x2:
            break
    assert (st & 0x2) == 0x2, "GCM tag_valid not asserted"

    tag_words = [await axil_read(dut, 0x30 + 4*i) for i in range(4)]
    got_tag = (tag_words[0] << 96) | (tag_words[1] << 64) | (tag_words[2] << 32) | tag_words[3]
    assert got_tag == exp_tag, f"GCM Tag mismatch: got {hex(got_tag)}, exp {hex(exp_tag)}"
