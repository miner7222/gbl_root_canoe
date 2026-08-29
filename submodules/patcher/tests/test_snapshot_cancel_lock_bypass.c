#include "../patchlib.h"

static void put32(CHAR8* buf, INT32 off, UINT32 raw) {
    buf[off] = (CHAR8)(raw & 0xff);
    buf[off + 1] = (CHAR8)((raw >> 8) & 0xff);
    buf[off + 2] = (CHAR8)((raw >> 16) & 0xff);
    buf[off + 3] = (CHAR8)((raw >> 24) & 0xff);
}

static void put_cstr(CHAR8* buf, INT32 off, const CHAR8* s) {
    while (*s) buf[off++] = *s++;
    buf[off] = 0;
}

static void make_prefixed_pe(CHAR8* buf, INT32 delta) {
    buf[delta] = 'M';
    buf[delta + 1] = 'Z';
    put32(buf, delta + 0x3c, 0x40);
    buf[delta + 0x40] = 'P';
    buf[delta + 0x41] = 'E';
}

static UINT32 encode_cbz_w(INT32 from, INT32 to, UINT8 rt) {
    INT32 imm19 = (to - from) >> 2;
    return 0x34000000u | (((UINT32)imm19 & 0x7ffffu) << 5) | rt;
}

static UINT32 encode_add_x_imm(UINT8 rd, UINT16 imm) {
    return 0x91000000u | ((UINT32)imm << 10) | ((UINT32)rd << 5) | rd;
}

int main(void) {
    const INT32 delta = 0x80;
    const INT32 gate = delta + 0x1200;
    const INT32 error_block = delta + 0x12a0;
    const INT32 xref = error_block + 0x10;
    const INT32 message = delta + 0x1800;
    CHAR8 complete[0x3000] = {0};
    CHAR8 incomplete[0x3000] = {0};
    CHAR8 compact[0x3000] = {0};

    make_prefixed_pe(complete, delta);
    put_cstr(complete, message,
             "Snapshot Cancel is not allowed in Lock State");
    put32(complete, gate, encode_cbz_w(gate, error_block, 8));
    put32(complete, error_block, 0x90000009);     /* ADRP X9 */
    put32(complete, error_block + 4, 0xf9402fe8); /* LDR X8,[SP,#0x58] */
    put32(complete, error_block + 8, 0x94000100); /* BL */
    put32(complete, error_block + 12, 0x54000161);/* B.NE */
    put32(complete, xref, 0x90000000);            /* ADRP X0 */
    put32(complete, xref + 4, encode_add_x_imm(0, 0x800));

    if (patch_snapshot_cancel_lock_bypass(complete, sizeof(complete)) != 1)
        return 1;
    if (read_instr(complete, gate) != NOP)
        return 2;

    make_prefixed_pe(incomplete, delta);
    put_cstr(incomplete, message,
             "Snapshot Cancel is not allowed in Lock State");
    put32(incomplete, gate, encode_cbz_w(gate, error_block, 8));
    put32(incomplete, error_block + 8, 0x94000100);
    put32(incomplete, error_block + 12, 0x54000161);
    put32(incomplete, xref, 0x90000000);
    put32(incomplete, xref + 4, encode_add_x_imm(0, 0x800));

    if (patch_snapshot_cancel_lock_bypass(incomplete, sizeof(incomplete)) != 0)
        return 3;
    if (read_instr(incomplete, gate) == NOP)
        return 4;

    make_prefixed_pe(compact, delta);
    put_cstr(compact, message,
             "Snapshot Cancel is not allowed in Lock State");
    const INT32 compact_gate = delta + 0x1900;
    const INT32 compact_state = delta + 0x1a00;
    const INT32 compact_xref = compact_state + 8;
    put32(compact, compact_gate, encode_cbz_w(compact_gate, compact_state, 8));
    put32(compact, compact_state, 0x94000100);     /* BL */
    put32(compact, compact_state + 4, 0x54000161); /* B.NE */
    put32(compact, compact_xref, 0x90000000);      /* ADRP X0 */
    put32(compact, compact_xref + 4, encode_add_x_imm(0, 0x800));

    if (patch_snapshot_cancel_lock_bypass(compact, sizeof(compact)) != 1)
        return 5;
    if (read_instr(compact, compact_gate) != NOP)
        return 6;

    return 0;
}
