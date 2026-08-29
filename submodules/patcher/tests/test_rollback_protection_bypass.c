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

static UINT32 encode_add_x_imm(UINT8 rd, UINT16 imm) {
    return 0x91000000u | ((UINT32)imm << 10) | ((UINT32)rd << 5) | rd;
}

static UINT32 encode_b_cond(INT32 from, INT32 to, UINT8 cond) {
    INT32 imm19 = (to - from) >> 2;
    return 0x54000000u | (((UINT32)imm19 & 0x7ffffu) << 5) | cond;
}

static UINT32 encode_b(INT32 from, INT32 to) {
    INT32 imm26 = (to - from) >> 2;
    return 0x14000000u | ((UINT32)imm26 & 0x03ffffffu);
}

static void put_scm_call(CHAR8* buf, INT32 off, UINT32 mov_id,
                         UINT32 movk_id, BOOLEAN include_context_load) {
    INT32 vtable_load = off + 20;

    put32(buf, off, mov_id);
    put32(buf, off + 4, 0x910003e3);  /* ADD X3,SP,#0 */
    put32(buf, off + 8, 0x910003e4);  /* ADD X4,SP,#0 */
    put32(buf, off + 12, movk_id);
    put32(buf, off + 16, 0x2a1f03e2); /* MOV W2,WZR */
    if (include_context_load) {
        put32(buf, vtable_load, 0xf9406d00); /* LDR X0,[X8,#0xd8] */
        vtable_load += 4;
    }
    put32(buf, vtable_load, 0xf9401c08);     /* LDR X8,[X0,#0x38] */
    put32(buf, vtable_load + 4, 0xd63f0100); /* BLR X8 */
    put32(buf, vtable_load + 8, 0xb4000100); /* CBZ X0,ok */
}

static void make_fixture(CHAR8* buf, INT32 delta, BOOLEAN include_legacy_scm,
                         BOOLEAN include_context_load) {
    const INT32 compare_off = delta + 0x1100;
    const INT32 compare_branch_off = compare_off + 4;
    const INT32 compare_ok_off = compare_off + 0x40;
    const INT32 compare_xref = compare_off + 0x24;
    const INT32 compare_string = delta + 0x1800;
    const INT32 write_fn = delta + 0x1200;
    const INT32 write_xref = write_fn + 0x1c;
    const INT32 write_string = delta + 0x1880;
    const INT32 scm_ab = delta + 0x1400;
    const INT32 scm_legacy = delta + 0x1440;

    make_prefixed_pe(buf, delta);

    put_cstr(buf, compare_string,
             ": Image rollback index is less than the stored rollback index.");
    put32(buf, compare_off, 0xeb0c011f); /* CMP X8, X12 */
    put32(buf, compare_branch_off,
          encode_b_cond(compare_branch_off, compare_ok_off, 2)); /* B.CS */
    put32(buf, compare_xref, 0x90000006); /* ADRP X6, same page */
    put32(buf, compare_xref + 4, encode_add_x_imm(6, 0x800));

    put_cstr(buf, write_string,
             "WriteRollbackIndex Location %d, RollbackIndex %d");
    put32(buf, write_fn, 0xd503233f);     /* PACIASP */
    put32(buf, write_fn + 4, 0xd100c3ff); /* SUB SP,SP,#0x30 */
    put32(buf, write_xref, 0x90000001);   /* ADRP X1, same page */
    put32(buf, write_xref + 4, encode_add_x_imm(1, 0x880));

    put_scm_call(buf, scm_ab, 0x52802201, 0x72a64001,
                 include_context_load);

    if (include_legacy_scm) {
        put_scm_call(buf, scm_legacy, 0x528023c1, 0x72a04001,
                     include_context_load);
    }
}

int main(void) {
    const INT32 delta = 0x80;
    const INT32 compare_branch_off = delta + 0x1104;
    const INT32 compare_ok_off = delta + 0x1140;
    const INT32 write_fn = delta + 0x1200;
    const INT32 scm_ab_blr = delta + 0x1418;
    const INT32 scm_legacy_blr = delta + 0x1458;
    const INT32 context_scm_ab_blr = delta + 0x141c;
    const INT32 context_scm_legacy_blr = delta + 0x145c;
    CHAR8 complete[0x3000] = {0};
    CHAR8 context_load[0x3000] = {0};
    CHAR8 incomplete[0x3000] = {0};

    make_fixture(complete, delta, TRUE, FALSE);
    if (patch_rollback_protection_bypass(complete, sizeof(complete)) != 4)
        return 1;
    if (read_instr(complete, compare_branch_off)
        != encode_b(compare_branch_off, compare_ok_off))
        return 2;
    if (read_instr(complete, write_fn) != 0x2a1f03e0
        || read_instr(complete, write_fn + 4) != 0xd65f03c0)
        return 3;
    if (read_instr(complete, scm_ab_blr) != 0xaa1f03e0
        || read_instr(complete, scm_legacy_blr) != 0xaa1f03e0)
        return 4;

    make_fixture(context_load, delta, TRUE, TRUE);
    if (patch_rollback_protection_bypass(context_load,
                                         sizeof(context_load)) != 4)
        return 5;
    if (read_instr(context_load, context_scm_ab_blr) != 0xaa1f03e0
        || read_instr(context_load, context_scm_legacy_blr) != 0xaa1f03e0)
        return 6;

    make_fixture(incomplete, delta, FALSE, FALSE);
    if (patch_rollback_protection_bypass(incomplete, sizeof(incomplete)) != 0)
        return 7;
    if (read_instr(incomplete, compare_branch_off)
        != encode_b_cond(compare_branch_off, compare_ok_off, 2))
        return 8;

    return 0;
}
