#include "types.h"

#include "arm64_inst_decoder.h"

typedef enum { LOC_REG, LOC_STK64, LOC_STK8 } DataLocType;

typedef struct {
    DataLocType type;
    INT32 val;
} DataLoc;

typedef struct {
    DataLoc locs[256];
    INT32 count;
} LocSet;

static BOOLEAN locset_has(const LocSet* s, DataLoc l) {
    for (INT32 i = 0; i < s->count; ++i)
        if (s->locs[i].type == l.type && s->locs[i].val == l.val) return TRUE;
    return FALSE;
}
static BOOLEAN locset_has_reg  (const LocSet* s, INT8 r)   { return locset_has(s, (DataLoc){LOC_REG, r}); }
static BOOLEAN locset_has_stk64(const LocSet* s, UINT32 v) { return locset_has(s, (DataLoc){LOC_STK64, (INT32)v}); }
static BOOLEAN locset_has_stk8 (const LocSet* s, UINT32 v) { return locset_has(s, (DataLoc){LOC_STK8, (INT32)v}); }

static void locset_add(LocSet* s, DataLoc l) {
    if (!locset_has(s, l) && s->count < 256) s->locs[s->count++] = l;
}
static void locset_add_reg  (LocSet* s, INT8 r)   { locset_add(s, (DataLoc){LOC_REG, r}); }
static void locset_add_stk64(LocSet* s, UINT32 v) { locset_add(s, (DataLoc){LOC_STK64, (INT32)v}); }
static void locset_add_stk8 (LocSet* s, UINT32 v) { locset_add(s, (DataLoc){LOC_STK8, (INT32)v}); }

static void locset_del(LocSet* s, DataLoc l) {
    for (INT32 i = 0; i < s->count; ++i) {
        if (s->locs[i].type == l.type && s->locs[i].val == l.val) {
            s->locs[i] = s->locs[s->count - 1];
            s->count--;
            return;
        }
    }
}
static void locset_del_reg  (LocSet* s, INT8 r)   { locset_del(s, (DataLoc){LOC_REG, r}); }
static void locset_del_stk64(LocSet* s, UINT32 v) { locset_del(s, (DataLoc){LOC_STK64, (INT32)v}); }
static void locset_del_stk8 (LocSet* s, UINT32 v) { locset_del(s, (DataLoc){LOC_STK8, (INT32)v}); }

static BOOLEAN locset_empty(const LocSet* s) { return s->count == 0; }

static void locset_print(const LocSet* s) {
    if (s->count == 0) {
        Print_patcher("WARRNING: LocSet empty, using fallback. Will Match any LDRB\n");
        return;
    }
    Print_patcher("  LocSet{");
    for (INT32 i = 0; i < s->count; ++i) {
        if (i) Print_patcher(", ");
        switch (s->locs[i].type) {
            case LOC_REG:   Print_patcher("W%d", s->locs[i].val); break;
            case LOC_STK64: Print_patcher("[SP+0x%X]/64", s->locs[i].val); break;
            case LOC_STK8:  Print_patcher("[SP+0x%X]/8",  s->locs[i].val); break;
        }
    }
    Print_patcher("}\n");
}

/* 判断一条指令是否为 STRB 或 32-bit STR W，并提取字段 */
typedef struct {
    BOOLEAN valid;
    UINT8   rt;
    UINT8   rn;
    UINT32  imm;
    UINT8   size;   /* 1 = STRB, 4 = STR W */
} StoreInfo;

/* legacy alias */
typedef StoreInfo StrbInfo;

static StoreInfo decode_any_store(UINT32 raw) {
    StoreInfo info = { FALSE, 0, 0, 0, 0 };
    DecodedInst d;
    memset(&d, 0, sizeof(d));

    if (decode_inst_strb_imm(raw, &d)) {
        info.valid = TRUE; info.rt = d.rt; info.rn = d.rn; info.imm = d.imm; info.size = 1;
    } else if (decode_inst_strb_post(raw, &d)) {
        info.valid = TRUE; info.rt = d.rt; info.rn = d.rn; info.imm = (UINT32)d.simm & 0x1FF; info.size = 1;
    } else if (decode_inst_strb_pre(raw, &d)) {
        info.valid = TRUE; info.rt = d.rt; info.rn = d.rn; info.imm = (UINT32)d.simm & 0x1FF; info.size = 1;
    } else if (decode_inst_str_w_imm(raw, &d)) {
        info.valid = TRUE; info.rt = d.rt; info.rn = d.rn; info.imm = d.imm; info.size = 4;
    }
    return info;
}

/* Fallback (locset empty) sink acceptance check.
 *
 * Without bounds, the first store after anchor may land on unrelated
 * code (loop scratch on stack, lookup table iteration counters, etc.).
 * Reject obvious non-sinks:
 *   1. distance: within FALLBACK_MAX_BYTES of anchor
 *   2. base register: not SP (real sink writes to a context struct field)
 *   3. offset range: typical device-state field sits at 0x100..0x800
 */
#define FALLBACK_MAX_BYTES 0x40
#define FALLBACK_MIN_FIELD_OFF 0x100
#define FALLBACK_MAX_FIELD_OFF 0x800

static BOOLEAN fallback_sink_acceptable(StoreInfo si, INT32 off, INT32 anchor_off) {
    if (off - anchor_off > FALLBACK_MAX_BYTES) return FALSE;
    if (si.rn == 31) return FALSE;
    if (si.imm < FALLBACK_MIN_FIELD_OFF || si.imm > FALLBACK_MAX_FIELD_OFF) return FALSE;
    return TRUE;
}

INT32 patch_abl_gbl(CHAR8* buffer, INT32 size) {
    CHAR8 target[]      = { 'e',0, 'f',0, 'i',0, 's',0, 'p',0 };
    CHAR8 replacement[] = { 'n',0, 'u',0, 'l',0, 'l',0, 's',0 };
    INT32 target_len = sizeof(target);
    for (INT32 i = 0; i < size - target_len; ++i) {
        if (memcmp_patcher(buffer + i, target, target_len) == 0) {
            memcpy_patcher(buffer + i, replacement, target_len);
            return 0;
        }
    }
    return -1;
}

INT16 Original[] = {
    -1, 0x00, 0x00, 0x34, 0x28, 0x00, 0x80, 0x52,
    0x06, 0x00, 0x00, 0x14, 0xE8, -1, 0x40, 0xF9,
    0x08, 0x01, 0x40, 0x39, 0x1F, 0x01, 0x00, 0x71,
    0xE8, 0x07, 0x9F, 0x1A, 0x08, 0x79, 0x1F, 0x53
};
INT16 Patched[] = {
    -1, -1, -1, -1, 0x08, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1
};

INT32 patch_abl_bootstate(CHAR8* buffer, INT32 size,
                          INT8* lock_register_num, INT32* offset) {
    INT32 pattern_len = sizeof(Original) / sizeof(INT16);
    INT32 patched_count = 0;
    if (size < pattern_len) return 0;
    for (INT32 i = 0; i <= size - pattern_len; ++i) {
        BOOLEAN match = TRUE;
        for (INT32 j = 0; j < pattern_len; ++j) {
            if (Original[j] != -1 && (UINT8)buffer[i + j] != (UINT8)Original[j]) {
                match = FALSE; break;
            }
        }
        if (match) {
            *lock_register_num = (INT8)((UINT8)buffer[i] & 0x1F);
            *offset = i;
            #ifndef DISABLE_PATCH_3
            for (INT32 j = 0; j < pattern_len; ++j)
                if (Patched[j] != -1) buffer[i + j] = (char)Patched[j];
            #endif
            patched_count++;
            i += pattern_len - 1;
        }
    }
    return patched_count;
}

static INT32 track_forward_patch_strb(CHAR8* buffer, INT32 size, INT32 ldrb_off,
                                      INT8 src_reg, INT32 anchor_off) {
    LocSet set;
    set.count = 0;
    locset_add_reg(&set, src_reg);

    Print_patcher("\n=== Forward tracking from LDRB@0x%X (W%d), anchor=0x%X ===\n",
           ldrb_off, (int)src_reg, anchor_off);
    locset_print(&set);

    for (INT32 off = ldrb_off + 4; off < size - 4; off += 4) {
        DecodedInst d = decode_at(buffer, off);

        if (d.type == INST_PACIASP) {
            Print_patcher("0x%X: function boundary, stop\n", off);
            break;
        }

        switch (d.type) {

        /* ---- STR Xt, [SP, #imm] 64-bit spill ---- */
        case INST_STR_X_IMM:
            if (d.rn == 31) {
                if (locset_has_reg(&set, (INT8)d.rt)) {
                    Print_patcher("  0x%X: STR X%d,[SP,#0x%X] spill64\n", off, d.rt, d.imm);
                    locset_add_stk64(&set, d.imm);
                    locset_print(&set);
                } else if (locset_has_stk64(&set, d.imm)) {
                    Print_patcher("  0x%X: STR X%d,[SP,#0x%X] overwrite stk64 -> del\n", off, d.rt, d.imm);
                    locset_del_stk64(&set, d.imm);
                    locset_print(&set);
                }
            }
            break;

        /* ---- LDR Xt, [SP, #imm] 64-bit reload ---- */
        case INST_LDR_X_IMM:
            if (d.rn == 31) {
                if (locset_has_stk64(&set, d.imm)) {
                    Print_patcher("  0x%X: LDR X%d,[SP,#0x%X] reload64\n", off, d.rt, d.imm);
                    locset_add_reg(&set, (INT8)d.rt);
                    locset_print(&set);
                } else if (locset_has_reg(&set, (INT8)d.rt)) {
                    Print_patcher("  0x%X: LDR X%d,[SP,#0x%X] overwrite reg -> del\n", off, d.rt, d.imm);
                    locset_del_reg(&set, (INT8)d.rt);
                    locset_print(&set);
                }
            }
            break;

        /* INST_STR_W_IMM SP-spill handling moved into the unified case below. */

        /* ---- LDR Wt, [SP, #imm] 32-bit reload ---- */
        case INST_LDR_W_IMM:
            if (d.rn == 31) {
                if (locset_has_stk64(&set, d.imm)) {
                    Print_patcher("  0x%X: LDR W%d,[SP,#0x%X] reload32\n", off, d.rt, d.imm);
                    locset_add_reg(&set, (INT8)d.rt);
                    locset_print(&set);
                } else if (locset_has_reg(&set, (INT8)d.rt)) {
                    Print_patcher("  0x%X: LDR W%d,[SP,#0x%X] overwrite reg -> del\n", off, d.rt, d.imm);
                    locset_del_reg(&set, (INT8)d.rt);
                    locset_print(&set);
                }
            }
            break;

        /* ---- LDRB Wt, [Xn, #imm] — 外部内存覆写寄存器 ---- */
        case INST_LDRB_IMM:
            if (locset_has_reg(&set, (INT8)d.rt)) {
                Print_patcher("  0x%X: LDRB W%d,[X%d,#0x%X] overwrite reg -> del\n",
                       off, d.rt, d.rn, d.imm);
                locset_del_reg(&set, (INT8)d.rt);
                locset_print(&set);
            }
            break;

        /* ---- MOV Xd, Xm ---- */
        case INST_MOV_X:
            if (locset_has_reg(&set, (INT8)d.rm) && d.rt != 31) {
                Print_patcher("  0x%X: MOV X%d,X%d propagate\n", off, d.rt, d.rm);
                locset_add_reg(&set, (INT8)d.rt);
                locset_print(&set);
            } else if (locset_has_reg(&set, (INT8)d.rt)) {
                Print_patcher("  0x%X: MOV X%d,X%d overwrite -> del\n", off, d.rt, d.rm);
                locset_del_reg(&set, (INT8)d.rt);
                locset_print(&set);
            }
            break;

        /* ---- MOV Wd, Wm ---- */
        case INST_MOV_W:
            if (locset_has_reg(&set, (INT8)d.rm) && d.rt != 31) {
                Print_patcher("  0x%X: MOV W%d,W%d propagate\n", off, d.rt, d.rm);
                locset_add_reg(&set, (INT8)d.rt);
                locset_print(&set);
            } else if (locset_has_reg(&set, (INT8)d.rt)) {
                Print_patcher("  0x%X: MOV W%d,W%d overwrite -> del\n", off, d.rt, d.rm);
                locset_del_reg(&set, (INT8)d.rt);
                locset_print(&set);
            }
            break;

        /* ---- STRB / STR W (所有形式) ----
         * Boot-state field may be 1 byte (STRB) or 4 bytes (STR W).
         * Fallback path is gated by fallback_sink_acceptable to avoid
         * patching unrelated stores after the anchor.
         */
        case INST_STRB_IMM:
        case INST_STRB_POST:
        case INST_STRB_PRE:
        case INST_STR_W_IMM: {
            StoreInfo si = decode_any_store(d.raw);
            BOOLEAN tracked = si.valid && locset_has_reg(&set, (INT8)si.rt);
            BOOLEAN fallback = si.valid && locset_empty(&set) && off > anchor_off
                               && fallback_sink_acceptable(si, off, anchor_off);
            if (tracked || fallback) {
                if (off > anchor_off) {
                    #ifndef DISABLE_PRINT
                    const CHAR8* mnem = (si.size == 1) ? "STRB" : "STR ";
                    if (si.rn == 31) {
                        Print_patcher("  0x%X: %s W%d,[SP,#0x%X] ** SINK (after anchor0x%X)%s **\n",
                        off, mnem, si.rt, si.imm, anchor_off, fallback ? " [fallback]" : "");
                    } else {
                        Print_patcher("  0x%X: %s W%d,[X%d,#0x%X] ** SINK (after anchor0x%X)%s **\n",
                        off, mnem, si.rt, si.rn, si.imm, anchor_off, fallback ? " [fallback]" : "");
                    }
                    #endif
                    Print_patcher("  Before: %02X %02X %02X %02X\n",
                           (UINT8)buffer[off], (UINT8)buffer[off+1],
                           (UINT8)buffer[off+2], (UINT8)buffer[off+3]);

                    /* Rt is bits[0:4] for both STRB and STR W, so the
                     * STRB rewrite helper applies unchanged. */
                    write_instr(buffer, off, strb_with_reg(d.raw, 31));

                    Print_patcher("  After : %02X %02X %02X %02X (Rt -> WZR)\n",
                           (UINT8)buffer[off], (UINT8)buffer[off+1],
                           (UINT8)buffer[off+2], (UINT8)buffer[off+3]);
                    return 1;
                } else if (si.size == 1) {
                    Print_patcher("  0x%X: STRB W%d,[X%d,#0x%X] before anchor -> spill8\n",
                           off, si.rt, si.rn, si.imm);
                    if (si.rn == 31) locset_add_stk8(&set, si.imm);
                    locset_print(&set);
                } else if (si.size == 4 && si.rn == 31) {
                    /* 32-bit spill tracked via stk64 slot (no stk32 category) */
                    Print_patcher("  0x%X: STR W%d,[SP,#0x%X] before anchor -> spill32\n",
                           off, si.rt, si.imm);
                    locset_add_stk64(&set, si.imm);
                    locset_print(&set);
                }
            } else if (si.valid && si.size == 1 && si.rn == 31
                       && locset_has_stk8(&set, si.imm)) {
                Print_patcher("  0x%X: STRB W%d,[SP,#0x%X] overwrite stk8 -> del\n",
                       off, si.rt, si.imm);
                locset_del_stk8(&set, si.imm);
            } else if (si.valid && si.size == 4 && si.rn == 31
                       && locset_has_stk64(&set, si.imm)) {
                Print_patcher("  0x%X: STR W%d,[SP,#0x%X] overwrite stk -> del\n",
                       off, si.rt, si.imm);
                locset_del_stk64(&set, si.imm);
            }
            break;
        }

        default:
            break;
        }
    }

    Print_patcher("Forward tracking: no sink STRB found after anchor 0x%X\n", anchor_off);
    return -1;
}
//
INT32 source_callback(CHAR8* buffer, INT32 size, INT32 now_offset, INT8 current_target, INT32 anchor_offset) {
    Print_patcher("  Before: %02X %02X %02X %02X\n",
        (UINT8)buffer[now_offset], (UINT8)buffer[now_offset+1],
        (UINT8)buffer[now_offset+2], (UINT8)buffer[now_offset+3]);
    #ifndef DISABLE_PATCH_4
    write_instr(buffer, now_offset, encode_movz_w((UINT8)current_target, 1));
    Print_patcher("  After : %02X %02X %02X %02X (MOV W%d, #1)\n",
        (UINT8)buffer[now_offset], (UINT8)buffer[now_offset+1],
        (UINT8)buffer[now_offset+2], (UINT8)buffer[now_offset+3],
        (int)current_target);
    #endif
    #ifndef DISABLE_PATCH_5
    INT32 fwd = track_forward_patch_strb(buffer, size, now_offset, current_target, anchor_offset);
    if (fwd <= 0) {
        Print_patcher("Warning: sink STRB not found after anchor 0x%X\n", anchor_offset);
        return -1;
    }
    Print_patcher("Sink patched successfully.\n");
    #endif
    return 0;
}
#define KEYMASTER_UNLOCK_SINK_MAX_BYTES 0x400
#define KEYMASTER_UNLOCK_STACK_OFF      0x60
#define KEYMASTER_COLOR_STACK_OFF       0x64

static BOOLEAN is_stp_w_sp_imm(UINT32 raw, UINT32 imm) {
    if ((raw & 0xFFC00000u) != 0x29000000u) return FALSE;
    if (((raw >> 5) & 0x1Fu) != 31) return FALSE;

    INT32 imm7 = (INT32)((raw >> 15) & 0x7F);
    if (imm7 & 0x40) imm7 |= ~0x7F;
    return (UINT32)(imm7 << 2) == imm;
}

static BOOLEAN has_keymaster_unlock_context(CHAR8* buffer, INT32 size, INT32 off) {
    INT32 end = off + 0x40;
    if (end > size - 4) end = size - 4;

    for (INT32 i = off + 4; i <= end; i += 4) {
        if (is_stp_w_sp_imm(read_instr(buffer, i), KEYMASTER_COLOR_STACK_OFF))
            return TRUE;
    }
    return FALSE;
}

INT32 patch_keymaster_unlock_sink(CHAR8* buffer, INT32 size, INT32 anchor_off) {
    if (anchor_off < 0 || anchor_off >= size - 4) return 0;

    INT32 patched = 0;
    INT32 end = anchor_off + KEYMASTER_UNLOCK_SINK_MAX_BYTES;
    if (end > size - 4) end = size - 4;

    for (INT32 off = anchor_off + 4; off <= end; off += 4) {
        DecodedInst d = decode_at(buffer, off);
        if (d.type != INST_STRB_IMM) continue;
        if (d.rn != 31 || d.imm != KEYMASTER_UNLOCK_STACK_OFF) continue;
        if (!has_keymaster_unlock_context(buffer, size, off)) continue;

        Print_patcher("KeyMaster unlock sink @ 0x%X: STRB W%d,[SP,#0x%X]\n",
                      off, d.rt, d.imm);
        Print_patcher("  Before: %02X %02X %02X %02X\n",
                      (UINT8)buffer[off], (UINT8)buffer[off+1],
                      (UINT8)buffer[off+2], (UINT8)buffer[off+3]);
        write_instr(buffer, off, strb_with_reg(d.raw, 31));
        Print_patcher("  After : %02X %02X %02X %02X (Rt -> WZR)\n",
                      (UINT8)buffer[off], (UINT8)buffer[off+1],
                      (UINT8)buffer[off+2], (UINT8)buffer[off+3]);
        patched++;
    }
    return patched;
}

//定义 callback 函数类型
typedef INT32 (*SourceCallback)(CHAR8* buffer, INT32 size, INT32 now_offset, INT8 current_target, INT32 anchor_offset);
/* ============================================================
 *  第十二部分：反向找 LDRB 源头
 * ============================================================ */
INT32 find_ldrB_instructio_reverse(CHAR8* buffer, INT32 size,
                                   INT32 anchor_offset, INT8 target_register, SourceCallback callback) {
    INT32 now_offset = anchor_offset - 4;
    INT8 current_target = target_register;
    INT32 bounce_count = 0;
    const INT32 MAX_BOUNCES = 8;

    while (now_offset >= 0) {
        DecodedInst d = decode_at(buffer, now_offset);

        if (d.type == INST_PACIASP) {
            Print_patcher("Reached function start at 0x%X\n", now_offset);
            break;
        }

        /* ---- 64-bit 栈 reload 弹跳 ---- */
        if (d.type == INST_LDR_X_IMM && d.rn == 31 && (INT8)d.rt == current_target) {
            UINT32 spill_imm = d.imm;
            Print_patcher("Bounce at 0x%X: LDR X%d,[SP,#0x%X]\n",
                   now_offset, (int)current_target, spill_imm);
            INT32 search = now_offset - 4;
            BOOLEAN found = FALSE;
            while (search >= 0) {
                DecodedInst ds = decode_at(buffer, search);
                if (ds.type == INST_PACIASP) break;
                if (ds.type == INST_STR_X_IMM && ds.rn == 31 && ds.imm == spill_imm) {
                    Print_patcher("  -> STR X%d,[SP,#0x%X] at 0x%X\n",
                           (INT32)ds.rt, spill_imm, search);
                    current_target = (INT8)ds.rt;
                    now_offset = search - 4;
                    found = TRUE;
                    bounce_count++;
                    break;
                }
                search -= 4;
            }
            if (!found) { Print_patcher("  -> No matching STR, abort\n"); return -1; }
            if (bounce_count > MAX_BOUNCES) { Print_patcher("Too many bounces\n"); return -1; }
            continue;
        }

        /* ---- byte 级栈 reload 弹跳 ---- */
        if (d.type == INST_LDRB_IMM && d.rn == 31 && (INT8)d.rt == current_target) {
            UINT32 byte_imm = d.imm;
            Print_patcher("Byte bounce at 0x%X: LDRB W%d,[SP,#0x%X]\n",
                   now_offset, (int)current_target, byte_imm);
            INT32 search = now_offset - 4;
            BOOLEAN found = FALSE;
            while (search >= 0) {
                DecodedInst ds = decode_at(buffer, search);
                if (ds.type == INST_PACIASP) break;
                if (ds.type == INST_STRB_IMM && ds.rn == 31 && ds.imm == byte_imm) {
                    Print_patcher("  -> STRB W%d,[SP,#0x%X] at 0x%X\n",
                           (INT32)ds.rt, byte_imm, search);
                    current_target = (INT8)ds.rt;
                    now_offset = search - 4;
                    found = TRUE;
                    bounce_count++;
                    break;
                }
                search -= 4;
            }
            if (!found) { Print_patcher("  -> No matching STRB, abort\n"); return -1; }
            if (bounce_count > MAX_BOUNCES) { Print_patcher("Too many bounces\n"); return -1; }
            continue;
        }

        /* ---- 真正源头: LDRB W{current_target}, [Xn!=SP, #imm] ---- */
        if (d.type == INST_LDRB_IMM && (INT8)d.rt == current_target && d.rn != 31) {
            Print_patcher("Found source LDRB at 0x%X: LDRB W%d,[X%d,#0x%X](%d bounces)\n",
                   now_offset, d.rt, d.rn, d.imm, bounce_count);
            return callback(buffer, size, now_offset, current_target, anchor_offset);
        }

        now_offset -= 4;
    }
    return -1;
}

static BOOLEAN str_at(const CHAR8* buffer, INT32 size, INT64 file_off, const CHAR8* needle) {
    if (file_off < 0) return FALSE;
    INT32 len = strlen(needle);
    if ((INT32)file_off + len >= size) return FALSE;
    return memcmp_patcher(buffer + file_off, needle, len) == 0;
}

static UINT32 read_u32_unaligned(const CHAR8* buffer, INT32 off) {
    return (UINT8)buffer[off]
         | ((UINT8)buffer[off+1] << 8)
         | ((UINT8)buffer[off+2] << 16)
         | ((UINT8)buffer[off+3] << 24);
}

static UINT64 read_u64_unaligned(const CHAR8* buffer, INT32 off) {
    UINT64 v = 0;
    for (INT32 i = 0; i < 8; ++i)
        v |= ((UINT64)(UINT8)buffer[off + i]) << (i * 8);
    return v;
}

static INT32 detect_pe_image_delta(const CHAR8* buffer, INT32 size) {
    static const CHAR8* cached_buffer = 0;
    static INT32 cached_size = 0;
    static INT32 cached_delta = 0;

    if (cached_buffer == buffer && cached_size == size)
        return cached_delta;

    cached_buffer = buffer;
    cached_size = size;
    cached_delta = 0;

    if (size < 0x44)
        return 0;

    INT32 limit = size - 0x44;
    if (limit > 0x1000) limit = 0x1000;

    for (INT32 off = 0; off <= limit; ++off) {
        if (buffer[off] != 'M' || buffer[off + 1] != 'Z')
            continue;

        UINT32 pe_rel = read_u32_unaligned(buffer, off + 0x3c);
        INT64 pe_sig = (INT64)off + (INT64)pe_rel;
        if (pe_sig < 0 || pe_sig + 4 > size)
            continue;

        if (buffer[pe_sig] == 'P'
            && buffer[pe_sig + 1] == 'E'
            && buffer[pe_sig + 2] == 0
            && buffer[pe_sig + 3] == 0) {
            cached_delta = off;
            return cached_delta;
        }
    }

    return 0;
}

static INT64 calc_adrl_file_offset(const CHAR8* buffer, INT32 size,
                                   INT32 adrp_off, UINT64 load_base) {
    DecodedInst d0 = decode_at(buffer, adrp_off);
    DecodedInst d1 = decode_at(buffer, adrp_off + 4);

    if (d0.type != INST_ADRP) return -1;
    if (d1.type != INST_ADD_X_IMM) return -1;
    if (d1.rt != d0.rt || d1.rn != d0.rt) return -1;

    INT32 image_delta = detect_pe_image_delta(buffer, size);
    INT64 image_off = (INT64)adrp_off - image_delta;
    if (image_off < 0) return -1;

    UINT64 pc      = load_base + (UINT64)image_off;
    UINT64 page_pc = pc & ~0xFFFull;
    UINT64 target_va = (UINT64)((INT64)page_pc + d0.simm) + d1.imm;
    return (INT64)(target_va - load_base) + image_delta;
}

INT32 patch_adrl_unlocked_to_locked(CHAR8* buffer, INT32 size, UINT64 load_base) {
    if (size < 24) return 0;
    INT32 patched = 0;

    for (INT32 i = 0; i <= size - 24; i += 4) {
        DecodedInst a0 = decode_at(buffer, i);
        DecodedInst a1 = decode_at(buffer, i + 4);
        DecodedInst b0 = decode_at(buffer, i + 8);
        DecodedInst b1 = decode_at(buffer, i + 12);

        if (a0.type != INST_ADRP || a1.type != INST_ADD_X_IMM) continue;
        if (a1.rt != a0.rt || a1.rn != a0.rt) continue;

        if (b0.type != INST_ADRP || b1.type != INST_ADD_X_IMM) continue;
        if (b1.rt != b0.rt || b1.rn != b0.rt) continue;


        UINT8 xa = a0.rt, xb = b0.rt;
        if (xa == xb) continue;

        INT64 off0 = calc_adrl_file_offset(buffer, size, i,      load_base);
        INT64 off1 = calc_adrl_file_offset(buffer, size, i + 8,  load_base);

        if (!str_at(buffer, size, off0, "unlocked")) continue;
        if (!str_at(buffer, size, off1, "locked"))   continue;
        BOOLEAN match = FALSE;
        for(int j=i+16; j<=i+40;j+=4){
            DecodedInst c0 = decode_at(buffer, j);
            DecodedInst c1 = decode_at(buffer, j + 4);
            if(c0.type == INST_ADRP && c1.type == INST_ADD_X_IMM){
                INT64 offc = calc_adrl_file_offset(buffer, size, j, load_base);
                if(str_at(buffer, size, offc, "androidboot.vbmeta.device_state")){
                    match = TRUE;
                    break;
                }
            }
        }
        if (!match) continue;
        Print_patcher("Found ADRL triple at 0x%X:\n", i);
        Print_patcher("  [0x%X] ADRP+ADD X%d -> file:0x%llX \"unlocked\"\n",
               i, xa, (unsigned long long)off0);
        Print_patcher("  [0x%X] ADRP+ADD X%d -> file:0x%llX \"locked\"\n",
               i+8, xb, (unsigned long long)off1);

        UINT32 new_adrp = adrp_with_rd(b0.raw, xa);
        UINT32 new_add  = add_with_reg(b1.raw, xa);

        Print_patcher("  Patch pair-0: ADRP %08X->%08X, ADD %08X->%08X\n",
               a0.raw, new_adrp, a1.raw, new_add);

        write_instr(buffer, i,     new_adrp);
        write_instr(buffer, i + 4, new_add);

        patched++;
        i += 20;
    }

    if (patched == 0)
        Print_patcher("ADRL triple not found\n");
    else
        Print_patcher("ADRL patch applied: %d location(s)\n", patched);

    return patched;
}

/* Bypass the Snapshot Cancel locked-state gate.
 *
 * The denial block has a unique direct string reference preceded by:
 *   ADRP X9, <protocol page>
 *   LDR  X8, [SP, #imm]
 *   BL   <state check>
 *   B.NE <escape>
 *   ADRP+ADD X0, "Snapshot Cancel is not allowed in Lock State"
 *
 * A single CBZ Wt in the preceding 0x300 bytes targets the start of that
 * block. NOP the gate so execution stays on the allowed path.
 */
INT32 patch_snapshot_cancel_lock_bypass(CHAR8* buffer, INT32 size) {
    static const CHAR8 message[] =
        "Snapshot Cancel is not allowed in Lock State";
    INT32 message_len = (INT32)(sizeof(message) - 1);
    INT32 message_off = -1;
    INT32 gate_off = -1;
    INT32 found = 0;

    for (INT32 off = 0; off + message_len < size; ++off) {
        if (memcmp_patcher(buffer + off, message, message_len) == 0) {
            message_off = off;
            break;
        }
    }
    if (message_off < 0)
        return 0;

    for (INT32 xref = 0; xref + 8 <= size; xref += 4) {
        if (calc_adrl_file_offset(buffer, size, xref, 0) != message_off)
            continue;
        if (xref < 0x10)
            continue;

        INT32 error_block = -1;
        DecodedInst protocol_page = decode_at(buffer, xref - 0x10);
        DecodedInst state_load = decode_at(buffer, xref - 0x0C);
        UINT32 bl = read_instr(buffer, xref - 8);
        UINT32 b_ne = read_instr(buffer, xref - 4);
        if (protocol_page.type == INST_ADRP && protocol_page.rt == 9
            && state_load.type == INST_LDR_X_IMM
            && state_load.rt == 8 && state_load.rn == 31
            && (bl & 0xFC000000u) == 0x94000000u
            && (b_ne & 0xFF00001Fu) == 0x54000001u) {
            error_block = xref - 0x10;
        } else if ((bl & 0xFC000000u) == 0x94000000u
                   && (b_ne & 0xFF00001Fu) == 0x54000001u) {
            /* Compact error path keeps only the state-check call/branch. */
            error_block = xref - 8;
        }
        if (error_block < 0)
            continue;

        INT32 start = xref - 0x300;
        if (start < 0) start = 0;
        for (INT32 off = start; off < error_block; off += 4) {
            UINT32 raw = read_instr(buffer, off);
            if ((raw & 0x7F000000u) != 0x34000000u)
                continue;

            INT32 imm19 = (INT32)((raw >> 5) & 0x7FFFFu);
            if (imm19 & 0x40000)
                imm19 |= ~0x7FFFF;
            if (off + (imm19 << 2) != error_block)
                continue;

            gate_off = off;
            found++;
        }
    }

    if (found != 1) {
        Print_patcher("snapshot cancel lock bypass: locator count %d, "
                      "skipping\n", found);
        return 0;
    }

    Print_patcher("snapshot cancel lock bypass: NOP CBZ @ 0x%X\n", gate_off);
    write_instr(buffer, gate_off, NOP);
    return 1;
}

/* Region compatibility bypass.
 *
 * This handles the direct string/branch layout.
 * Anchor: diagnostic string printed when image / device region tags
 * mismatch (typo "is not invalid" intact in known vintages).
 *
 * Direct-layout primary patch: rewrite the cbz Xt sitting one instruction
 * before the adrp+add to that string into an unconditional B with the
 * same compatible-path target. The primary mismatch branch can no longer
 * fall into the shutdown sequence.
 *
 * Direct-layout secondary patch: two shutdown branches (B.EQ and CBNZ
 * Xt) in the same block remain reachable from alternative entries that
 * bypass the cbz. They both target a single shutdown stub. Overwrite
 * that stub's first instruction with an unconditional B to the same
 * compatible-path target so every incoming branch becomes a no-op
 * redirect.
 *
 * 8-byte runtime patch (4 + 4). The primary patch is enough for the
 * common direct-mismatch case; the secondary patch closes rarer
 * paths. No-op on images without the anchor.
 */
INT32 patch_region_lockout_bypass(CHAR8* buffer, INT32 size) {
    static const CHAR8 anchor[] = "region info is not invalid";
    INT32 anchor_len = (INT32)(sizeof(anchor) - 1);

    /* Locate the anchor string. */
    INT32 str_off = -1;
    for (INT32 i = 0; i + anchor_len < size; ++i) {
        if (memcmp_patcher(buffer + i, anchor, anchor_len) == 0) {
            str_off = i;
            break;
        }
    }
    if (str_off < 0) {
        Print_patcher("region bypass A-1: anchor not found, skipping\n");
        return 0;
    }
    Print_patcher("region bypass A-1: anchor @ 0x%X\n", str_off);

    /* Locate the adrp+add pair that materialises the anchor address. */
    INT32 adrl_off = -1;
    for (INT32 i = 0; i + 8 <= size; i += 4) {
        DecodedInst d0 = decode_at(buffer, i);
        if (d0.type != INST_ADRP) continue;
        DecodedInst d1 = decode_at(buffer, i + 4);
        if (d1.type != INST_ADD_X_IMM) continue;
        if (d1.rt != d0.rt || d1.rn != d0.rt) continue;
        INT64 t = calc_adrl_file_offset(buffer, size, i, 0);
        if (t == (INT64)str_off) {
            adrl_off = i;
            break;
        }
    }
    if (adrl_off < 0) {
        Print_patcher("region bypass A-1: adrp+add ref not found, skipping\n");
        return 0;
    }
    Print_patcher("region bypass A-1: adrp+add ref @ 0x%X\n", adrl_off);

    /* The gating branch sits exactly one instruction before the adrp. */
    INT32 cbz_off = adrl_off - 4;
    if (cbz_off < 0 || cbz_off + 4 > size) {
        Print_patcher("region bypass A-1: pre-anchor offset out of range\n");
        return 0;
    }
    UINT32 v = *(UINT32*)(buffer + cbz_off);

    /* Accept either CBZ Xt (0xb4) or CBZ Wt (0x34). */
    UINT8 hi = (UINT8)((v >> 24) & 0xff);
    if (hi != 0xb4 && hi != 0x34) {
        Print_patcher("region bypass A-1: pre-anchor instr is 0x%08X (hi=0x%02x),"
                      " expected CBZ; skipping\n", v, hi);
        return 0;
    }

    /* Decode CBZ target. imm19 is signed and scaled by 4. */
    INT32 imm19 = (INT32)((v >> 5) & 0x7ffff);
    if (imm19 & 0x40000) imm19 -= 0x80000;
    INT32 target = cbz_off + imm19 * 4;

    if (target < 0 || target >= size) {
        Print_patcher("region bypass A-1: cbz target 0x%X out of range\n", target);
        return 0;
    }
    Print_patcher("region bypass A-1: cbz @ 0x%X -> compatible target 0x%X\n",
                  cbz_off, target);

    /* Rewrite cbz as unconditional B to the compatible target.
     * imm26 is signed, scaled by 4, range +/- 128 MB which always
     * covers a same-function branch. */
    INT32 imm26 = (target - cbz_off) >> 2;
    UINT32 new_v = 0x14000000U | ((UINT32)imm26 & 0x3ffffffU);

    Print_patcher("region bypass A-1: patching 0x%08X -> 0x%08X\n", v, new_v);
    *(UINT32*)(buffer + cbz_off) = new_v;

    /* Find the secondary shutdown stub and redirect it to the
     * compatible target. Scan a short window past the primary site for
     * B.cond / CBZ Xt / CBNZ Xt / CBZ Wt / CBNZ Wt whose target differs
     * from the compatible target -- those land on the shutdown stub. */
    INT32 shutdown_tgt = -1;
    for (INT32 i = cbz_off + 4; i + 4 <= size && i < cbz_off + 0x80; i += 4) {
        UINT32 ins = read_instr(buffer, i);
        INT32 t = -1;

        /* B.cond: 0x54xxxxxC where C in [0,15] */
        if ((ins & 0xFF000010) == 0x54000000) {
            INT32 b_imm19 = (INT32)((ins >> 5) & 0x7ffff);
            if (b_imm19 & 0x40000) b_imm19 -= 0x80000;
            t = i + b_imm19 * 4;
        } else {
            UINT8 hi2 = (UINT8)((ins >> 24) & 0xff);
            if (hi2 == 0x34 || hi2 == 0x35 || hi2 == 0xb4 || hi2 == 0xb5) {
                INT32 c_imm19 = (INT32)((ins >> 5) & 0x7ffff);
                if (c_imm19 & 0x40000) c_imm19 -= 0x80000;
                t = i + c_imm19 * 4;
            }
        }
        if (t < 0 || t >= size) continue;
        if (t == target) continue; /* compatible-path branch, leave alone */

        shutdown_tgt = t;
        break;
    }
    if (shutdown_tgt < 0) {
        Print_patcher("region bypass A-1: secondary shutdown stub not seen,"
                      " primary only\n");
        return 1;
    }

    /* Sanity: stub must be backward (earlier in the section) and within
     * reach of an unconditional B from itself. */
    INT32 redirect_imm26 = (target - shutdown_tgt) >> 2;
    if (redirect_imm26 < -0x2000000 || redirect_imm26 >= 0x2000000) {
        Print_patcher("region bypass A-1: stub 0x%X out of B range to 0x%X\n",
                      shutdown_tgt, target);
        return 1;
    }

    UINT32 stub_new = 0x14000000U | ((UINT32)redirect_imm26 & 0x3ffffffU);
    Print_patcher("region bypass A-1: stub @ 0x%X 0x%08X -> 0x%08X (B 0x%X)\n",
                  shutdown_tgt, read_instr(buffer, shutdown_tgt),
                  stub_new, target);
    write_instr(buffer, shutdown_tgt, stub_new);

    return 2;
}

/* Record-table/message-page region bypass.
 *
 * Newer vintages move the diagnostic strings into a structured message
 * table indexed by record id. The cbz X0 anchor used by the direct
 * layout locator no longer has a direct adrp+add xref (string-payload
 * lookup is indirected through the table), so that locator silently
 * no-ops. The
 * shutdown stub still exists and still ends with `BL <reset>; B
 * <continue>` after one or more `BL <print>` calls preceded by
 * adrp+add references to the message page.
 *
 * Anchor: ASCII substring "incompatible with hardware" anywhere in the
 * binary. Compute its page; walk .text for the first adrp+add pair
 * targeting that page, then scan forward up to 0x80 bytes for the
 * trailing `BL X; B Y` pair with Y a forward branch. Overwrite the BL
 * with NOP. Execution falls through to the unconditional B which
 * continues boot instead of calling ResetSystem.
 *
 * Selectivity: requires the candidate window to contain >= 2 adrp
 * pairs aimed at the same page and >= 3 BL instructions before the
 * trailing BL+B (printf cascade plus reset). These constraints uniquely
 * identify the region-mismatch shutdown stub across known vintages and
 * keep unrelated `BL; B` sequences from being touched.
 *
 * 4-byte runtime patch (single NOP). No-op on images without the
 * message text.
 */
INT32 patch_region_bypass_stage_a2(CHAR8* buffer, INT32 size) {
    static const CHAR8 needle[] = "incompatible with hardware";
    INT32 needle_len = (INT32)(sizeof(needle) - 1);

    INT32 msg_off = -1;
    for (INT32 i = 0; i + needle_len < size; ++i) {
        if (memcmp_patcher(buffer + i, needle, needle_len) == 0) {
            msg_off = i;
            break;
        }
    }
    if (msg_off < 0) {
        Print_patcher("region bypass A-2: message text not present, skipping\n");
        return 0;
    }
    INT32 msg_page = msg_off & ~0xfff;
    Print_patcher("region bypass A-2: msg @ 0x%X (page 0x%X)\n", msg_off, msg_page);

    for (INT32 i = 0x1000; i + 4 <= size; i += 4) {
        UINT32 inst = read_instr(buffer, i);
        if ((inst & 0x9F000000u) != 0x90000000u) continue;
        /* decode adrp imm21 -> page target */
        INT32 immlo = (INT32)((inst >> 29) & 3);
        INT32 immhi = (INT32)((inst >> 5) & 0x7ffff);
        INT32 imm21 = (immhi << 2) | immlo;
        if (imm21 & 0x100000) imm21 -= 0x200000;
        INT32 page = (i & ~0xfff) + (imm21 << 12);
        if (page != msg_page) continue;

        /* Scan a short forward window for BL+B trail plus selectivity
         * counters. Counters seed with this adrp (1 adrp, 0 BL). */
        INT32 limit = i + 0x80;
        if (limit > size - 8) limit = size - 8;

        INT32 adrp_to_page = 1;
        INT32 bl_count = 0;

        for (INT32 nx = i + 4; nx + 8 <= limit; nx += 4) {
            UINT32 ins = read_instr(buffer, nx);

            if ((ins & 0x9F000000u) == 0x90000000u) {
                INT32 lo = (INT32)((ins >> 29) & 3);
                INT32 hi = (INT32)((ins >> 5) & 0x7ffff);
                INT32 im = (hi << 2) | lo;
                if (im & 0x100000) im -= 0x200000;
                INT32 pg = (nx & ~0xfff) + (im << 12);
                if (pg == msg_page) adrp_to_page++;
                continue;
            }

            if ((ins & 0xFC000000u) != 0x94000000u) continue;
            bl_count++;

            UINT32 br = read_instr(buffer, nx + 4);
            if ((br & 0xFC000000u) != 0x14000000u) continue;

            INT32 b_imm26 = (INT32)(br & 0x3ffffffu);
            if (b_imm26 & 0x2000000) b_imm26 -= 0x4000000;
            if (b_imm26 <= 0) continue;
            INT32 b_target = (nx + 4) + b_imm26 * 4;
            if (b_target < 0 || b_target >= size) continue;

            /* Selectivity: shutdown stub has multiple adrp refs and a
             * print cascade before the reset call. */
            if (adrp_to_page < 2 || bl_count < 3) continue;

            Print_patcher("region bypass A-2: NOP BL @ 0x%X (was 0x%08X), "
                          "post-BL B -> 0x%X\n",
                          nx, read_instr(buffer, nx), b_target);
            write_instr(buffer, nx, NOP);
            return 1;
        }
    }

    Print_patcher("region bypass A-2: shutdown BL+B pattern not located\n");
    return 0;
}

/* Kernel cmdline region override.
 *
 * Redirect the `androidboot.pcbaidinfo=` value pointer.
 *
 * ABL builds the kernel cmdline by appending `androidboot.pcbaidinfo=<value>`
 * where the value is sourced at runtime (TZ region tag or device buffer).
 * To force a fixed value, redirect the value-buffer pointer at the
 * emission call site so the formatter reads from a known rodata literal
 * ("PRC" or "ROW") instead of the runtime buffer.
 *
 * Pattern (OLD PRC / ROW vintages):
 *   ADRP Xa, <page-of-pcbaidinfo>
 *   ADD  Xa, Xa, #<imm12-of-pcbaidinfo>      ; key string
 *   ADD  X2, SP, #imm                        ; value buffer ptr   <-- target
 *   ...
 *   BL   <formatter>                          ; emits "key=value"
 *
 * Rewrite the `ADD X2, SP, #imm` (or `ADD X2, X_any, #imm`) into
 * `ADR X2, <region_literal>`. The literal is a 3-char NUL-terminated
 * string already present in rodata. ADR has +/- 1MB range which is
 * sufficient within a single ABL image.
 *
 * region must be 3 chars ("PRC" or "ROW"). Locator skips if the
 * direct adrp+add key xref is absent (e.g., newer record-table style —
 * needs separate handling).
 */
INT32 patch_pcbaidinfo_override(CHAR8* buffer, INT32 size,
                                const CHAR8* region) {
    static const CHAR8 key[] = " androidboot.pcbaidinfo=";
    INT32 key_len = (INT32)(sizeof(key) - 1);

    if (region == 0 || region[0] == 0 || region[1] == 0 || region[2] == 0) {
        Print_patcher("cmdline override B-1: invalid region argument, skipping\n");
        return 0;
    }

    /* Locate key string */
    INT32 key_off = -1;
    for (INT32 i = 0; i + key_len < size; ++i) {
        if (memcmp_patcher(buffer + i, key, key_len) == 0) {
            key_off = i; break;
        }
    }
    if (key_off < 0) {
        Print_patcher("cmdline override B-1: key string not present, skipping\n");
        return 0;
    }
    Print_patcher("cmdline override B-1: key @ 0x%X (forcing %s)\n",
                  key_off, region);

    /* Locate region literal: \0<region>\0 */
    INT32 lit_off = -1;
    for (INT32 i = 0; i + 4 < size; ++i) {
        if (buffer[i] == 0
            && buffer[i+1] == region[0]
            && buffer[i+2] == region[1]
            && buffer[i+3] == region[2]
            && buffer[i+4] == 0) {
            lit_off = i + 1; break;
        }
    }
    if (lit_off < 0) {
        Print_patcher("cmdline override B-1: region literal not present, skipping\n");
        return 0;
    }
    Print_patcher("cmdline override B-1: region literal @ 0x%X\n", lit_off);

    /* Walk .text for ADRP+ADD pair targeting the key string. */
    INT32 patched = 0;
    for (INT32 i = 0x1000; i + 8 <= size; i += 4) {
        DecodedInst d0 = decode_at(buffer, i);
        if (d0.type != INST_ADRP) continue;
        DecodedInst d1 = decode_at(buffer, i + 4);
        if (d1.type != INST_ADD_X_IMM) continue;
        if (d1.rt != d0.rt || d1.rn != d0.rt) continue;
        INT64 t = calc_adrl_file_offset(buffer, size, i, 0);
        if (t != (INT64)key_off) continue;

        /* Scan next 0x20 bytes for ADD X2, X_any, #imm (sf=1, Rd=2). */
        INT32 sink_off = -1;
        for (INT32 j = i + 8; j + 4 <= size && j < i + 0x20; j += 4) {
            UINT32 ins = read_instr(buffer, j);
            if ((ins & 0xFF80001Fu) == 0x91000002u) {
                sink_off = j; break;
            }
        }
        if (sink_off < 0) continue;

        /* Encode ADR X2, lit_off. ADR range is +/- 1MB. */
        INT32 off = lit_off - sink_off;
        if (off < -(1 << 20) || off >= (1 << 20)) {
            Print_patcher("cmdline override B-1: ADR range exceeded, skipping site\n");
            continue;
        }
        UINT32 imm21 = (UINT32)off & 0x1FFFFFu;
        UINT32 immlo = imm21 & 3u;
        UINT32 immhi = (imm21 >> 2) & 0x7FFFFu;
        UINT32 adr = 0x10000000u
                   | (immlo << 29)
                   | (0x10u << 24)
                   | (immhi << 5)
                   | 2u;

        Print_patcher("cmdline override B-1: ADR X2 @ 0x%X 0x%08X -> 0x%08X "
                      "(literal 0x%X)\n",
                      sink_off, read_instr(buffer, sink_off), adr, lit_off);
        write_instr(buffer, sink_off, adr);
        patched++;
        break; /* Only patch the first emission site found */
    }

    if (patched == 0)
        Print_patcher("cmdline override B-1: emission site not located\n");
    return patched;
}

/* `hqsysfs.pcba_config=` value override.
 *
 * The hqsysfs kernel module exposes /sys/module/hqsysfs/parameters/
 * pcba_config which carries the region tag (PRC vs ROW) from the
 * kernel cmdline argument `hqsysfs.pcba_config=PRC` emitted by ABL.
 *
 * Earlier revisions of this patch tried two approaches:
 *  v1) Redirect the key-string adrp+add to an embedded override
 *      " hqsysfs.pcba_config=ROW " in .data NUL padding. That flipped
 *      /sys/module/hqsysfs/parameters/pcba_config to "ROW", but the
 *      formatter still appended the runtime value behind our embed,
 *      producing a stray "PRC" token after the space separator:
 *          hqsysfs.pcba_config=ROW PRC
 *      Userspace consumers searching /proc/cmdline for the substring
 *      "PRC" still matched the stray, defeating the override.
 *  v2) NOP only the first BL after the ADRL pair, hoping to suppress
 *      the whole emission. That suppressed the key emission but not
 *      the value emission (the formatter uses two BLs per cmdline
 *      argument: first BL emits the key, second BL emits the value).
 *      Result on /proc/cmdline:
 *          hqsysfs.pcba_stage=MPPRC hqsysfs.pcba_hwid=...
 *      The skipped key left "MP" (preceding emission's value) glued
 *      directly to "PRC" (our emission's value) with no separator.
 *
 * Current approach: keep both formatter calls, but redirect only the value
 * pointer load to a fixed rodata literal. Pattern around ROW ABL:
 *
 *   ADRP X2, " hqsysfs.pcba_config="
 *   ADD  X2, X2, #imm
 *   BL   formatter                  ; emits key
 *   LDR  X2, [SP, #imm]             ; runtime region ptr  <-- target
 *   BL   formatter                  ; emits value
 *
 * Rewriting the LDR to `ADR X2, "ROW"` yields exactly
 * `hqsysfs.pcba_config=ROW` with no trailing runtime PRC token.
 *
 * Builds without a direct adrp+add key xref (record-table vintages)
 * silently no-op.
 */
INT32 patch_hqsysfs_pcba_config_override(CHAR8* buffer, INT32 size,
                                          const CHAR8* region) {
    static const CHAR8 key[] = " hqsysfs.pcba_config=";
    INT32 key_len = (INT32)(sizeof(key) - 1);

    if (region == 0 || region[0] == 0 || region[1] == 0 || region[2] == 0) {
        Print_patcher("cmdline override B-2: invalid region argument, skipping\n");
        return 0;
    }

    /* Find key string in rodata */
    INT32 key_off = -1;
    for (INT32 i = 0; i + key_len < size; ++i) {
        if (memcmp_patcher(buffer + i, key, key_len) == 0) {
            key_off = i; break;
        }
    }
    if (key_off < 0) {
        Print_patcher("cmdline override B-2: key string absent, skipping\n");
        return 0;
    }
    Print_patcher("cmdline override B-2: key @ 0x%X (forcing %s)\n",
                  key_off, region);

    INT32 lit_off = -1;
    for (INT32 i = 0; i + 4 < size; ++i) {
        if (buffer[i] == 0
            && buffer[i+1] == region[0]
            && buffer[i+2] == region[1]
            && buffer[i+3] == region[2]
            && buffer[i+4] == 0) {
            lit_off = i + 1; break;
        }
    }
    if (lit_off < 0) {
        Print_patcher("cmdline override B-2: region literal not present, skipping\n");
        return 0;
    }
    Print_patcher("cmdline override B-2: region literal @ 0x%X\n", lit_off);

    /* Find the adrp+add pair targeting key_off, then locate the runtime
     * value load between the key-emit BL and value-emit BL. */
    INT32 patched = 0;
    for (INT32 i = 0x1000; i + 8 <= size; i += 4) {
        DecodedInst d0 = decode_at(buffer, i);
        if (d0.type != INST_ADRP) continue;
        DecodedInst d1 = decode_at(buffer, i + 4);
        if (d1.type != INST_ADD_X_IMM) continue;
        if (d1.rt != d0.rt || d1.rn != d0.rt) continue;
        INT64 t = calc_adrl_file_offset(buffer, size, i, 0);
        if (t != (INT64)key_off) continue;

        INT32 bl1 = -1, bl2 = -1, value_load = -1;
        for (INT32 j = i + 8; j + 4 <= size && j < i + 0x34; j += 4) {
            UINT32 raw = read_instr(buffer, j);
            /* arm64_inst_decoder has an INST_BL enum but no active BL decoder;
             * match BL by raw opcode like the rest of this file. */
            if ((raw & 0xFC000000u) == 0x94000000u) {
                if (bl1 < 0) {
                    bl1 = j;
                } else {
                    bl2 = j;
                    break;
                }
                continue;
            }

            DecodedInst dj = decode_at(buffer, j);
            if (bl1 >= 0 && dj.type == INST_LDR_X_IMM && dj.rt == 2) {
                value_load = j;
            }
        }
        if (bl1 < 0 || bl2 < 0 || value_load < 0 || value_load >= bl2) continue;

        /* Encode ADR X2, lit_off. ADR range is +/- 1MB. */
        INT32 off = lit_off - value_load;
        if (off < -(1 << 20) || off >= (1 << 20)) {
            Print_patcher("cmdline override B-2: ADR range exceeded, skipping site\n");
            continue;
        }
        UINT32 imm21 = (UINT32)off & 0x1FFFFFu;
        UINT32 immlo = imm21 & 3u;
        UINT32 immhi = (imm21 >> 2) & 0x7FFFFu;
        UINT32 adr = 0x10000000u
                   | (immlo << 29)
                   | (0x10u << 24)
                   | (immhi << 5)
                   | 2u;

        Print_patcher("cmdline override B-2: ADR X2 @ 0x%X 0x%08X -> 0x%08X "
                      "(literal 0x%X), key BL @ 0x%X, value BL @ 0x%X\n",
                      value_load, read_instr(buffer, value_load), adr,
                      lit_off, bl1, bl2);
        write_instr(buffer, value_load, adr);
        patched++;
        break;
    }

    if (patched == 0)
        Print_patcher("cmdline override B-2: ADRL/value-load pair not found\n");
    return patched;
}

/* vbmeta AVB key swap.
 *
 * Locates the embedded 4096-bit AvbRSAPublicKey blob for the platform's
 * stock vbmeta verify key and overwrites it in place with the AOSP test
 * key blob. After the swap, any vbmeta image signed with the AOSP test
 * private key (publicly published in external/avb/test/data) verifies
 * successfully on this device.
 *
 * AvbRSAPublicKey layout (1032 bytes for RSA-4096):
 *   offset 0x000  4B  key_num_bits = 0x00001000 BE
 *   offset 0x004  4B  n0inv         BE (derived from modulus)
 *   offset 0x008 512B modulus       BE
 *   offset 0x208 512B rr            BE (R^2 mod N)
 *
 * Anchor: header (4B) + n0inv (4B) + first 32 modulus bytes. The
 * modulus prefix is unique enough that no false positive is possible
 * within an ABL-sized image; n0inv is included because it is also
 * tied to the modulus and changes only when the modulus does, giving
 * an extra structural check at zero cost.
 *
 * Multi-vintage compatibility: this exact 1032-byte blob ships in
 * PRC and ROW variants and in earlier rotated vintages of the
 * platform's xbl/abl pair. Builds whose vbmeta key has been rotated
 * to a different modulus silently no-op (locator returns 0); they
 * can be supported later by adding a second anchor without touching
 * the rest of the codebase.
 *
 * 1032-byte runtime overwrite, single site. Gated by FORCE_AVB_KEY_ARB
 * so default builds are unaffected.
 */

/* AvbRSAPublicKey header (8 bytes) + first 32 modulus bytes of the
 * stock vbmeta key. memcmp anchor for in-place swap. */
static const UINT8 STOCK_AVB_ANCHOR[40] = {
    0x00, 0x00, 0x10, 0x00, 0xbc, 0x29, 0xf0, 0xad,
    0x99, 0x83, 0x5c, 0x83, 0xd5, 0x0e, 0x5d, 0xbc,
    0x55, 0x73, 0xa1, 0x33, 0xc1, 0x70, 0x7c, 0x62,
    0xee, 0x53, 0x5e, 0x1f, 0xa1, 0x39, 0xbd, 0x46,
    0x96, 0xb5, 0x50, 0x53, 0xc8, 0x80, 0x08, 0x86,
};

/* Full AvbRSAPublicKey blob for the AOSP testkey_rsa4096 — 8B header
 * + 4B n0inv + 512B modulus + 512B rr. Published under Apache 2.0 in
 * external/avb/test/data/testkey_rsa4096.pem. */
static const UINT8 AOSP_AVB_BLOB[1032] = {
    0x00, 0x00, 0x10, 0x00, 0x55, 0xd9, 0x04, 0xad, 0xd8, 0x04, 0xaf, 0xe3,
    0xd3, 0x84, 0x6c, 0x7e, 0x0d, 0x89, 0x3d, 0xc2, 0x8c, 0xd3, 0x12, 0x55,
    0xe9, 0x62, 0xc9, 0xf1, 0x0f, 0x5e, 0xcc, 0x16, 0x72, 0xab, 0x44, 0x7c,
    0x2c, 0x65, 0x4a, 0x94, 0xb5, 0x16, 0x2b, 0x00, 0xbb, 0x06, 0xef, 0x13,
    0x07, 0x53, 0x4c, 0xf9, 0x64, 0xb9, 0x28, 0x7a, 0x1b, 0x84, 0x98, 0x88,
    0xd8, 0x67, 0xa4, 0x23, 0xf9, 0xa7, 0x4b, 0xdc, 0x4a, 0x0f, 0xf7, 0x3a,
    0x18, 0xae, 0x54, 0xa8, 0x15, 0xfe, 0xb0, 0xad, 0xac, 0x35, 0xda, 0x3b,
    0xad, 0x27, 0xbc, 0xaf, 0xe8, 0xd3, 0x2f, 0x37, 0x34, 0xd6, 0x51, 0x2b,
    0x6c, 0x5a, 0x27, 0xd7, 0x96, 0x06, 0xaf, 0x6b, 0xb8, 0x80, 0xca, 0xfa,
    0x30, 0xb4, 0xb1, 0x85, 0xb3, 0x4d, 0xaa, 0xaa, 0xc3, 0x16, 0x34, 0x1a,
    0xb8, 0xe7, 0xc7, 0xfa, 0xf9, 0x09, 0x77, 0xab, 0x97, 0x93, 0xeb, 0x44,
    0xae, 0xcf, 0x20, 0xbc, 0xf0, 0x80, 0x11, 0xdb, 0x23, 0x0c, 0x47, 0x71,
    0xb9, 0x6d, 0xd6, 0x7b, 0x60, 0x47, 0x87, 0x16, 0x56, 0x93, 0xb7, 0xc2,
    0x2a, 0x9a, 0xb0, 0x4c, 0x01, 0x0c, 0x30, 0xd8, 0x93, 0x87, 0xf0, 0xed,
    0x6e, 0x8b, 0xbe, 0x30, 0x5b, 0xf6, 0xa6, 0xaf, 0xdd, 0x80, 0x7c, 0x45,
    0x5e, 0x8f, 0x91, 0x93, 0x5e, 0x44, 0xfe, 0xb8, 0x82, 0x07, 0xee, 0x79,
    0xca, 0xbf, 0x31, 0x73, 0x62, 0x58, 0xe3, 0xcd, 0xc4, 0xbc, 0xc2, 0x11,
    0x1d, 0xa1, 0x4a, 0xbf, 0xfe, 0x27, 0x7d, 0xa1, 0xf6, 0x35, 0xa3, 0x5e,
    0xca, 0xdc, 0x57, 0x2f, 0x3e, 0xf0, 0xc9, 0x5d, 0x86, 0x6a, 0xf8, 0xaf,
    0x66, 0xa7, 0xed, 0xcd, 0xb8, 0xed, 0xa1, 0x5f, 0xba, 0x9b, 0x85, 0x1a,
    0xd5, 0x09, 0xae, 0x94, 0x4e, 0x3b, 0xcf, 0xcb, 0x5c, 0xc9, 0x79, 0x80,
    0xf7, 0xcc, 0xa6, 0x4a, 0xa8, 0x6a, 0xd8, 0xd3, 0x31, 0x11, 0xf9, 0xf6,
    0x02, 0x63, 0x2a, 0x1a, 0x2d, 0xd1, 0x1a, 0x66, 0x1b, 0x16, 0x41, 0xbd,
    0xbd, 0xf7, 0x4d, 0xc0, 0x4a, 0xe5, 0x27, 0x49, 0x5f, 0x7f, 0x58, 0xe3,
    0x27, 0x2d, 0xe5, 0xc9, 0x66, 0x0e, 0x52, 0x38, 0x16, 0x38, 0xfb, 0x16,
    0xeb, 0x53, 0x3f, 0xe6, 0xfd, 0xe9, 0xa2, 0x5e, 0x25, 0x59, 0xd8, 0x79,
    0x45, 0xff, 0x03, 0x4c, 0x26, 0xa2, 0x00, 0x5a, 0x8e, 0xc2, 0x51, 0xa1,
    0x15, 0xf9, 0x7b, 0xf4, 0x5c, 0x81, 0x9b, 0x18, 0x47, 0x35, 0xd8, 0x2d,
    0x05, 0xe9, 0xad, 0x0f, 0x35, 0x74, 0x15, 0xa3, 0x8e, 0x8b, 0xcc, 0x27,
    0xda, 0x7c, 0x5d, 0xe4, 0xfa, 0x04, 0xd3, 0x05, 0x0b, 0xba, 0x3a, 0xb2,
    0x49, 0x45, 0x2f, 0x47, 0xc7, 0x0d, 0x41, 0x3f, 0x97, 0x80, 0x4d, 0x3f,
    0xc1, 0xb5, 0xbb, 0x70, 0x5f, 0xa7, 0x37, 0xaf, 0x48, 0x22, 0x12, 0x45,
    0x2e, 0xf5, 0x0f, 0x87, 0x92, 0xe2, 0x84, 0x01, 0xf9, 0x12, 0x0f, 0x14,
    0x15, 0x24, 0xce, 0x89, 0x99, 0xee, 0xb9, 0xc4, 0x17, 0x70, 0x70, 0x15,
    0xea, 0xbe, 0xc6, 0x6c, 0x1f, 0x62, 0xb3, 0xf4, 0x2d, 0x16, 0x87, 0xfb,
    0x56, 0x1e, 0x45, 0xab, 0xae, 0x32, 0xe4, 0x5e, 0x91, 0xed, 0x53, 0x66,
    0x5e, 0xbd, 0xed, 0xad, 0xe6, 0x12, 0x39, 0x0d, 0x83, 0xc9, 0xe8, 0x6b,
    0x6c, 0x2d, 0xa5, 0xee, 0xc4, 0x5a, 0x66, 0xae, 0x8c, 0x97, 0xd7, 0x0d,
    0x6c, 0x49, 0xc7, 0xf5, 0xc4, 0x92, 0x31, 0x8b, 0x09, 0xee, 0x33, 0xda,
    0xa9, 0x37, 0xb6, 0x49, 0x18, 0xf8, 0x0e, 0x60, 0x45, 0xc8, 0x33, 0x91,
    0xef, 0x20, 0x57, 0x10, 0xbe, 0x78, 0x2d, 0x83, 0x26, 0xd6, 0xca, 0x61,
    0xf9, 0x2f, 0xe0, 0xbf, 0x05, 0x30, 0x52, 0x5a, 0x12, 0x1c, 0x00, 0xa7,
    0x5d, 0xcc, 0x7c, 0x2e, 0xc5, 0x95, 0x8b, 0xa3, 0x3b, 0xf0, 0x43, 0x2e,
    0x5e, 0xdd, 0x00, 0xdb, 0x0d, 0xb3, 0x37, 0x99, 0xa9, 0xcd, 0x9c, 0xb7,
    0x43, 0xf7, 0x35, 0x44, 0x21, 0xc2, 0x82, 0x71, 0xab, 0x8d, 0xaa, 0xb4,
    0x41, 0x11, 0xec, 0x1e, 0x8d, 0xfc, 0x14, 0x82, 0x92, 0x4e, 0x83, 0x6a,
    0x0a, 0x6b, 0x35, 0x5e, 0x5d, 0xe9, 0x5c, 0xcc, 0x8c, 0xde, 0x39, 0xd1,
    0x4a, 0x5b, 0x5f, 0x63, 0xa9, 0x64, 0xe0, 0x0a, 0xcb, 0x0b, 0xb8, 0x5a,
    0x7c, 0xc3, 0x0b, 0xe6, 0xbe, 0xfe, 0x8b, 0x0f, 0x7d, 0x34, 0x8e, 0x02,
    0x66, 0x74, 0x01, 0x6c, 0xca, 0x76, 0xac, 0x7c, 0x67, 0x08, 0x2f, 0x3f,
    0x1a, 0xa6, 0x2c, 0x60, 0xb3, 0xff, 0xda, 0x8d, 0xb8, 0x12, 0x0c, 0x00,
    0x7f, 0xcc, 0x50, 0xa1, 0x5c, 0x64, 0xa1, 0xe2, 0x5f, 0x32, 0x65, 0xc9,
    0x9c, 0xbe, 0xd6, 0x0a, 0x13, 0x87, 0x3c, 0x2a, 0x45, 0x47, 0x0c, 0xca,
    0x42, 0x82, 0xfa, 0x89, 0x65, 0xe7, 0x89, 0xb4, 0x8f, 0xf7, 0x1e, 0xe6,
    0x23, 0xa5, 0xd0, 0x59, 0x37, 0x79, 0x92, 0xd7, 0xce, 0x3d, 0xfd, 0xe3,
    0xa1, 0x0b, 0xcf, 0x6c, 0x85, 0xa0, 0x65, 0xf3, 0x5c, 0xc6, 0x4a, 0x63,
    0x5f, 0x6e, 0x3a, 0x3a, 0x2a, 0x8b, 0x6a, 0xb6, 0x2f, 0xbb, 0xf8, 0xb2,
    0x4b, 0x62, 0xbc, 0x1a, 0x91, 0x25, 0x66, 0xe3, 0x69, 0xca, 0x60, 0x49,
    0x0b, 0xf6, 0x8a, 0xbe, 0x3e, 0x76, 0x53, 0xc2, 0x7a, 0xa8, 0x04, 0x17,
    0x75, 0xf1, 0xf3, 0x03, 0x62, 0x1b, 0x85, 0xb2, 0xb0, 0xef, 0x80, 0x15,
    0xb6, 0xd4, 0x4e, 0xdf, 0x71, 0xac, 0xdb, 0x2a, 0x04, 0xd4, 0xb4, 0x21,
    0xba, 0x65, 0x56, 0x57, 0xe8, 0xfa, 0x84, 0xa2, 0x7d, 0x13, 0x0e, 0xaf,
    0xd7, 0x9a, 0x58, 0x2a, 0xa3, 0x81, 0x84, 0x8d, 0x09, 0xa0, 0x6a, 0xc1,
    0xbb, 0xd9, 0xf5, 0x86, 0xac, 0xbd, 0x75, 0x61, 0x09, 0xe6, 0x8c, 0x3d,
    0x77, 0xb2, 0xed, 0x30, 0x20, 0xe4, 0x00, 0x1d, 0x97, 0xe8, 0xbf, 0xc7,
    0x00, 0x1b, 0x21, 0xb1, 0x16, 0xe7, 0x41, 0x67, 0x2e, 0xec, 0x38, 0xbc,
    0xe5, 0x1b, 0xb4, 0x06, 0x23, 0x31, 0x71, 0x1c, 0x49, 0xcd, 0x76, 0x4a,
    0x76, 0x36, 0x8d, 0xa3, 0x89, 0x8b, 0x4a, 0x7a, 0xf4, 0x87, 0xc8, 0x15,
    0x0f, 0x37, 0x39, 0xf6, 0x6d, 0x80, 0x19, 0xef, 0x5c, 0xa8, 0x66, 0xce,
    0x1b, 0x16, 0x79, 0x21, 0xdf, 0xd7, 0x31, 0x30, 0xc4, 0x21, 0xdd, 0x34,
    0x5b, 0xd2, 0x1a, 0x2b, 0x3e, 0x5d, 0xf7, 0xea, 0xca, 0x05, 0x8e, 0xb7,
    0xcb, 0x49, 0x2e, 0xa0, 0xe3, 0xf4, 0xa7, 0x48, 0x19, 0x10, 0x9c, 0x04,
    0xa7, 0xf4, 0x28, 0x74, 0xc8, 0x6f, 0x63, 0x20, 0x2b, 0x46, 0x24, 0x26,
    0x19, 0x1d, 0xd1, 0x2c, 0x31, 0x6d, 0x5a, 0x29, 0xa2, 0x06, 0xa6, 0xb2,
    0x41, 0xcc, 0x0a, 0x27, 0x96, 0x09, 0x96, 0xac, 0x47, 0x65, 0x78, 0x68,
    0x51, 0x98, 0xd6, 0xd8, 0xa6, 0x2d, 0xa0, 0xcf, 0xec, 0xe2, 0x74, 0xf2,
    0x82, 0xe3, 0x97, 0xd9, 0x7e, 0xd4, 0xf8, 0x0b, 0x70, 0x43, 0x3d, 0xb1,
    0x7b, 0x97, 0x80, 0xd6, 0xcb, 0xd7, 0x19, 0xbc, 0x63, 0x0b, 0xfd, 0x4d,
    0x88, 0xfe, 0x67, 0xac, 0xb8, 0xcc, 0x50, 0xb7, 0x68, 0xb3, 0x5b, 0xd6,
    0x1e, 0x25, 0xfc, 0x5f, 0x3c, 0x8d, 0xb1, 0x33, 0x7c, 0xb3, 0x49, 0x01,
    0x3f, 0x71, 0x55, 0x0e, 0x51, 0xba, 0x61, 0x26, 0xfa, 0xea, 0xe5, 0xb5,
    0xe8, 0xaa, 0xcf, 0xcd, 0x96, 0x9f, 0xd6, 0xc1, 0x5f, 0x53, 0x91, 0xad,
    0x05, 0xde, 0x20, 0xe7, 0x51, 0xda, 0x5b, 0x95, 0x67, 0xed, 0xf4, 0xee,
    0x42, 0x65, 0x70, 0x13, 0x0b, 0x70, 0x14, 0x1c, 0xc9, 0xe0, 0x19, 0xca,
    0x5f, 0xf5, 0x1d, 0x70, 0x4b, 0x6c, 0x06, 0x74, 0xec, 0xb5, 0x2e, 0x77,
    0xe1, 0x74, 0xa1, 0xa3, 0x99, 0xa0, 0x85, 0x9e, 0xf1, 0xac, 0xd8, 0x7e,
};

#define AVB_BLOB_LEN 1032
#define AVB_ANCHOR_LEN 40

INT32 patch_swap_avb_key_arb(CHAR8* buffer, INT32 size) {
    if (size < AVB_BLOB_LEN) {
        Print_patcher("avb key swap C: buffer too small, skipping\n");
        return 0;
    }
    INT32 patched = 0;
    INT32 limit = size - AVB_BLOB_LEN;
    for (INT32 i = 0; i <= limit; ++i) {
        if (memcmp_patcher(buffer + i, STOCK_AVB_ANCHOR, AVB_ANCHOR_LEN) != 0)
            continue;
        Print_patcher("avb key swap C: stock AvbRSAPublicKey @ 0x%X, overwriting"
                      " with AOSP testkey (%d bytes)\n", i, AVB_BLOB_LEN);
        memcpy_patcher(buffer + i, AOSP_AVB_BLOB, AVB_BLOB_LEN);
        patched++;
        i += AVB_BLOB_LEN - 1;
    }
    if (patched == 0)
        Print_patcher("avb key swap C: stock key not located, skipping\n");
    else if (patched > 1)
        Print_patcher("avb key swap C: warning, %d sites swapped (expected 1)\n",
                      patched);
    return patched;
}

/* Disable `oem lock-flash` fastboot command.
 *
 * On ROW builds an `oem lock-flash` command writes the CSDK flash_dis
 * flag to 1, which gates Firehose LUN 0 writes on next EDL session. The
 * state is sticky across normal reboots — once set, EDL flashes that touch
 * protected LUNs begin to NAK partway through, leaving the device
 * in a half-flashed state with no in-band recovery path.
 *
 * Defensive measure: scan the patch buffer for the literal cmd string
 * `oem lock-flash` and overwrite the byte at offset 4 (the `l` in
 * `lock`) with an underscore. The stored cmd-table entry becomes
 * `oem _ock-flash` — same length, still NUL-terminated, but no longer
 * a prefix or whole-string match for any user input. The EDK2 fastboot
 * dispatcher does prefix matching (see `fastboot flashing unlock` ->
 * `oem unlock`), so an all-NUL truncation to `oem ` would actually
 * widen the match instead of narrowing it; the underscore preserves
 * the original string length and avoids creating a broad `oem ` prefix
 * that could be hit by any future `oem X` user input.
 *
 * Boundary check: require the match to be standalone (NUL-preceded
 * and NUL-followed) so we do not corrupt a longer string that happens
 * to contain the same substring. Single-byte runtime patch per hit.
 * PRC builds lack the cmd string entirely; locator silently no-ops.
 */
INT32 patch_disable_lock_flash_cmd(CHAR8* buffer, INT32 size) {
    static const CHAR8 needle[] = "oem lock-flash";
    INT32 needle_len = (INT32)(sizeof(needle) - 1);
    INT32 patched = 0;

    if (size < needle_len + 1) return 0;

    for (INT32 i = 0; i + needle_len < size; ++i) {
        if (memcmp_patcher(buffer + i, needle, needle_len) != 0) continue;
        if (buffer[i + needle_len] != 0) continue;
        if (i > 0 && buffer[i - 1] != 0) continue;

        Print_patcher("disable_lock_flash: hit @ 0x%X, mangling cmd "
                      "string at offset +4\n", i);
        Print_patcher("  Before: %02X %02X %02X %02X %02X %02X %02X\n",
                      (UINT8)buffer[i], (UINT8)buffer[i+1], (UINT8)buffer[i+2],
                      (UINT8)buffer[i+3], (UINT8)buffer[i+4], (UINT8)buffer[i+5],
                      (UINT8)buffer[i+6]);
        buffer[i + 4] = '_';
        Print_patcher("  After : %02X %02X %02X %02X %02X %02X %02X\n",
                      (UINT8)buffer[i], (UINT8)buffer[i+1], (UINT8)buffer[i+2],
                      (UINT8)buffer[i+3], (UINT8)buffer[i+4], (UINT8)buffer[i+5],
                      (UINT8)buffer[i+6]);

        patched++;
        i += needle_len - 1;
    }

    if (patched == 0)
        Print_patcher("disable_lock_flash: string not present, skipping\n");
    else if (patched > 1)
        Print_patcher("disable_lock_flash: warning, %d sites patched "
                      "(expected 1)\n", patched);
    return patched;
}

/* Bypass `oem unlock-region` token verification.
 *
 * The command still requires a locked device and still accepts only the
 * exact ROW / PRC region strings. Only the token challenge verification
 * result is forced to success.
 *
 * Locator:
 *   1. find standalone fastboot command string `oem unlock-region`
 *   2. find command-table entry `{ cmd_string_va, callback_va }`
 *   3. inside that callback, find the token gate:
 *        BL <token-state>
 *        TST W0,#0xff
 *        B.EQ <no-token path>
 *        BL <verify-token>
 *        CBZ X0,<ok>
 *   4. replace the verify-token BL with `MOV X0, XZR`
 *
 * Patching the BL to a zero return value is safer than NOP: the next
 * instruction branches on X0 == 0.
 */
#define UNLOCK_REGION_TOKEN_BYPASS_MAX_BYTES 0x180
#define MOV_X0_XZR 0xAA1F03E0u

static BOOLEAN is_standalone_cstr(const CHAR8* buffer, INT32 size,
                                  INT32 off, INT32 len) {
    if (off < 0 || off + len >= size) return FALSE;
    if (buffer[off + len] != 0) return FALSE;
    if (off > 0 && buffer[off - 1] != 0) return FALSE;
    return TRUE;
}

static BOOLEAN is_cbz_x0(UINT32 raw) {
    return (raw & 0xFF00001Fu) == 0xB4000000u;
}

static INT32 patch_unlock_region_handler_token_bl(CHAR8* buffer, INT32 size,
                                                  INT32 handler_off) {
    if (handler_off < 0 || handler_off + 4 > size) return 0;
    if (read_instr(buffer, handler_off) != 0xD503233Fu) return 0;

    INT32 end = handler_off + UNLOCK_REGION_TOKEN_BYPASS_MAX_BYTES;
    if (end > size - 8) end = size - 8;

    for (INT32 off = handler_off + 4; off <= end; off += 4) {
        UINT32 raw = read_instr(buffer, off);

        if (off != handler_off && raw == 0xD503233Fu)
            break;

        if (raw != 0x72001C1Fu)
            continue;

        for (INT32 bl_off = off + 4; bl_off <= end; bl_off += 4) {
            UINT32 bl = read_instr(buffer, bl_off);
            if (bl == 0xD503233Fu)
                break;
            if ((bl & 0xFC000000u) != 0x94000000u)
                continue;
            if (!is_cbz_x0(read_instr(buffer, bl_off + 4)))
                continue;

            Print_patcher("unlock-region token bypass: handler 0x%X, "
                          "verify BL @ 0x%X 0x%08X -> 0x%08X\n",
                          handler_off, bl_off, bl, MOV_X0_XZR);
            write_instr(buffer, bl_off, MOV_X0_XZR);
            return 1;
        }
    }

    Print_patcher("unlock-region token bypass: token BL not found in "
                  "handler 0x%X\n", handler_off);
    return 0;
}

INT32 patch_unlock_region_token_bypass(CHAR8* buffer, INT32 size) {
    static const CHAR8 cmd[] = "oem unlock-region";
    INT32 cmd_len = (INT32)(sizeof(cmd) - 1);
    INT32 patched = 0;
    INT32 delta = detect_pe_image_delta(buffer, size);

    if (size < cmd_len + 16)
        return 0;

    for (INT32 cmd_off = 0; cmd_off + cmd_len < size; ++cmd_off) {
        if (memcmp_patcher(buffer + cmd_off, cmd, cmd_len) != 0)
            continue;
        if (!is_standalone_cstr(buffer, size, cmd_off, cmd_len))
            continue;

        INT64 cmd_va = (INT64)cmd_off - delta;
        if (cmd_va < 0)
            continue;

        for (INT32 ent = 0; ent + 16 <= size; ent += 8) {
            if (read_u64_unaligned(buffer, ent) != (UINT64)cmd_va)
                continue;

            UINT64 handler_va = read_u64_unaligned(buffer, ent + 8);
            if (handler_va > (UINT64)(size - delta - 4))
                continue;

            INT32 handler_off = (INT32)handler_va + delta;
            INT32 n = patch_unlock_region_handler_token_bl(buffer, size,
                                                           handler_off);
            if (n == 0)
                continue;
            patched += n;
            break;
        }
    }

    if (patched == 0)
        Print_patcher("unlock-region token bypass: command handler not "
                      "located, skipping\n");
    else if (patched > 1)
        Print_patcher("unlock-region token bypass: warning, %d sites "
                      "patched (expected 1)\n", patched);
    return patched;
}

/* AVB and TZ rollback protection bypass.
 *
 * This patch covers three separate rollback channels:
 *   1. force the AVB image-vs-stored rollback comparison to its accept path
 *   2. replace WriteRollbackIndex with a success-return stub
 *   3. suppress both TZ rollback-version update SIPs with fake success
 *
 * All four sites must be located before any instruction is changed.
 */
#define ROLLBACK_EXPECTED_PATCHES 4
#define MOV_W0_WZR 0x2A1F03E0u
#define RET_X30 0xD65F03C0u

static BOOLEAN is_cmp_x_reg(UINT32 raw) {
    return (raw & 0xFFE0FC1Fu) == 0xEB00001Fu;
}

static BOOLEAN is_b_cs(UINT32 raw) {
    return (raw & 0xFF00001Fu) == 0x54000002u;
}

static UINT32 b_from_b_cond(UINT32 raw) {
    INT32 imm19 = (INT32)((raw >> 5) & 0x7FFFFu);
    if (imm19 & 0x40000)
        imm19 |= ~0x7FFFF;
    return 0x14000000u | ((UINT32)imm19 & 0x03FFFFFFu);
}

static BOOLEAN is_sub_sp_sp_imm(UINT32 raw) {
    return (raw & 0xFFC003FFu) == 0xD10003FFu;
}

static BOOLEAN is_add_x_sp_imm(UINT32 raw, UINT8 rd) {
    return (raw & 0xFFC003FFu) == (0x910003E0u | rd);
}

static INT32 find_string_offset(const CHAR8* buffer, INT32 size,
                                const CHAR8* needle) {
    INT32 len = strlen(needle);
    if (len == 0 || size < len)
        return -1;
    for (INT32 off = 0; off <= size - len; ++off)
        if (memcmp_patcher(buffer + off, needle, len) == 0)
            return off;
    return -1;
}

static INT32 find_rollback_compare_branch(const CHAR8* buffer, INT32 size) {
    static const CHAR8 msg[] =
        ": Image rollback index is less than the stored rollback index.";
    INT32 msg_off = find_string_offset(buffer, size, msg);
    INT32 found = -1;
    INT32 count = 0;

    if (msg_off < 0)
        return -1;

    for (INT32 xref = 0; xref <= size - 8; xref += 4) {
        if (calc_adrl_file_offset(buffer, size, xref, 0) != msg_off)
            continue;

        INT32 start = xref - 0x60;
        if (start < 4) start = 4;
        for (INT32 br = xref - 4; br >= start; br -= 4) {
            if (!is_b_cs(read_instr(buffer, br)))
                continue;
            if (!is_cmp_x_reg(read_instr(buffer, br - 4)))
                continue;
            found = br;
            count++;
            break;
        }
    }

    return count == 1 ? found : -1;
}

static INT32 find_write_rollback_index_start(const CHAR8* buffer, INT32 size) {
    static const CHAR8 msg[] =
        "WriteRollbackIndex Location %d, RollbackIndex %d";
    INT32 msg_off = find_string_offset(buffer, size, msg);
    INT32 found = -1;
    INT32 count = 0;

    if (msg_off < 0)
        return -1;

    for (INT32 xref = 0; xref <= size - 8; xref += 4) {
        if (calc_adrl_file_offset(buffer, size, xref, 0) != msg_off)
            continue;

        INT32 start = xref - 0x80;
        if (start < 0) start = 0;
        for (INT32 off = xref; off >= start; off -= 4) {
            if (read_instr(buffer, off) != 0xD503233Fu)
                continue;
            if (!is_sub_sp_sp_imm(read_instr(buffer, off + 4)))
                continue;
            found = off;
            count++;
            break;
        }
    }

    return count == 1 ? found : -1;
}

static INT32 find_tz_rollback_update_blr(const CHAR8* buffer, INT32 size,
                                         UINT32 mov_id, UINT32 movk_id) {
    INT32 found = -1;
    INT32 count = 0;

    for (INT32 off = 0; off <= size - 36; off += 4) {
        if (read_instr(buffer, off) != mov_id)
            continue;
        if (!is_add_x_sp_imm(read_instr(buffer, off + 4), 3))
            continue;
        if (!is_add_x_sp_imm(read_instr(buffer, off + 8), 4))
            continue;
        if (read_instr(buffer, off + 12) != movk_id)
            continue;
        if (read_instr(buffer, off + 16) != 0x2A1F03E2u)
            continue;

        INT32 vtable_load_off = off + 20;
        DecodedInst context_load = decode_at(buffer, vtable_load_off);
        if (context_load.type == INST_LDR_X_IMM
            && context_load.rt == 0 && context_load.rn != 31)
            vtable_load_off += 4;

        if (read_instr(buffer, vtable_load_off) != 0xF9401C08u)
            continue;
        INT32 blr_off = vtable_load_off + 4;
        if (read_instr(buffer, blr_off) != 0xD63F0100u)
            continue;
        if (!is_cbz_x0(read_instr(buffer, blr_off + 4)))
            continue;

        found = blr_off;
        count++;
    }

    return count == 1 ? found : -1;
}

INT32 patch_rollback_protection_bypass(CHAR8* buffer, INT32 size) {
    INT32 compare_br = find_rollback_compare_branch(buffer, size);
    INT32 write_fn = find_write_rollback_index_start(buffer, size);
    INT32 scm_ab_blr = find_tz_rollback_update_blr(
        buffer, size, 0x52802201u, 0x72A64001u);
    INT32 scm_legacy_blr = find_tz_rollback_update_blr(
        buffer, size, 0x528023C1u, 0x72A04001u);

    if (compare_br < 0 || write_fn < 0
        || scm_ab_blr < 0 || scm_legacy_blr < 0) {
        Print_patcher("rollback bypass: incomplete locator "
                      "compare=0x%X write=0x%X scm_ab=0x%X scm_legacy=0x%X, "
                      "skipping\n",
                      compare_br, write_fn, scm_ab_blr, scm_legacy_blr);
        return 0;
    }

    Print_patcher("rollback bypass: compare B.CS @ 0x%X 0x%08X -> B\n",
                  compare_br, read_instr(buffer, compare_br));
    write_instr(buffer, compare_br,
                b_from_b_cond(read_instr(buffer, compare_br)));

    Print_patcher("rollback bypass: WriteRollbackIndex @ 0x%X -> success\n",
                  write_fn);
    write_instr(buffer, write_fn, MOV_W0_WZR);
    write_instr(buffer, write_fn + 4, RET_X30);

    Print_patcher("rollback bypass: TZ AB update BLR @ 0x%X -> success\n",
                  scm_ab_blr);
    write_instr(buffer, scm_ab_blr, MOV_X0_XZR);

    Print_patcher("rollback bypass: TZ legacy update BLR @ 0x%X -> success\n",
                  scm_legacy_blr);
    write_instr(buffer, scm_legacy_blr, MOV_X0_XZR);

    return ROLLBACK_EXPECTED_PATCHES;
}

BOOLEAN PatchBuffer(CHAR8* data, INT32 size) {
    #ifndef DISABLE_PATCH_1
    if (patch_abl_gbl(data, size) != 0)
        Print_patcher("Warning: Failed to patch ABL GBL\n");
    #endif

    #ifndef DISABLE_PATCH_2
    INT32 patched_adrl = patch_adrl_unlocked_to_locked(data, size, 0);
    if (patched_adrl == 0){
        Print_patcher("Warning: ADRL triple not found, skipping\n");
        // not critical, continue with other patches
    }

    if(patched_adrl > 1){
        Print_patcher("Warning: Multiple ADRL triples patched (%d), verify if all are correct\n", patched_adrl);
        return FALSE; //cr
    }
    #endif
    #ifndef DISABLE_PATCH_SNAPSHOT_CANCEL_LOCK
    if (patch_snapshot_cancel_lock_bypass(data, size) == 0)
        Print_patcher("Info: snapshot cancel lock bypass not applied\n");
    #endif
    INT32 offset = -1;
    INT8 lock_register_num = -1;
    INT32 num_patches = patch_abl_bootstate(data, size, &lock_register_num, &offset);
    if (num_patches == 0) {
        Print_patcher("Error: Failed to find/patch ABL Boot State\n");
        free(data);
        return 0;
    }
    Print_patcher("Anchor offset : 0x%X\n", offset);
    Print_patcher("Lock register : W%d\n", (int)lock_register_num);
    Print_patcher("Boot patches: %d\n", num_patches);

    if (find_ldrB_instructio_reverse(data, size, offset, lock_register_num, source_callback) != 0) {
        Print_patcher("Warning: Failed to patch LDRB->STRB chain for W%d\n",
               (int)lock_register_num);
    }

    #ifndef DISABLE_PATCH_7
    INT32 km_unlock_patches = patch_keymaster_unlock_sink(data, size, offset);
    if (km_unlock_patches == 0) {
        Print_patcher("Warning: KeyMaster unlock sink not found\n");
    } else if (km_unlock_patches > 1) {
        Print_patcher("Warning: Multiple KeyMaster unlock sinks patched (%d)\n", km_unlock_patches);
        return FALSE;
    }
    #endif

    #ifndef DISABLE_PATCH_REGION
    if (patch_region_lockout_bypass(data, size) == 0)
        Print_patcher("Info: region lockout bypass (A-1) not applied\n");
    if (patch_region_bypass_stage_a2(data, size) == 0)
        Print_patcher("Info: region lockout bypass (A-2) not applied\n");
    #endif

    #if defined(FORCE_PCBAIDINFO_PRC)
    if (patch_pcbaidinfo_override(data, size, "PRC") == 0)
        Print_patcher("Info: cmdline override (B-1/PRC) not applied\n");
    if (patch_hqsysfs_pcba_config_override(data, size, "PRC") == 0)
        Print_patcher("Info: cmdline override (B-2/PRC) not applied\n");
    #elif defined(FORCE_PCBAIDINFO_ROW)
    if (patch_pcbaidinfo_override(data, size, "ROW") == 0)
        Print_patcher("Info: cmdline override (B-1/ROW) not applied\n");
    if (patch_hqsysfs_pcba_config_override(data, size, "ROW") == 0)
        Print_patcher("Info: cmdline override (B-2/ROW) not applied\n");
    #endif

    #if defined(FORCE_AVB_KEY_ARB)
    if (patch_swap_avb_key_arb(data, size) == 0)
        Print_patcher("Info: AVB key swap (C) not applied\n");
    #endif

    #ifndef DISABLE_PATCH_LOCK_FLASH_CMD
    if (patch_disable_lock_flash_cmd(data, size) == 0)
        Print_patcher("Info: disable lock-flash cmd (D) not applied\n");
    #endif

    #ifndef DISABLE_PATCH_UNLOCK_REGION_TOKEN
    if (patch_unlock_region_token_bypass(data, size) == 0)
        Print_patcher("Info: unlock-region token bypass (E) not applied\n");
    #endif

    #ifndef DISABLE_PATCH_ROLLBACK_PROTECTION
    if (patch_rollback_protection_bypass(data, size)
        != ROLLBACK_EXPECTED_PATCHES)
        Print_patcher("Info: rollback protection bypass (F) not applied\n");
    #endif

    return 1;
}
