//
//  KernelStructScan.m
//  实现见 KernelStructScan.h 的组织说明。这里只补「为什么这么写」与证据指针。
//
//  English-only rule for this translation unit: tools/clex_check.py scans every
//  .c/.h/.m under Aether/ (clex_check.py:28-30, :134) and fails the gate on ANY
//  CJK codepoint outside a string literal or comment. So every comment here is
//  ASCII -- including ones that would read more naturally in Chinese. The
//  reasoning lives in KernelStructScan.h, written in Chinese.
//

#import <Foundation/Foundation.h>
#include <stdarg.h>
#include <string.h>

#include "KernelMemory.h"
#include "KernelSlide.h"
#include "KernelStructScan.h"

#pragma mark - Scan geometry

/*
 * Byte window scanned inside struct task.
 *
 * The authoritative offsets seen in the wild sit in 0x28..0x40, and the head of
 * struct task (the refcount/active word, the map pointer) is well inside the
 * first 0x100 bytes. Scanning 0x00..0x100 costs at most 32 word reads, all
 * inside the task object -- which is the one structure we already know is
 * mapped, since task = proc + proc__object_size was confirmed on device by two
 * independent checks (see KernelStructScan.h).
 */
#define KM_SS_SCAN_BEGIN 0x00ULL
#define KM_SS_SCAN_END 0x100ULL

/*
 * Same window inside the candidate vm_map.
 *
 * vm_map's own pointer fields (lock[2], the vm_map_links pair, rbh_root) all sit
 * below 0x40 -- offsetof(struct _vm_map, pmap) == 0x40 per static_info.h:198-206.
 * 0x100 is generous on purpose: this window must never be the reason a real
 * pmap is missed.
 */
#define KM_SS_CAND_BEGIN 0x00ULL
#define KM_SS_CAND_END 0x100ULL

/*
 * The two pmap head fields. Layout: static_info.h:255-257 (struct pmap begins
 * with `u64 tte; u64 ttep;`). KernelPhysWindow.m:663-665 reads this same pair,
 * so a candidate accepted here means exactly what that probe means by it.
 */
#define KM_SS_PMAP_TTE_OFF 0x00ULL
#define KM_SS_PMAP_TTEP_OFF 0x08ULL

/*
 * Read transaction budget. Each km_read64 issues TWO kread calls
 * (KernelMemory.m:881-885), and a candidate costs two of them for its head
 * pair, so a bad-luck run of 32 candidates x 32 slots would otherwise be a few
 * thousand kernel reads. The probe is read-only, so this budget is about
 * runtime and observability, not safety. Hitting it is reported as a limitation
 * in the summary -- never as a silent truncation, because a partial scan that
 * reads like a clean miss is the one outcome this file must not produce.
 */
#define KM_SS_READ_BUDGET 512

/*
 * Physical-address domain. Deliberately the SAME criterion the project already
 * uses for a physical address (KernelSlide.m:1588 for gPhysBase: non-zero,
 * < 2^48, 16K aligned). If this file invented a looser one, a value accepted
 * here would be rejected by the slide code and the two would disagree about
 * what "looks like a PA" means.
 *
 * Why 16K alignment is hardcoded instead of derived from km_kernel_page_size():
 * page tables are kernel pages, and every iOS device this project supports uses
 * 16K kernel pages (geometry table in KernelPhysWindow.m:21-23). Deriving it
 * would add a sysctl dependency to a judgement that must also hold when sysctl
 * is unavailable, and a 4K-derived mask would be looser, not safer. The device's
 * real page size is printed in the diagnostic, so a 4K device shows up as a
 * known limitation rather than as a quietly wrong answer.
 */
#define KM_SS_PA_LIMIT (1ULL << 48)
#define KM_SS_PA_ALIGN_MASK 0x3fffULL

/*
 * The offsetof value 0x40 for struct _vm_map's pmap (static_info.h:198-206:
 * lock[2] = 16 bytes, then vm_map_header = vm_map_links 4x8 + i32 + u16 +
 * bitfield + rb_head_store 8 = 48 bytes) is NOT redefined as a macro here --
 * km_vm_map_pmap_offset() is the project's single source for it
 * (KernelMemory.m:790-798), and a second copy in this file would be exactly the
 * kind of duplicated constant that drifts. It is used for corroboration
 * reporting only, never as a criterion.
 */

/// Text buffer. The design-review worst case is about 5KB (64 candidate lines +
/// 32 slot lines + the fixed blocks); 16KB leaves room for a future line to be
/// added without silently rewriting the tail.
#define KM_SS_TEXT_SIZE 16384

/// Maximum number of slots that can qualify simultaneously. 32 = the number of
/// slots in the scan window; a 33rd is impossible by construction.
#define KM_SS_MAX_CANDIDATES 32

#pragma mark - State

/// Last diagnostic text. Written once per scan, read by km_scan_diagnostic().
/// Same discipline as KernelPhysWindow.m:114 and KernelSlide.m's g_diagText: the
/// caller keeps both calls on one serial path (AutoTracker.syncExternal),
/// because the kread backend is not thread safe.
static NSString *g_scanText = nil;

/// Read counter and budget flag for the current scan.
static uint64_t g_scanReads = 0;
static bool g_scanBudgetHit = false;

#pragma mark - Helpers

/*
 * Shape gate -- the ONLY door every kread target must pass.
 *
 * Two conditions, both required, and both deliberately identical to what
 * km_read64 itself enforces (KernelMemory.m:877 calls km_is_kernel_address):
 *   (1) kernel address domain: top 16 bits all ones. Same predicate as
 *       km_is_kernel_address (KernelMemory.m:241-244). Deliberately NOT
 *       stricter than km_read64's own gate -- if it were, a read rejected here
 *       would look different from a read rejected by km_read64, and the
 *       diagnostic would stop describing what actually happened.
 *   (2) 8-byte alignment: an 8-byte read at a misaligned address returns two
 *       neighbouring fields spliced together. That value "looks like a
 *       legitimate pointer" and sails through every later check -- the exact
 *       failure mode this project paid for twice: zero is caught by the shape
 *       gate, a plausible wrong value is not (KernelMemory.m:1580,
 *       KernelMemory.m:1695).
 *
 * Every address this file hands to km_read64 -- including ones computed from a
 * value we just read -- comes through here first.
 */
static bool km_ss_readable(uint64_t addr)
{
    if (addr == 0) {
        return false;
    }
    if ((addr >> 48) != 0xFFFF) {
        return false;
    }
    if ((addr & 0x7ULL) != 0) {
        return false;
    }
    return true;
}

/// Kernel virtual address domain. Spelled out rather than delegating to
/// km_is_kernel_address: that function also gates reads, and "is this value in
/// the KVA domain" and "may I read this address" are different questions.
static bool km_ss_is_kva(uint64_t v)
{
    return (v >> 48) == 0xFFFF;
}

/// Physical address domain: non-zero, < 2^48, 16K aligned. See KM_SS_PA_* above.
static bool km_ss_is_pa(uint64_t v)
{
    if (v == 0 || v >= KM_SS_PA_LIMIT) {
        return false;
    }
    return (v & KM_SS_PA_ALIGN_MASK) == 0;
}

/// km_read64 wrapper that (a) enforces the shape gate, (b) counts the budget.
/// Returns false once the budget is exhausted, so the caller stops cleanly
/// instead of issuing reads whose results it cannot account for.
static uint64_t km_ss_read64(uint64_t addr, bool *ok)
{
    if (ok != NULL) {
        *ok = false;
    }
    if (!km_ss_readable(addr)) {
        return 0;
    }
    if (g_scanReads >= KM_SS_READ_BUDGET) {
        g_scanBudgetHit = true;
        return 0;
    }
    g_scanReads++;

    /*
     * *ok from km_read64 means "address shape is legal AND two consecutive reads
     * agreed" (KernelMemory.m:863-870) -- NOT "kread reported success", because
     * kread returns void and cannot report anything. Two reads of a live kernel
     * field agree with overwhelming probability, so !ok is a real signal: the
     * value is untrustworthy and must never be used as a pointer.
     */
    bool inner = false;
    const uint64_t v = km_read64(addr, &inner);
    if (ok != NULL) {
        *ok = inner;
    }
    return v;
}

/*
 * Text builder. Accounting by ACTUAL bytes written (vsnprintf + strlen), never
 * by vsnprintf's return value.
 *
 * This project has a real crash from getting it wrong (KernelMemory.m's
 * km_self_test): on truncation vsnprintf returns "how much WOULD have been
 * written", i.e. more than the room left, so `size - used` wraps on size_t into
 * an astronomical number and the next append writes past the buffer. Here the
 * buffer is static, so an overrun smashes neighbouring static data.
 *
 * The printed text is Chinese on purpose: the panel renders it verbatim and the
 * operators on this project read Chinese. That CJK lives inside string literals
 * only, which is exactly what clex_check.py:52-64 permits.
 */
typedef struct {
    char *buf;
    size_t size;
    size_t used;
    bool truncated;
} km_ss_text;

static void km_ss_append(km_ss_text *t, const char *fmt, ...)
{
    if (t->used >= t->size) {
        t->truncated = true;
        return;
    }
    const size_t room = t->size - t->used;

    va_list args;
    va_start(args, fmt);
    const int written = vsnprintf(t->buf + t->used, room, fmt, args);
    va_end(args);

    t->used += strlen(t->buf + t->used);
    if (written < 0 || (size_t)written >= room) {
        t->truncated = true;
    }
}

/*
 * Replace the first line in place with `summary`.
 *
 * The placeholder summary is written before any work so the panel always has a
 * first line, and this overwrites it once the verdict exists. memcpy, not a
 * second snprintf: the summary only owns line 1, so replacing it neither shifts
 * later lines nor changes t.used. Shorter summaries are space-padded to the
 * placeholder's width so no placeholder characters survive at the line end
 * ("...running == 1. preconditions ==" is the bug this prevents).
 */
static void km_ss_set_summary(char *buf, size_t bufSize, const char *summary)
{
    if (buf == NULL || bufSize == 0 || summary == NULL) {
        return;
    }
    const size_t len = strlen(summary);
    if (len + 1 > bufSize) {
        return;
    }
    memcpy(buf, summary, len);
    buf[len] = '\n';
    for (size_t i = len + 1; i < 64 && i < bufSize - 1 && buf[i] != '\n'; i++) {
        buf[i] = ' ';
    }
}

#pragma mark - Candidate inspection

/*
 * Does this value look like `struct pmap *`?
 *
 * The criterion is one pairing, stated once:
 *
 *     read64(p + 0x00) must be a KERNEL VIRTUAL address   (pmap->tte  == KVA)
 *     read64(p + 0x08) must be a PHYSICAL address         (pmap->ttep == PA)
 *
 * This is the whole hard judgement, and the reason it is hard is that the two
 * domains are mutually exclusive for every non-zero value: a physical address
 * has its top 16 bits clear (ARM_TTE_PA_MASK == 0x0000fffffffff000,
 * static_info.h:54-55), a kernel virtual address has them set. Two adjacent
 * 8-byte words with one shape each is therefore not "some field happens to sit
 * at this offset" -- it is a signature that survives field renames.
 *
 * What can fool it is written down in the header and repeated here: any object
 * whose first two words are one KVA and one page-aligned PA. The second gate --
 * uniqueness across the 32 slots of struct task -- is what actually settles
 * that; see km_scan_task_map_offset().
 *
 * `evidence` receives the branch that decided, so a failure path reads as "why
 * it did not look like a pmap" instead of just "no".
 */
static bool km_ss_pmap_like(uint64_t cand, char *evidence, size_t evidenceSize)
{
    evidence[0] = '\0';

    if (!km_ss_readable(cand)) {
        /*
         * Should be unreachable: the caller only passes values read out of a
         * slot, already shaped. Kept because this address came FROM a read, and
         * "a plausible-looking wrong value" is precisely how unmapped addresses
         * get dereferenced in this project (KernelMemory.m:1580).
         */
        snprintf(evidence, evidenceSize, "candidate address fails the shape gate");
        return false;
    }

    bool ok0 = false;
    const uint64_t tte = km_ss_read64(cand + KM_SS_PMAP_TTE_OFF, &ok0);
    if (!ok0) {
        snprintf(evidence, evidenceSize, "pmap+0x00 read failed (two consecutive reads disagreed)");
        return false;
    }
    if (!km_ss_is_kva(tte)) {
        snprintf(evidence, evidenceSize, "pmap->tte=%#llx is not in the kernel domain",
                 (unsigned long long)tte);
        return false;
    }

    bool ok1 = false;
    const uint64_t ttep = km_ss_read64(cand + KM_SS_PMAP_TTEP_OFF, &ok1);
    if (!ok1) {
        snprintf(evidence, evidenceSize, "pmap+0x08 read failed (two consecutive reads disagreed)");
        return false;
    }
    if (!km_ss_is_pa(ttep)) {
        snprintf(evidence, evidenceSize,
                 "pmap->ttep=%#llx is not PA-shaped (need !=0, <2^48, 16K aligned)",
                 (unsigned long long)ttep);
        return false;
    }

    /*
     * Accepted. The line carries both measured values plus one corroboration
     * that is printed but NOT part of the criterion:
     *
     *   km_phystokv(ttep) vs tte -- two independent sources (the pmap field vs
     *   the ptov_table / gPhysBase mapping) describing the same page table.
     *   Informative when it agrees, silent when it does not:
     *   KernelPhysWindow.m:678-691 already settled that reading, and using it as
     *   a criterion would reject the correct answer whenever the conversion
     *   table is not loaded, because km_phystokv returns 0 by contract then
     *   (KernelSlide.h:150).
     */
    if (km_phystokv_ready()) {
        const uint64_t kv = km_phystokv(ttep);
        snprintf(evidence, evidenceSize,
                 "tte=%#llx (KVA) ttep=%#llx (PA) | kv(ttep)=%#llx %s",
                 (unsigned long long)tte, (unsigned long long)ttep, (unsigned long long)kv,
                 (kv == tte) ? "(agrees with tte: same page table)"
                             : "(differs from tte: sources differ, not a failure)");
    } else {
        snprintf(evidence, evidenceSize,
                 "tte=%#llx (KVA) ttep=%#llx (PA) | conversion table not ready: no corroboration "
                 "(not a failure)",
                 (unsigned long long)tte, (unsigned long long)ttep);
    }
    return true;
}

/// One slot that passed every criterion. Kept so the ambiguity path can list
/// them in full instead of reporting a bare count.
typedef struct {
    uint64_t offset;      // offset inside struct task
    uint64_t value;       // the slot's value == the vm_map candidate
    uint64_t hitOffset;   // offset inside the candidate where the pmap was found
    uint64_t firstHit;    // that pmap candidate's value
    char evidence[192];   // longest branch text is under 160 chars
} km_ss_candidate;

/*
 * Inspect one candidate vm_map: walk its slots, count kernel-shaped values, and
 * record the first pmap-like hit. Returns the number of hits found.
 *
 * The loop guard is cheap and specific: some kernels keep a self-referencing
 * pointer inside struct task, and proc sits at task - object_size, so a
 * candidate that equals task or proc would make us re-walk a structure we have
 * already walked or are about to. Skipping it is recorded, never hidden.
 */
static uint64_t km_ss_inspect_candidate(const km_ss_candidate *slot, uint64_t task, uint64_t proc,
                                        km_ss_text *t, uint64_t *shapedOut,
                                        km_ss_candidate *firstHitOut)
{
    const uint64_t cand = slot->value;
    uint64_t shaped = 0;
    uint64_t hits = 0;

    if (cand == task || cand == proc) {
        km_ss_append(t, "  candidate %#llx equals task/proc -- not descended (loop guard)\n",
                     (unsigned long long)cand);
        *shapedOut = 0;
        return 0;
    }

    for (uint64_t co = KM_SS_CAND_BEGIN; co < KM_SS_CAND_END; co += 8) {
        if (UINT64_MAX - cand < co) {
            break;
        }
        const uint64_t fieldAddr = cand + co;
        if (!km_ss_readable(fieldAddr)) {
            /*
             * Defensive: cand passed the shape gate, so cand+offset can only
             * fail it by overflowing into another domain -- in which case we
             * read nothing and say so.
             */
            km_ss_append(t, "  candidate+%#llx fails the shape gate -- not read\n",
                         (unsigned long long)co);
            break;
        }

        bool ok = false;
        const uint64_t v = km_ss_read64(fieldAddr, &ok);
        if (!ok) {
            if (g_scanBudgetHit) {
                break;
            }
            continue;
        }
        if (!km_ss_is_kva(v)) {
            continue;
        }
        shaped++;

        char evidence[192];
        if (km_ss_pmap_like(v, evidence, sizeof(evidence))) {
            hits++;
            km_ss_append(t, "  HIT task+%#llx -> candidate+%#llx = %#llx : pmap-like {%s}\n",
                         (unsigned long long)slot->offset, (unsigned long long)co,
                         (unsigned long long)v, evidence);
            if (hits == 1) {
                firstHitOut->offset = slot->offset;
                firstHitOut->value = cand;
                firstHitOut->hitOffset = co;
                firstHitOut->firstHit = v;
                snprintf(firstHitOut->evidence, sizeof(firstHitOut->evidence), "%s", evidence);
            }
        }
        /*
         * Candidates that fail are counted, not printed one by one: with 32
         * slots x 32 candidates a full listing would bury the lines that matter.
         * The shaped count keeps "there were pointers inside it, none of them a
         * pmap" visible, which is the difference between "not a vm_map" and
         * "a vm_map I could not confirm".
         */
    }

    *shapedOut = shaped;
    return hits;
}

#pragma mark - Probe

uint64_t km_scan_task_map_offset(void)
{
    static char buffer[KM_SS_TEXT_SIZE];
    memset(buffer, 0, sizeof(buffer));

    km_ss_text t = { buffer, sizeof(buffer), 0, false };
    g_scanReads = 0;
    g_scanBudgetHit = false;

    // Placeholder first line; replaced in place at the end (km_ss_set_summary).
    km_ss_append(&t, "[structscan] STATE=running\n");

    /*
     * `summary` is the single source for line 1 on every exit path, including
     * the two that would otherwise compute it separately (truncation and read
     * budget). One buffer, one writer.
     *
     * It is declared and initialised HERE, before the first `goto done`, and not
     * further down next to the other locals: every early exit jumps to the
     * `done:` label past this point, and jumping over an array declaration's
     * scope is at best a diagnostic and at worst an error. Everything else in
     * this function that a `goto` can skip is a plain scalar, which is harmless.
     */
    char summary[160];
    snprintf(summary, sizeof(summary), "[structscan] STATE=not_ready");

    const uint64_t knownMapOff = km_task_map_offset();
    const uint64_t pmapOff = km_vm_map_pmap_offset();

    uint64_t hitSlot = 0;
    bool haveHit = false;
    bool ambiguous = false;
    const char *state = "not_ready";

    uint64_t scannedSlots = 0;
    uint64_t slotReadFail = 0;
    uint64_t slotNonKva = 0;
    uint64_t slotKvaNoHit = 0;
    uint64_t totalHits = 0;

    km_ss_candidate candidates[KM_SS_MAX_CANDIDATES];
    uint64_t candidateCount = 0;
    memset(candidates, 0, sizeof(candidates));

    /* ---- 1. Preconditions. Nothing below this block runs unless it holds. ---- */
    km_ss_append(&t, "== 1. preconditions ==\n");
    if (!km_ready()) {
        km_ss_append(&t, "km_ready()=false: the kernel read/write layer is not up. "
                         "Zero kreads issued.\n");
        goto done;
    }
    km_ss_append(&t, "km_ready()=true\n");

    {
        const uint64_t pageSize = km_kernel_page_size();
        const uint64_t proc = km_current_proc();
        const uint64_t objectSize = km_proc_object_size();

        km_ss_append(&t, "km_kernel_page_size()=%#llx%s\n", (unsigned long long)pageSize,
                     (pageSize == 0x4000)
                         ? " (16K: the PA alignment criterion applies as written)"
                         : " (NOT 16K: the 16K alignment criterion is a known limitation here)");
        km_ss_append(&t, "km_current_proc()=%#llx  km_proc_object_size()=%#llx  "
                         "km_task_map_offset()=%#llx [version table]  "
                         "km_vm_map_pmap_offset()=%#llx [offsetof]\n",
                     (unsigned long long)proc, (unsigned long long)objectSize,
                     (unsigned long long)knownMapOff, (unsigned long long)pmapOff);

        if (proc == 0 || objectSize == 0) {
            km_ss_append(&t, "current_proc or proc__object_size is 0: the version table did not "
                             "match, or the kernel layer is half up. Without task there is "
                             "nothing to scan.\n");
            goto done;
        }
        if (UINT64_MAX - proc < objectSize) {
            km_ss_append(&t, "proc + proc__object_size overflows\n");
            goto done;
        }

        const uint64_t task = proc + objectSize;
        if (!km_ss_readable(task)) {
            km_ss_append(&t, "task=%#llx fails the shape gate (kernel domain + 8-byte aligned + "
                             "non-zero)\n",
                         (unsigned long long)task);
            goto done;
        }

        /*
         * proc -> task is NOT what this probe questions: task = proc +
         * object_size was confirmed on device by two independent checks (a
         * public chain derives proc as task - object_size and validates it
         * against p_pid; and on the target device task - proc equals the version
         * table constant 0x730). It is printed as the fixed premise, and nothing
         * below touches it.
         */
        km_ss_append(&t, "== 2. task (fixed premise, not under test) ==\n");
        km_ss_append(&t, "proc=%#llx + object_size=%#llx = task=%#llx (shape gate OK)\n",
                     (unsigned long long)proc, (unsigned long long)objectSize,
                     (unsigned long long)task);

        /* ---- 2. Every 8-byte slot of the task prefix. ---- */
        km_ss_append(&t, "== 3. slot scan: task+%#llx .. task+%#llx, step 8 ==\n",
                     (unsigned long long)KM_SS_SCAN_BEGIN,
                     (unsigned long long)KM_SS_SCAN_END);

        for (uint64_t off = KM_SS_SCAN_BEGIN; off < KM_SS_SCAN_END; off += 8) {
            if (UINT64_MAX - task < off) {
                break;
            }
            const uint64_t addr = task + off;
            if (!km_ss_readable(addr)) {
                km_ss_append(&t, "  task+%#llx fails the shape gate -- not read\n",
                             (unsigned long long)off);
                continue;
            }

            bool ok = false;
            const uint64_t value = km_ss_read64(addr, &ok);

            if (g_scanBudgetHit) {
                /*
                 * The budget cut this read off, so the slot was NOT read: it must
                 * not be counted as scanned. A partial scan that reports full
                 * coverage is the one accounting error that would make the
                 * verdict below look trustworthy.
                 */
                km_ss_append(&t, "  read budget %llu exhausted at task+%#llx -- scan stops here\n",
                             (unsigned long long)KM_SS_READ_BUDGET, (unsigned long long)off);
                break;
            }
            scannedSlots++;
            if (!ok) {
                slotReadFail++;
                km_ss_append(&t, "  task+%#llx read failed (two consecutive reads disagreed) -- "
                                 "not treated as zero, not scanned\n",
                             (unsigned long long)off);
                continue;
            }
            if (!km_ss_is_kva(value)) {
                slotNonKva++;
                /*
                 * Non-kernel values are counted, not listed: printing 32 of them
                 * would bury the slots that matter, and the summary count keeps
                 * "nothing here looked like a kernel pointer" visible.
                 */
                continue;
            }

            km_ss_candidate slot;
            memset(&slot, 0, sizeof(slot));
            slot.offset = off;
            slot.value = value;

            uint64_t shaped = 0;
            km_ss_candidate hit;
            memset(&hit, 0, sizeof(hit));
            const uint64_t hits = km_ss_inspect_candidate(&slot, task, proc, &t, &shaped, &hit);
            totalHits += hits;

            if (hits == 0) {
                slotKvaNoHit++;
                km_ss_append(&t, "  task+%#llx = %#llx [KVA]  kernel-shaped slots inside=%llu  "
                                 "pmap-like=0\n",
                             (unsigned long long)off, (unsigned long long)value,
                             (unsigned long long)shaped);
                continue;
            }

            km_ss_append(&t, "  task+%#llx = %#llx [KVA]  kernel-shaped slots inside=%llu  "
                             "pmap-like=%llu  first at candidate+%#llx\n",
                         (unsigned long long)off, (unsigned long long)value,
                         (unsigned long long)shaped, (unsigned long long)hits,
                         (unsigned long long)hit.hitOffset);

            if (candidateCount < KM_SS_MAX_CANDIDATES) {
                candidates[candidateCount++] = hit;
            }
            if (!haveHit) {
                haveHit = true;
                hitSlot = off;
            } else {
                /*
                 * Second qualifying slot: remember it for the listing and let
                 * the verdict below refuse to choose. A tie means the
                 * discriminator is the problem, not the data.
                 */
                ambiguous = true;
            }
        }
    }

    /* ---- 3. Verdict. ---- */
    km_ss_append(&t, "== 4. verdict ==\n");
    km_ss_append(&t, "slots scanned=%llu  read failures=%llu  non-kernel values=%llu  "
                     "kernel-shaped without pmap=%llu  pmap-like hits=%llu%s\n",
                 (unsigned long long)scannedSlots, (unsigned long long)slotReadFail,
                 (unsigned long long)slotNonKva, (unsigned long long)slotKvaNoHit,
                 (unsigned long long)totalHits,
                 g_scanBudgetHit ? "  [read budget hit: results are PARTIAL]" : "");

    if (candidateCount == 0) {
        state = "miss";
        km_ss_append(&t, "No slot of struct task holds a value that looks like vm_map. Reported as a "
                         "MISS on purpose: no fallback offset is substituted, because a guessed "
                         "offset is exactly what made task+0x28 return 0x52bc7e10023e93c0 on the "
                         "target device.\n");
        km_ss_append(&t, "How to read the lines above: if every kernel-shaped value shows "
                         "inside=0, the candidate was not a vm_map at all; if inside>0 but "
                         "pmap-like=0, the candidate had pointer fields but its head was not a "
                         "tte/ttep pair; if non-kernel values dominate, no slot in the window "
                         "held a pointer in the first place.\n");
        snprintf(summary, sizeof(summary), "[structscan] STATE=miss (no vm_map candidate)");
    } else if (g_scanBudgetHit) {
        /*
         * The read budget stopped the scan short. Whatever qualified so far is
         * NOT a unique answer -- uniqueness is a property of the WHOLE window,
         * and the window was not fully walked. Returning the one early hit here
         * would be a guess dressed as a measurement, which is the failure this
         * file exists to avoid. The count and the STATE make it recoverable.
         */
        state = "partial";
        km_ss_append(&t, "Read budget exhausted before the window was fully walked, so the scan is "
                         "PARTIAL and no offset is returned. This is not a miss: %llu slot(s) "
                         "qualified so far, and unnamed slots remain unexamined.\n",
                     (unsigned long long)candidateCount);
        for (uint64_t i = 0; i < candidateCount; i++) {
            km_ss_append(&t, "  #%llu task+%#llx = %#llx  pmap at candidate+%#llx (pmap=%#llx)\n",
                         (unsigned long long)(i + 1), (unsigned long long)candidates[i].offset,
                         (unsigned long long)candidates[i].value,
                         (unsigned long long)candidates[i].hitOffset,
                         (unsigned long long)candidates[i].firstHit);
            km_ss_append(&t, "      %s\n", candidates[i].evidence);
        }
        snprintf(summary, sizeof(summary),
                 "[structscan] STATE=partial (%llu qualified, scan incomplete, reads budget-limited)",
                 (unsigned long long)candidateCount);
    } else if (ambiguous || candidateCount > 1) {
        state = "ambiguous";
        km_ss_append(&t, "MORE THAN ONE slot qualifies, so no offset is returned: the criterion "
                         "set is not selective enough on this kernel. Listed in full:\n");
        for (uint64_t i = 0; i < candidateCount; i++) {
            km_ss_append(&t, "  #%llu task+%#llx = %#llx  pmap at candidate+%#llx (pmap=%#llx)\n",
                         (unsigned long long)(i + 1), (unsigned long long)candidates[i].offset,
                         (unsigned long long)candidates[i].value,
                         (unsigned long long)candidates[i].hitOffset,
                         (unsigned long long)candidates[i].firstHit);
            km_ss_append(&t, "      %s\n", candidates[i].evidence);
        }
        km_ss_append(&t, "Refusing to pick one of %llu.\n", (unsigned long long)candidateCount);
        snprintf(summary, sizeof(summary), "[structscan] STATE=ambiguous (%llu candidates)",
                 (unsigned long long)candidateCount);
    } else {
        state = "hit_unique";
        km_ss_append(&t, "== 5. version table comparison ==\n");
        km_ss_append(&t, "measured task->map = %#llx   version table task__map = %#llx\n",
                     (unsigned long long)hitSlot, (unsigned long long)knownMapOff);
        if (knownMapOff == 0) {
            km_ss_append(&t, "the version table has no task__map for this kernel (dynamic_info did "
                             "not match), so there is nothing to compare against\n");
        } else if (hitSlot == knownMapOff) {
            km_ss_append(&t, "SAME: the hardcoded value is correct on this build. If the pmap "
                             "chain still fails downstream, the cause is elsewhere -- do not "
                             "start editing offsets.\n");
        } else {
            const uint64_t delta = (hitSlot > knownMapOff) ? (hitSlot - knownMapOff)
                                                           : (knownMapOff - hitSlot);
            km_ss_append(&t, "DIFFERENT: measured %#llx vs hardcoded %#llx, difference %#llu bytes "
                             "(%s). The hardcoded value is wrong on this build, which is why "
                             "task+%#llx returned a non-kernel value on device.\n",
                         (unsigned long long)hitSlot, (unsigned long long)knownMapOff,
                         (unsigned long long)delta,
                         (hitSlot > knownMapOff) ? "measured is larger" : "measured is smaller",
                         (unsigned long long)knownMapOff);
        }

        km_ss_append(&t, "== 6. corroboration (NOT used to decide) ==\n");
        km_ss_append(&t, "pmap found at candidate+%#llx; offsetof(struct _vm_map, pmap)=%#llx "
                         "[static_info.h:198-206]\n",
                     (unsigned long long)candidates[0].hitOffset, (unsigned long long)pmapOff);
        if (candidates[0].hitOffset == pmapOff) {
            km_ss_append(&t, "  agree: the pmap field sits exactly where the struct layout says, "
                             "so the layout is unchanged and only task->map moved.\n");
        } else {
            km_ss_append(&t, "  differ: the pmap field is NOT at the layout offset. Either the "
                             "layout differs on this build, or the accepted candidate is not a "
                             "vm_map. Treat the offset as measured but unconfirmed.\n");
        }
        km_ss_append(&t, "  the known map offset (offsetof) %#llx was never a criterion; the "
                         "task-side value printed above is %s it.\n",
                     (unsigned long long)pmapOff,
                     (hitSlot == pmapOff) ? "coincidentally equal to" : "unrelated to");

        snprintf(summary, sizeof(summary), "[structscan] STATE=hit_unique offset=%#llx (version table %#llx)",
                 (unsigned long long)hitSlot, (unsigned long long)knownMapOff);
    }

done:
    /*
     * `state` is read by the truncation branch below on every path that reaches
     * it (not_ready / miss / partial / ambiguous / hit_unique), so the
     * not_ready early exits are not leaving it unread -- this cast only keeps
     * that explicit for a reader who wonders why the variable exists when the
     * summary already carries the verdict text.
     */
    (void)state;

    /*
     * Truncation and budget are LIMITATIONS, not conclusions, and neither may
     * read as a clean miss. The verdict itself was reached before the text was
     * finished and does not depend on the text, so it is kept; the limitation is
     * folded into line 1 so a consumer that only parses the summary still sees
     * it. This is the one place that writes the summary on these two paths --
     * the earlier draft wrote it in two places and they disagreed.
     */
    if (t.truncated || g_scanBudgetHit) {
        char bounded[160];
        const bool uniqueAnswer = haveHit && !ambiguous && candidateCount == 1 && !g_scanBudgetHit;
        if (uniqueAnswer) {
            snprintf(bounded, sizeof(bounded), "[structscan] STATE=%s offset=%#llx (text %s, reads %s)",
                     state, (unsigned long long)hitSlot, t.truncated ? "truncated" : "complete",
                     g_scanBudgetHit ? "budget-limited" : "within budget");
        } else {
            snprintf(bounded, sizeof(bounded), "[structscan] STATE=%s (text %s, reads %s)", state,
                     t.truncated ? "truncated" : "complete",
                     g_scanBudgetHit ? "budget-limited" : "within budget");
        }
        snprintf(summary, sizeof(summary), "%s", bounded);
    }
    km_ss_set_summary(buffer, sizeof(buffer), summary);

    g_scanText = [NSString stringWithUTF8String:buffer];

    /*
     * Return contract: the offset, or 0 for "no unique answer". 0 is a safe
     * sentinel here because offset 0 inside struct task is never the map field
     * (the first qword is struct task's refcount/active word), and because every
     * consumer treats 0 as "unknown" -- see the header for the three distinct
     * reasons 0 can be returned and the STATE line that separates them.
     */
    if (!haveHit || ambiguous || candidateCount > 1 || g_scanBudgetHit) {
        return 0;
    }
    return hitSlot;
}

NSString *km_scan_diagnostic(void)
{
    if (g_scanText == nil) {
        return @"== struct scan ==\n"
                "not run yet. This probe is READ-ONLY: it issues no kernel writes.\n"
                "Call km_scan_task_map_offset() (or the panel button) to run it.\n";
    }
    return g_scanText;
}
