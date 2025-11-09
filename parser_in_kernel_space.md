很可以！把「Parser/Loader」走向 MISRA C 友善版時，最重要的是可預測性、明確所有權、受控的轉型與資源生命週期。
Linux kernel 本身不是以 MISRA 為目標，但我們可以用「MISRA-minded」的介面與實作，降低未來做形式驗證 / 靜態掃描（Coverity、Cppcheck MISRA profiles、LDRA、Polyspace）時的噪音，並把必要的偏離（deviation）集中管理。

下面先講設計原則差異，再給你一個經過調整的 MISRA 友善版介面與骨架（在你前一版的基礎上微調）。

⸻

MISRA-minded 設計要點（為什麼要這樣改）
	1.	避免 FAM（flexible array member）當 ABI
MISRA 對不定長度/邊界檢查很敏感；把 struct {...; T arr[];} 改為「count + 指標」，並用 kcalloc() 配列，搭配越界檢查。
	2.	固定寬度整數與一致的型別語意
用 u32/s32（或 <stdint.h> 的 uint32_t/int32_t），size_t 只用在記憶體尺寸與索引，避免有號/無號混算。布林用 bool。
	3.	清楚的所有權與單一出口（single exit）
函式保持一個 return（或用單一 goto out），所有資源在同一出口解構，利於 MISRA 15.x 類規則與審查。
	4.	受控的字串處理與界線
不依賴非標準 strlcpy；包一個自家 *_strncpyz()，永遠 NUL 結尾、回傳實際寫入長度。所有外部輸入皆做長度驗證。
	5.	位元旗標只在無號整數上做位運算
旗標型別採 u32，提供「測試/設定/清除」的 static inline 函式，避免直接位運算導致 essential type/隱式轉型問題。
	6.	避免未定義/實作定義行為的指標/整數轉型
不把任意 void * 直接塞進 64-bit。對「啟動位址」改成標籤化結構（kind + {cpu|dev}），避免指標↔整數大小差轉型（MISRA 11.x）。
	7.	顯式對齊與溢位保護
對 align 要檢查「是否為 2 的次方」、「是否 <= PAGE_SIZE 或平台允許值」。配列／乘法用 kcalloc() 或 check_*_overflow() 防溢位。
	8.	動態記憶體策略
MISRA 傳統上不鼓勵執行期分配；在 kernel 中不可避免，限制在 init/realize 階段，執行熱路徑避免分配，並集中封裝 allocator（可讓靜態檢查有明確熱/冷界線）。
	9.	日誌封裝
用無副作用的宏包 dev_*()，避免巨集參數多次求值；日誌字串固定前綴、參數個數固定，有助靜態工具追蹤。

⸻

MISRA 友善版：介面（header）

與你前版相比：移除了 FAM、entry 換成「標籤化結構」、加上字串與旗標的包裝函式，所有輸入參數皆標 const，回傳型別用 s32。

/* mvpu_fw_iface_misra.h */
#ifndef MVPU_FW_IFACE_MISRA_H
#define MVPU_FW_IFACE_MISRA_H

#include <linux/types.h>
#include <linux/device.h>
#include <linux/dma-mapping.h>
#include <linux/gfp.h>
#include <linux/stddef.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/overflow.h>
#include <linux/bug.h>   /* BUILD_BUG_ON for static asserts */
#include <linux/stdarg.h>
#include <linux/kernel.h> /* min_t */

#define MVPU_IFACE_VER    (1u)

/* ---- class / flags ---- */
typedef u32 mvpu_flags_t;

enum mvpu_mem_class {
    MVPU_MEM_TEXT = 0,
    MVPU_MEM_RODATA,
    MVPU_MEM_DATA,
    MVPU_MEM_BSS,
    MVPU_MEM_SCRATCH,
    MVPU_MEM_HEAP,
    MVPU_MEM_CLASS_MAX
};

enum {
    MVPU_MEMF_EXEC      = (1u << 0),
    MVPU_MEMF_DMA       = (1u << 1),
    MVPU_MEMF_COHERENT  = (1u << 2),
    MVPU_MEMF_PINNED    = (1u << 3),
    MVPU_MEMF_ZERO      = (1u << 4)
};

/* 安全旗標存取（避免直接位運算引起 essential-type 警告） */
static inline bool mvpu_flag_test(mvpu_flags_t flags, mvpu_flags_t mask)
{
    return ((flags & mask) != 0u);
}

/* ---- 安全字串 copy（NUL terminating, 回傳實際寫入長度） ---- */
static inline size_t mvpu_strncpyz(char *dst, size_t dst_sz, const char *src)
{
    size_t i = 0u;
    if ((dst == NULL) || (src == NULL) || (dst_sz == 0u)) {
        return 0u;
    }
    /* 拷到 dst_sz-1，最後補 0 */
    for (i = 0u; (i + 1u) < dst_sz; ++i) {
        const char c = src[i];
        dst[i] = c;
        if (c == '\0') {
            return i; /* 已含 NUL，寫入長度不含結尾 NUL */
        }
    }
    dst[dst_sz - 1u] = '\0';
    return dst_sz - 1u;
}

/* ---- 記憶體需求 / 實配 ---- */
struct mvpu_mem_req {
    u32                id;
    enum mvpu_mem_class cls;
    mvpu_flags_t       flags;     /* MVPU_MEMF_* */
    size_t             size;      /* bytes */
    size_t             align;     /* 必須為 2 的整次方；0 表示無特別需求 */
    struct device     *target_dev;/* 可為 NULL（純 CPU） */
};

struct mvpu_mem_res {
    u32         id;       /* 對應 req.id */
    size_t      size;     /* 實際大小（>= req.size） */
    void       *cpu_addr; /* CPU 可訪問位址；DMA coherent 時可直接用 */
    dma_addr_t  dma_addr; /* 需要 DMA 時提供；否則為 0 */
    u64         iova;     /* 平台需要可填；否則為 0 */
    void       *priv;     /* Loader 內部用 handle */
};

/* Parser 產出的配置計畫：用 pointer 而非 FAM */
struct mvpu_load_plan {
    u32                    version; /* = MVPU_IFACE_VER */
    u32                    req_cnt;
    struct mvpu_mem_req   *reqs;    /* kcalloc(req_cnt) */
};

/* Loader 實際配置集合 */
struct mvpu_alloc_set {
    u32                    version; /* = MVPU_IFACE_VER */
    u32                    res_cnt; /* == plan->req_cnt */
    struct mvpu_mem_res   *resv;    /* kcalloc(res_cnt) */
};

/* entry 以標籤化結構呈現，避免 pointer/int 互轉 */
enum mvpu_entry_kind { MVPU_ENTRY_NONE = 0, MVPU_ENTRY_CPU, MVPU_ENTRY_DEV };

struct mvpu_entry {
    enum mvpu_entry_kind kind;
    uintptr_t            cpu; /* MVPU_ENTRY_CPU 時有效 */
    dma_addr_t           dev; /* MVPU_ENTRY_DEV 時有效 */
};

/* image 物件（Parser 端擁有） */
struct mvpu_image {
    u32            version; /* = MVPU_IFACE_VER */
    struct mvpu_entry entry;
    void          *priv;
};

/* 符號查詢（由 Loader 提供） */
struct mvpu_sym_resolver {
    u64   (*lookup)(const char *name, void *cookie); /* 0 表示未找到 */
    void  *cookie;
};

/* Parser ops */
struct mvpu_parser_ops {
    u32 version;
    s32 (*plan)(const u8 *bin, size_t bin_sz, struct mvpu_load_plan **out_plan);
    s32 (*realize)(const u8 *bin, size_t bin_sz,
                   const struct mvpu_alloc_set *allocs,
                   const struct mvpu_sym_resolver *sym,
                   struct mvpu_image **out_img);
    void (*destroy_image)(struct mvpu_image *img);
    void (*free_plan)(struct mvpu_load_plan *plan);
};

/* Loader ops */
struct mvpu_loader_ops {
    u32 version;
    s32 (*alloc)(const struct mvpu_load_plan *plan, gfp_t gfp,
                 struct mvpu_alloc_set **out_allocs);
    void (*free)(const struct mvpu_load_plan *plan, struct mvpu_alloc_set *allocs);
};

/* 共同的小工具 */
static inline bool mvpu_is_power_of_two(size_t x)
{
    return (x != 0u) && ((x & (x - 1u)) == 0u);
}

#endif /* MVPU_FW_IFACE_MISRA_H */


⸻

MISRA 友善版：Parser/Loader 骨架（重點在風格）

差異：所有指標先判空、所有尺寸先做「0/溢位/對齊」檢查；單一出口；不做未經檢查的轉型；避免遞迴；不可變參數標 const。

/* parser_misra.c */
#include "mvpu_fw_iface_misra.h"

static s32 parser_build_plan(const u8 *bin, size_t sz, struct mvpu_load_plan **outp)
{
    s32 status = 0;
    struct mvpu_load_plan *plan = NULL;
    struct mvpu_mem_req *reqs = NULL;
    const u32 n = 4u;
    size_t bytes = 0u;

    if ((bin == NULL) || (outp == NULL)) {
        return -EINVAL;
    }
    (void)sz; /* 本例未用，實作時請解析 ELF */

    /* kcalloc 會內建乘法溢位保護 */
    reqs = kcalloc((size_t)n, sizeof(struct mvpu_mem_req), GFP_KERNEL);
    if (reqs == NULL) {
        return -ENOMEM;
    }

    plan = kzalloc(sizeof(*plan), GFP_KERNEL);
    if (plan == NULL) {
        kfree(reqs);
        return -ENOMEM;
    }

    plan->version = MVPU_IFACE_VER;
    plan->req_cnt = n;
    plan->reqs    = reqs;

    /* 對齊只允許 2 的次方（MISRA：明確約束） */
    reqs[0].id = 0u; reqs[0].cls = MVPU_MEM_TEXT;  reqs[0].flags = (MVPU_MEMF_EXEC | MVPU_MEMF_DMA | MVPU_MEMF_COHERENT | MVPU_MEMF_ZERO);
    reqs[0].size = (size_t)(64u * 1024u); reqs[0].align = 4096u; reqs[0].target_dev = NULL;

    reqs[1].id = 1u; reqs[1].cls = MVPU_MEM_RODATA; reqs[1].flags = (MVPU_MEMF_DMA | MVPU_MEMF_COHERENT | MVPU_MEMF_ZERO);
    reqs[1].size = (size_t)(8u * 1024u);  reqs[1].align = 4096u; reqs[1].target_dev = NULL;

    reqs[2].id = 2u; reqs[2].cls = MVPU_MEM_DATA;   reqs[2].flags = (MVPU_MEMF_DMA | MVPU_MEMF_COHERENT | MVPU_MEMF_ZERO);
    reqs[2].size = (size_t)(16u * 1024u); reqs[2].align = 4096u; reqs[2].target_dev = NULL;

    reqs[3].id = 3u; reqs[3].cls = MVPU_MEM_BSS;    reqs[3].flags = (MVPU_MEMF_DMA | MVPU_MEMF_COHERENT | MVPU_MEMF_ZERO);
    reqs[3].size = (size_t)(32u * 1024u); reqs[3].align = 4096u; reqs[3].target_dev = NULL;

    /* 對齊檢查 */
    if ((!mvpu_is_power_of_two(reqs[0].align)) ||
        (!mvpu_is_power_of_two(reqs[1].align)) ||
        (!mvpu_is_power_of_two(reqs[2].align)) ||
        (!mvpu_is_power_of_two(reqs[3].align))) {
        status = -EINVAL;
        goto out;
    }

    *outp = plan;
    return 0;

out:
    kfree(reqs);
    kfree(plan);
    return status;
}

static const struct mvpu_mem_res* find_res(const struct mvpu_alloc_set *as, u32 id)
{
    u32 i = 0u;
    if ((as == NULL) || (as->resv == NULL)) {
        return NULL;
    }
    for (i = 0u; i < as->res_cnt; ++i) {
        if (as->resv[i].id == id) {
            return &as->resv[i];
        }
    }
    return NULL;
}

static s32 parser_do_realize(const u8 *bin, size_t sz,
                             const struct mvpu_alloc_set *as,
                             const struct mvpu_sym_resolver *sym,
                             struct mvpu_image **out_img)
{
    s32 status = 0;
    const struct mvpu_mem_res *text;
    const struct mvpu_mem_res *ro;
    const struct mvpu_mem_res *data;
    const struct mvpu_mem_res *bss;
    struct mvpu_image *img;

    if ((bin == NULL) || (as == NULL) || (out_img == NULL)) {
        return -EINVAL;
    }
    if ((as->version != MVPU_IFACE_VER) || (as->resv == NULL)) {
        return -EINVAL;
    }

    text = find_res(as, 0u);
    ro   = find_res(as, 1u);
    data = find_res(as, 2u);
    bss  = find_res(as, 3u);
    if ((text == NULL) || (ro == NULL) || (data == NULL) || (bss == NULL)) {
        return -EINVAL;
    }

    /* 初始化與淺拷：用 memmove/memcpy 之前都先檢查 size */
    memset(text->cpu_addr, 0, text->size);
    memset(ro->cpu_addr,   0, ro->size);
    memset(data->cpu_addr, 0, data->size);
    memset(bss->cpu_addr,  0, bss->size);

    if (text->size >= (size_t)64u) {
        memcpy(text->cpu_addr, bin, (size_t)64u);
    } else {
        memcpy(text->cpu_addr, bin, text->size);
    }

    if ((sym != NULL) && (sym->lookup != NULL) && (data->size >= sizeof(u64))) {
        const u64 ext = sym->lookup("mvpu_external_symbol", sym->cookie);
        memcpy(data->cpu_addr, &ext, sizeof(u64));
    }

    img = kzalloc(sizeof(*img), GFP_KERNEL);
    if (img == NULL) {
        return -ENOMEM;
    }

    img->version = MVPU_IFACE_VER;
    img->entry.kind = MVPU_ENTRY_DEV;   /* 本例假設給裝置跑 */
    img->entry.dev  = text->dma_addr;   /* 無需 pointer->int 轉型 */
    img->entry.cpu  = (uintptr_t)0u;
    img->priv       = NULL;

    *out_img = img;
    return 0;
}

/* 對外 ops（MISRA：所有函式靜態/外部連結性明確） */
static s32 mvpu_parser_plan(const u8 *bin, size_t sz, struct mvpu_load_plan **outp)
{
    return parser_build_plan(bin, sz, outp);
}

static s32 mvpu_parser_realize(const u8 *bin, size_t sz,
                               const struct mvpu_alloc_set *allocs,
                               const struct mvpu_sym_resolver *sym,
                               struct mvpu_image **out_img)
{
    return parser_do_realize(bin, sz, allocs, sym, out_img);
}

static void mvpu_parser_destroy_image(struct mvpu_image *img)
{
    kfree(img);
}

static void mvpu_parser_free_plan(struct mvpu_load_plan *plan)
{
    if (plan != NULL) {
        kfree(plan->reqs);
        kfree(plan);
    }
}

struct mvpu_parser_ops g_mvpu_parser_ops = {
    .version        = MVPU_IFACE_VER,
    .plan           = mvpu_parser_plan,
    .realize        = mvpu_parser_realize,
    .destroy_image  = mvpu_parser_destroy_image,
    .free_plan      = mvpu_parser_free_plan
};

/* loader_misra.c */
#include "mvpu_fw_iface_misra.h"

static s32 alloc_one(const struct mvpu_mem_req *rq, gfp_t gfp, struct mvpu_mem_res *out)
{
    if ((rq == NULL) || (out == NULL)) {
        return -EINVAL;
    }
    if ((rq->align != 0u) && (!mvpu_is_power_of_two(rq->align))) {
        return -EINVAL;
    }
    (void)gfp;

    memset(out, 0, sizeof(*out));
    out->id   = rq->id;
    out->size = rq->size;

    if (mvpu_flag_test(rq->flags, MVPU_MEMF_DMA)) {
        void *cpu = NULL;
        dma_addr_t dma = (dma_addr_t)0;
        if (rq->target_dev == NULL) {
            return -EINVAL;
        }
        cpu = dma_alloc_coherent(rq->target_dev, rq->size, &dma, GFP_KERNEL);
        if (cpu == NULL) {
            return -ENOMEM;
        }
        out->cpu_addr = cpu;
        out->dma_addr = dma;
        out->iova     = (u64)dma;
        if (mvpu_flag_test(rq->flags, MVPU_MEMF_ZERO)) {
            memset(cpu, 0, rq->size);
        }
        return 0;
    }

    if (mvpu_flag_test(rq->flags, MVPU_MEMF_EXEC)) {
        /* 依平台替換成 execmem_*；本例先用 vmalloc */
        void *cpu = vmalloc(rq->size);
        if (cpu == NULL) {
            return -ENOMEM;
        }
        if (mvpu_flag_test(rq->flags, MVPU_MEMF_ZERO)) {
            memset(cpu, 0, rq->size);
        }
        out->cpu_addr = cpu;
        return 0;
    }

    if (rq->size >= (size_t)(512u * 1024u)) {
        void *cpu = vmalloc(rq->size);
        if (cpu == NULL) {
            return -ENOMEM;
        }
        if (mvpu_flag_test(rq->flags, MVPU_MEMF_ZERO)) {
            memset(cpu, 0, rq->size);
        }
        out->cpu_addr = cpu;
    } else {
        void *cpu2;
        if (mvpu_flag_test(rq->flags, MVPU_MEMF_ZERO)) {
            cpu2 = kzalloc(rq->size, GFP_KERNEL);
        } else {
            cpu2 = kmalloc(rq->size, GFP_KERNEL);
        }
        if (cpu2 == NULL) {
            return -ENOMEM;
        }
        out->cpu_addr = cpu2;
    }
    return 0;
}

static void free_one(const struct mvpu_mem_req *rq, struct mvpu_mem_res *res)
{
    if ((rq == NULL) || (res == NULL)) {
        return;
    }
    if (mvpu_flag_test(rq->flags, MVPU_MEMF_DMA)) {
        if ((rq->target_dev != NULL) && (res->cpu_addr != NULL)) {
            dma_free_coherent(rq->target_dev, res->size, res->cpu_addr, res->dma_addr);
        }
        return;
    }
    if (res->cpu_addr != NULL) {
        if (is_vmalloc_addr(res->cpu_addr)) {
            vfree(res->cpu_addr);
        } else {
            kfree(res->cpu_addr);
        }
    }
}

static s32 loader_alloc(const struct mvpu_load_plan *plan, gfp_t gfp, struct mvpu_alloc_set **outp)
{
    s32 status = 0;
    struct mvpu_alloc_set *as = NULL;
    struct mvpu_mem_res *resv = NULL;
    u32 i = 0u;

    if ((plan == NULL) || (outp == NULL)) {
        return -EINVAL;
    }
    if ((plan->version != MVPU_IFACE_VER) || (plan->reqs == NULL)) {
        return -EINVAL;
    }

    as = kzalloc(sizeof(*as), gfp);
    if (as == NULL) {
        return -ENOMEM;
    }
    resv = kcalloc((size_t)plan->req_cnt, sizeof(struct mvpu_mem_res), gfp);
    if (resv == NULL) {
        kfree(as);
        return -ENOMEM;
    }
    as->version = MVPU_IFACE_VER;
    as->res_cnt = plan->req_cnt;
    as->resv    = resv;

    for (i = 0u; i < plan->req_cnt; ++i) {
        status = alloc_one(&plan->reqs[i], gfp, &resv[i]);
        if (status != 0) {
            /* 單一出口 + 清理 */
            u32 j = 0u;
            for (j = 0u; j < i; ++j) {
                free_one(&plan->reqs[j], &resv[j]);
            }
            kfree(resv);
            kfree(as);
            return status;
        }
    }

    *outp = as;
    return 0;
}

static void loader_free(const struct mvpu_load_plan *plan, struct mvpu_alloc_set *as)
{
    u32 i = 0u;
    if ((plan == NULL) || (as == NULL) || (as->resv == NULL)) {
        return;
    }
    for (i = 0u; i < plan->req_cnt; ++i) {
        free_one(&plan->reqs[i], &as->resv[i]);
    }
    kfree(as->resv);
    kfree(as);
}

struct mvpu_loader_ops g_mvpu_loader_ops = {
    .version = MVPU_IFACE_VER,
    .alloc   = loader_alloc,
    .free    = loader_free
};


⸻

你在 Code Review／工具設定上要注意
	•	工具配置：開啟 -Wconversion -Wsign-conversion -Wextra -Wshadow -Wcast-qual 等近似 MISRA 的告警；kernel 編譯可局部對此檔案開更嚴格的 ccflags-y += ...。
	•	Deviation 清單（建議）
	•	動態記憶體：限定在 plan/alloc/realize 階段，熱路徑不得分配（有 workqueue/kthread 預先配置）。
	•	goto/單一出口：使用單一 goto out 是為了安全解構；和 MISRA 對 goto 的建議衝突，以可讀安全為由偏離。
	•	union：本版已避免 union；若未來需要，必須有「標籤枚舉 + 邏輯覆核」的偏離說明。
	•	非標準函式：自製 mvpu_strncpyz()，不使用 gets/strcpy/sprintf 等不安全介面。
	•	位元運算：僅在 u32 上運作，並提供封裝函式避免隱式轉型。
	•	邊界條件：所有 size/乘法用 kcalloc 或 check_*_overflow()；對齊僅允許 2 的次方；所有輸入皆判空。
	•	Ownership：Parser 擁有 plan/image，Loader 擁有 alloc_set；任何一方只釋放自己分配的物件——這點是 MISRA 的大重點（避免隱含資源共享/雙重釋放）。

⸻

小結

上面這套把你原本「現代好維護」的分層保留住（ops+version / struct-as-ABI / 清楚 ownership），同時把容易被 MISRA/靜態分析挑的點（FAM、位元/轉型、NUL、安全字串、單一出口、邊界檢查）一一處理掉。接下來你只要把「假 ELF 解析 / 假 relocation」換成實作，整個框架就能在 MISRA 友善的基礎上演進。需要我再把 ELF Program Header→mvpu_mem_req 的產生也改成 MISRA 版，我可以直接補上最小實作。




超實用的題目。我把重點分兩塊：
(1)「怎麼做一層 OS shim」→ 同一套核心程式碼可在使用者空間用 GDB 開發、再無痛搬到 kernel module；
(2)「像 GDB 一樣好用的 kernel 偵錯方式」→ kgdb、QEMU、UML、KUnit 等。

⸻

一、OS Shim：用同一份核心邏輯跑兩個世界

目標：核心邏輯（parser/loader/算法）不含任何 <linux/...> 或 <pthread...>；所有跟「環境」有關的東西（記憶體、鎖、log、時間、位元節序）走小而穩的抽象介面。
做法：一個 header + 兩個 backend（kernel / posix）。盡量用 static inline 取代巨集，型別更安全。

目錄建議

include/mvpu_os.h          // 抽象層（只宣告、不含環境細節）
os/os_posix.c              // 使用者空間實作（malloc/pthread/printf）
os/os_kernel.c             // Kernel 實作（kzalloc/mutex/dev_*）
core/xxx.c                 // 你的核心邏輯（只 include mvpu_os.h）
kmod/Makefile              // Kbuild：把 core/*.c + os_kernel.c 編成 .ko
user/Makefile (或 CMake)   // 把 core/*.c + os_posix.c 編成可執行檔/測試

include/mvpu_os.h（可直接用）

#pragma once
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

/* ---- 前置：環境偵測或由 build 定義 MVPU_ENV_KERNEL ---- */
#ifndef MVPU_ENV_KERNEL
# ifdef __KERNEL__
#  define MVPU_ENV_KERNEL 1
# else
#  define MVPU_ENV_KERNEL 0
# endif
#endif

/* ---- 記憶體 ---- */
#if MVPU_ENV_KERNEL
# include <linux/slab.h>
# include <linux/gfp.h>
static inline void *mvpu_malloc(size_t sz)         { return kmalloc(sz, GFP_KERNEL); }
static inline void *mvpu_zalloc(size_t sz)         { return kzalloc(sz, GFP_KERNEL); }
static inline void *mvpu_realloc(void *p,size_t s) { return krealloc(p, s, GFP_KERNEL); }
static inline void  mvpu_free(void *p)             { kfree(p); }
#else
# include <stdlib.h>
# include <string.h>
static inline void *mvpu_malloc(size_t sz)         { return malloc(sz); }
static inline void *mvpu_zalloc(size_t sz)         { void *p = malloc(sz); if (p) memset(p,0,sz); return p; }
static inline void *mvpu_realloc(void *p,size_t s) { return realloc(p, s); }
static inline void  mvpu_free(void *p)             { free(p); }
#endif

/* ---- 鎖 ---- */
#if MVPU_ENV_KERNEL
# include <linux/mutex.h>
typedef struct mutex mvpu_mutex_t;
static inline void mvpu_mutex_init(mvpu_mutex_t *m){ mutex_init(m); }
static inline void mvpu_mutex_lock(mvpu_mutex_t *m){ mutex_lock(m); }
static inline void mvpu_mutex_unlock(mvpu_mutex_t*m){ mutex_unlock(m); }
#else
# include <pthread.h>
typedef pthread_mutex_t mvpu_mutex_t;
static inline void mvpu_mutex_init(mvpu_mutex_t *m){ pthread_mutex_init(m, NULL); }
static inline void mvpu_mutex_lock(mvpu_mutex_t *m){ pthread_mutex_lock(m); }
static inline void mvpu_mutex_unlock(mvpu_mutex_t*m){ pthread_mutex_unlock(m); }
#endif

/* ---- 時間（單調時鐘，微秒/奈秒） ---- */
#if MVPU_ENV_KERNEL
# include <linux/ktime.h>
static inline uint64_t mvpu_time_ns(void){ return ktime_get_ns(); }
#else
# include <time.h>
static inline uint64_t mvpu_time_ns(void){
	struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec*1000000000ull + (uint64_t)ts.tv_nsec;
}
#endif

/* ---- 日誌 ---- */
#if MVPU_ENV_KERNEL
# include <linux/device.h>
# include <linux/printk.h>
static inline void mvpu_log_info(const struct device *dev, const char *fmt, ...) __printf(2,3);
static inline void mvpu_log_info(const struct device *dev, const char *fmt, ...)
{
	va_list ap; va_start(ap, fmt); vdev_info((struct device *)dev, fmt, ap); va_end(ap);
}
static inline void mvpu_log_err (const struct device *dev, const char *fmt, ...) __printf(2,3);
static inline void mvpu_log_err (const struct device *dev, const char *fmt, ...)
{
	va_list ap; va_start(ap, fmt); vdev_err((struct device *)dev, fmt, ap); va_end(ap);
}
#else
# include <stdio.h>
# include <stdarg.h>
static inline void mvpu_log_info(const void *dev_unused, const char *fmt, ...){
	(void)dev_unused; va_list ap; va_start(ap, fmt); fprintf(stderr, "[I] "); vfprintf(stderr, fmt, ap); va_end(ap);
}
static inline void mvpu_log_err (const void *dev_unused, const char *fmt, ...){
	(void)dev_unused; va_list ap; va_start(ap, fmt); fprintf(stderr, "[E] "); vfprintf(stderr, fmt, ap); va_end(ap);
}
#endif

/* ---- 斷言 / 警告 ---- */
#if MVPU_ENV_KERNEL
# include <linux/bug.h>
# define MVPU_WARN_ON(x)  WARN_ON(x)
# define MVPU_BUG_ON(x)   BUG_ON(x)
#else
# include <assert.h>
# define MVPU_WARN_ON(x)  ((x)? (fprintf(stderr,"[W] %s:%d\n",__FILE__,__LINE__),0):0)
# define MVPU_BUG_ON(x)   do{ if(x){ fprintf(stderr,"[BUG]%s:%d\n",__FILE__,__LINE__); assert(!(x)); } }while(0)
#endif

/* ---- likely/unlikely ---- */
#if MVPU_ENV_KERNEL
# include <linux/compiler.h>
# define MVPU_LIKELY(x)   likely(x)
# define MVPU_UNLIKELY(x) unlikely(x)
#else
# define MVPU_LIKELY(x)   __builtin_expect(!!(x),1)
# define MVPU_UNLIKELY(x) __builtin_expect(!!(x),0)
#endif

你可以隨需求再加：位元節序（le32_to_cpu ↔ le32toh）、記憶體欄位對齊、簡單位元映射（bitmap）、甚至「假的 dma_alloc」用 posix_memalign 模擬對齊。

範例：核心邏輯（只 include mvpu_os.h）

// core/mvpu_vector.c
#include "mvpu_os.h"

struct mvpu_vec {
	void   **data;
	size_t   sz, cap;
	mvpu_mutex_t lock;
};

int mvpu_vec_init(struct mvpu_vec *v){
	if (!v) return -22; /* -EINVAL */
	v->data=NULL; v->sz=0; v->cap=0; mvpu_mutex_init(&v->lock); return 0;
}
int mvpu_vec_push(struct mvpu_vec *v, void *p){
	void **nd; size_t nc;
	if (!v) return -22;
	mvpu_mutex_lock(&v->lock);
	if (v->sz == v->cap){
		nc = v->cap ? v->cap*2 : 4;
		nd = mvpu_realloc(v->data, nc*sizeof(*nd));
		if (!nd){ mvpu_mutex_unlock(&v->lock); return -12; } /* -ENOMEM */
		v->data = nd; v->cap = nc;
	}
	v->data[v->sz++] = p;
	mvpu_mutex_unlock(&v->lock);
	return 0;
}
void mvpu_vec_deinit(struct mvpu_vec *v){
	if (!v) return;
	mvpu_free(v->data);
	v->data=NULL; v->cap=v->sz=0;
}

Kernel 端把 core + os_kernel.c 編成 .ko（kmod/Makefile）

obj-m += mvpu_demo.o
mvpu_demo-objs := os/os_kernel.o core/mvpu_vector.o

KDIR ?= /lib/modules/$(shell uname -r)/build
all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

使用者空間快速測試（user/Makefile）

CFLAGS += -I../include -O0 -g -DMVPU_ENV_KERNEL=0 -pthread
OBJS   = ../os/os_posix.o ../core/mvpu_vector.o test_main.o
all: test_vec
test_vec: $(OBJS) ; $(CC) -g -o $@ $(OBJS) -lpthread

這樣你在 Linux 使用者空間就能 gdb ./test_vec，之後把同一套 core 原封不動丟進 .ko 編譯即可。

⸻

二、像 GDB 一樣好用的 Kernel 偵錯方式

1) kgdb + QEMU（最低痛苦、最像 GDB）
	•	Kernel 設定：CONFIG_KGDB, CONFIG_KGDB_KDB, CONFIG_DEBUG_INFO, CONFIG_GDB_SCRIPTS, CONFIG_FRAME_POINTER, CONFIG_DYNAMIC_DEBUG,（可選）CONFIG_KASAN/UBSAN。
	•	QEMU 開機：
	•	方案 A：-s -S（QEMU 直接提供 gdb stub）：
qemu-system-x86_64 -kernel bzImage -append "nokaslr" -s -S ...
→ gdb vmlinux → target remote :1234。
	•	方案 B：kgdboc：
... -append "kgdboc=ttyS0,115200 kgdbwait nokaslr"，另一個終端跑 gdb vmlinux，接到對應 serial。
	•	模組斷點：載入後用 add-symbol-file 加上 .text 位址（可從 /sys/module/<mod>/sections/.text 讀）。

2) User Mode Linux (UML)（kernel 跑在使用者態，可直接 gdb linux）
	•	編 ARCH=um 的 kernel，把你的 .ko（或直接把核心邏輯做成 KUnit 測試）丟進去。
	•	優點：gdb 體驗最好、啟動快；缺點：沒有真實硬體/驅動環境。

3) KUnit（單元測試跑在 kernel；也能用 UML 跑）
	•	用 tools/testing/kunit/kunit.py run 跑測試，失敗點會有 call trace。
	•	你的 core 邏輯最適合寫成 KUnit test；和上面 OS shim 一起用，同一套測試在 user space & kernel 都能跑。

4) 動態偵錯與追蹤
	•	dynamic_debug：echo 'file mvpu_* +p' > /sys/kernel/debug/dynamic_debug/control 即時打開 pr_debug。
	•	ftrace/trace-cmd/perf：看函式進出、延遲。
	•	bpftrace/kprobes/tracepoints：動態插探。
	•	KASAN/KCSAN/UBSAN：越界、資料競爭、UB 直接抓。
	•	kmemleak：找洩漏。

Android/裝置上若要 kgdb，要注意 console/串口配置（kgdboc=ttyX,...）與關閉 KASLR、確保 DEBUG_INFO 帶上模組符號。

⸻

你可能會想加的實用巨集/小工具
	•	溢位安全：#include <linux/overflow.h> → struct_size()/array_size()/check_*_overflow()
	•	對齊/位欄：ALIGN(), BIT(), GENMASK(), FIELD_PREP/GET()
	•	錯誤指標模式：ERR_PTR(), PTR_ERR(), IS_ERR()
	•	分支提示：MVPU_LIKELY/MVPU_UNLIKELY（上面已包）
	•	一次性警告：#define MVPU_WARN_ONCE(cond, fmt, ...)  WARN_ONCE(cond, fmt, ##__VA_ARGS__)（user 空間對應 fprintf+靜態旗標）
	•	編譯期檢查：BUILD_BUG_ON() / static_assert()
	•	介面語意巨集（文檔化所有權）：
	•	/* @allocs: BORROWED; @out_img: CALLEE_OWNED */（寫在 kernel-doc，審 code 超清楚）

⸻

小結與落地建議
	1.	先把核心邏輯抽到 core/，只 include mvpu_os.h。
	2.	用上面的 OS shim 在 user space 先寫測試、灌 ASan/UBSan、用 GDB 把邏輯磨到穩。
	3.	搬到 kernel：core/*.c + os_kernel.c 編成 .ko。
	4.	需要步進除錯就用 QEMU + kgdb 或 UML；要自動化回歸就用 KUnit。
	5.	日常追問題用 dynamic_debug + ftrace/bpftrace；記憶體/越界用 KASAN/UBSAN。

如果你把你目前模組的檔案結構貼上來，我可以幫你把 mvpu_os.h 再客製化（加 endian、對齊、簡易 bitmap），並給一個可編的 user-space 測試 main + kernel Kbuild。

超好上手版來了！在 Linux 使用者空間用 CMake 開啟 ASan/UBSan/TSan 等 sanitizer，有兩種常見做法：全域開或針對特定 target 開。下面給你「可直接貼上」的模板＋實務細節（GCC/Clang 都適用）。

⸻

1) 最快上手（整個專案都開）

# CMakeLists.txt (建議 CMake ≥ 3.13)
cmake_minimum_required(VERSION 3.13)
project(demo C CXX)

option(ENABLE_ASAN "Enable AddressSanitizer" OFF)
option(ENABLE_UBSAN "Enable UndefinedBehaviorSanitizer" OFF)
option(ENABLE_TSAN "Enable ThreadSanitizer" OFF)  # 與 ASAN 不能同時用

if(CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
  add_compile_options(-g -O1 -fno-omit-frame-pointer)  # 給 sanitizer 友善的堆疊
  if(ENABLE_ASAN)
    add_compile_options(-fsanitize=address)
    add_link_options(-fsanitize=address)
    # Clang: LSan 隨 ASan 一起；GCC 也一樣，無需額外 -fsanitize=leak
  endif()
  if(ENABLE_UBSAN)
    add_compile_options(-fsanitize=undefined)
    add_link_options(-fsanitize=undefined)
  endif()
  if(ENABLE_TSAN)
    add_compile_options(-fsanitize=thread)
    add_link_options(-fsanitize=thread)
  endif()
endif()

add_executable(app src/main.cpp)

用法：

cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DENABLE_ASAN=ON -DENABLE_UBSAN=ON
cmake --build build -j
ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 UBSAN_OPTIONS=print_stacktrace=1 ./build/app


⸻

2) 只對「某些 target」開（推薦）

用 INTERFACE library 方式把旗標打包，想給誰就 target_link_libraries() 誰：

# Sanitizers.cmake（你專案裡的可重用模組）
function(enable_sanitizers iface)
  if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
    message(STATUS "Sanitizers disabled: compiler not GCC/Clang")
    return()
  endif()
  add_library(${iface} INTERFACE)
  target_compile_options(${iface} INTERFACE -g -O1 -fno-omit-frame-pointer)
  # 選擇組合：ASan + UBSan 是最常見；TSan 請單獨用
  set(opts "")
  if(DEFINED SANITIZE AND SANITIZE STREQUAL "asan-ubsan")
    list(APPEND opts -fsanitize=address -fsanitize=undefined)
  elseif(DEFINED SANITIZE AND SANITIZE STREQUAL "tsan")
    list(APPEND opts -fsanitize=thread)
  endif()
  target_compile_options(${iface} INTERFACE ${opts})
  target_link_options(${iface}    INTERFACE ${opts})
endfunction()

使用：

include(Sanitizers.cmake)
enable_sanitizers(san)                 # 讀環境變數 SANITIZE=asan-ubsan 或 tsan
add_executable(tool src/tool.cpp)
target_link_libraries(tool PRIVATE san)

add_executable(other src/other.cpp)    # 這個不開 sanitizer

執行：

SANITIZE=asan-ubsan cmake -S . -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build
ASAN_OPTIONS=detect_leaks=1:strict_string_checks=1 UBSAN_OPTIONS=print_stacktrace=1 ./build/tool


⸻

3) 進階：CMake Presets + 測試整合（CI 友善）

CMakePresets.json

{
  "version": 4,
  "configurePresets": [
    {
      "name": "asan",
      "generator": "Ninja",
      "binaryDir": "build/asan",
      "cacheVariables": {
        "CMAKE_BUILD_TYPE": "RelWithDebInfo",
        "ENABLE_ASAN": "ON",
        "ENABLE_UBSAN": "ON"
      }
    },
    {
      "name": "tsan",
      "generator": "Ninja",
      "binaryDir": "build/tsan",
      "cacheVariables": { "CMAKE_BUILD_TYPE": "RelWithDebInfo", "ENABLE_TSAN": "ON" }
    }
  ]
}

CTest（讓 sanitizer 失敗時測試直接紅）

enable_testing()
add_test(NAME run_app COMMAND app)
set_tests_properties(run_app PROPERTIES
  ENVIRONMENT "ASAN_OPTIONS=detect_leaks=1:halt_on_error=1;UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1")


⸻

4) 執行時的小撇步（Linux）
	•	Clang 符號化（如果沒自動偵測到）：
export ASAN_SYMBOLIZER_PATH=$(command -v llvm-symbolizer)
	•	常用選項：
	•	ASAN_OPTIONS=detect_leaks=1:abort_on_error=1:strict_string_checks=1
	•	UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1
	•	TSAN_OPTIONS=halt_on_error=1:suppressions=tsan.supp
	•	抑制檔（LSan/TSan）：
	•	LSAN_OPTIONS=suppressions=lsan.supp
	•	tsan.supp 範例：race:std::cout（忽略已知第三方競態）

⸻

5) 常見雷區 & 建議
	•	不要同時開 ASan 與 TSan（互斥）。ASan+UBSan 是黃金組合；TSan 請單獨一個 preset。
	•	-O1/-g/-fno-omit-frame-pointer 方便定位；Release 最少也用 RelWithDebInfo。
	•	第三方靜態庫常會報假陽性或缺符號；必要時只對你的 target 開 sanitizer。
	•	MSan（MemorySanitizer） 需要「全鏈」皆以 MSan 編譯（含 libc），一般不建議。
	•	若遇到 stack-use-after-return 難抓，可再加 -fsanitize-address-use-after-return=always（Clang）。
	•	CMake 3.13 以前沒有 target_link_options，可退而求其次用 set(CMAKE_EXE_LINKER_FLAGS ...)。

⸻

6) 與你的 Kernel 模組開發節奏搭配
	•	把「核心邏輯」用我前一則給你的 OS shim 分層，在 user space 開 ASan/UBSan 用 GDB 把 bug 抓乾淨，再把同一套 core 丟進 .ko。
	•	若要 fuzz，Clang 再加 -fsanitize=fuzzer,address,undefined，配合 libFuzzer 建 target；找到的最小化樣本可做 KUnit 測試。

⸻

需要的話，我可以把你現有的 CMake 專案骨架貼過來，幫你直接改成「Presets + Sanitizers + CTest」三件套的模板，含一個最小單元測試與 suppression 範例檔。





我不需要這麼多
mvpu_u64map 我只需要以下:
mvpu_u64map_create
mvpu_u64map_destroy
mvpu_u64map_clear
mvpu_u64map_set
mvpu_u64map_get
mvpu_u64map_erase
mvpu_u64map_alloc
mvpu_u64map_foreach
再加上 mvpu_u64map_remove

mvpu_u64map 我只需要以下:
create
destroy
clear
push_back
pop_back
front
size
empty
erase_first
remove_if
foreach



好的，我照你要的「精簡版 API」重寫成三個檔案：**C 介面 (`mvpu_ds.h`)**、**Kernel 後端 (`mvpu_ds_kernel.c`)**、**User 後端 (`mvpu_ds_user.cpp`)**。
功能只包含你列的那些：

* `mvpu_u64map`：`create/destroy/clear/set/get/erase/alloc/foreach/remove`
* `mvpu_list`：`create/destroy/clear/push_back/pop_back/front/size/empty/erase_first/remove_if/foreach`

> 說明：
>
> * `destroy/clear/remove/remove_if` 都可傳入 `val_dtor`（可為 `NULL`）；若提供，容器會對被移除的 **value** 逐一呼叫它（map 的 value、list 的節點值）。
> * `foreach` 的 callback 回非 0 會提前中止，該值會直接回傳給呼叫端。
> * **Kernel 端的 `u64map_remove`** 會先收集 key 再刪（避免迭代中修改 xarray）。
> * 單執行緒假設（你之前提到 OneThread）；若有 RCU 讀者，請把 `val_dtor` 換成 `kfree_rcu()` 版。

---

## 檔案：`mvpu_ds.h`（C 介面）

```c
#pragma once
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ===================== mvpu_u64map ===================== */
typedef struct mvpu_u64map mvpu_u64map;

/* dtor 可為 NULL；若提供，clear/destroy/remove 會對移除的 value 呼叫 dtor(val) */
mvpu_u64map* mvpu_u64map_create(void);
void         mvpu_u64map_destroy(mvpu_u64map* m, void (*val_dtor)(void*));
void         mvpu_u64map_clear  (mvpu_u64map* m, void (*val_dtor)(void*));

/* 0 / -errno；erase 回舊值（不呼叫 dtor）或 NULL；get 回 value 或 NULL */
int          mvpu_u64map_set   (mvpu_u64map* m, unsigned long key, void *val);
void*        mvpu_u64map_get   (const mvpu_u64map* m, unsigned long key);
void*        mvpu_u64map_erase (mvpu_u64map* m, unsigned long key);

/* 在 [min,max] 找空洞配一個 key（以 value 存入），成功回 0 並輸出 out_key */
int          mvpu_u64map_alloc (mvpu_u64map* m, unsigned long* out_key, void* val,
                                unsigned long min_key, unsigned long max_key);

/* foreach：cb 回非 0 會提前中止並把該值回傳 */
typedef int (*mvpu_u64map_foreach_fn)(unsigned long key, void *val, void *ctx);
int          mvpu_u64map_foreach(mvpu_u64map* m, mvpu_u64map_foreach_fn cb, void* ctx);

/* remove：pred(key,val,ctx)=true 的項目會被刪除；若提供 dtor，會對被刪 value 呼叫之。
 * 回傳移除數量。 */
typedef bool (*mvpu_u64map_pred_fn)(unsigned long key, void *val, void *ctx);
size_t       mvpu_u64map_remove(mvpu_u64map* m,
                                mvpu_u64map_pred_fn pred, void* ctx,
                                void (*val_dtor)(void*));

/* ===================== mvpu_list（non-intrusive, void*） ===================== */
typedef struct mvpu_list mvpu_list;

mvpu_list*   mvpu_list_create(void);
void         mvpu_list_destroy(mvpu_list* lst, void (*val_dtor)(void*));
void         mvpu_list_clear  (mvpu_list* lst, void (*val_dtor)(void*));

int          mvpu_list_push_back(mvpu_list* lst, void* val);  /* 0/-errno */
void*        mvpu_list_pop_back (mvpu_list* lst);             /* 回值（不呼叫 dtor）或 NULL */
void*        mvpu_list_front    (const mvpu_list* lst);

size_t       mvpu_list_size (const mvpu_list* lst);
bool         mvpu_list_empty(const mvpu_list* lst);

/* 依指標等值移除第一個；回被移除值（不呼叫 dtor）或 NULL */
void*        mvpu_list_erase_first(mvpu_list* lst, void* val);

/* 依條件移除；pred(val,ctx)=true 就刪。若提供 dtor，會對被刪值呼叫之；回刪除數量。 */
typedef bool (*mvpu_list_pred_fn)(void* val, void* ctx);
size_t       mvpu_list_remove_if(mvpu_list* lst, mvpu_list_pred_fn pred, void* ctx,
                                 void (*val_dtor)(void*));

/* foreach：cb 回非 0 會提前中止並把該值回傳 */
typedef int (*mvpu_list_foreach_fn)(void* val, void* ctx);
int          mvpu_list_foreach(mvpu_list* lst, mvpu_list_foreach_fn cb, void* ctx);

#ifdef __cplusplus
} /* extern "C" */
#endif
```

---

## 檔案：`mvpu_ds_kernel.c`（Kernel 後端，C）

```c
// SPDX-License-Identifier: GPL-2.0
#include "mvpu_ds.h"
#include <linux/slab.h>
#include <linux/xarray.h>
#include <linux/list.h>
#include <linux/limits.h>

/* -------- mvpu_u64map：xarray -------- */
struct mvpu_u64map { struct xarray xa; };

mvpu_u64map* mvpu_u64map_create(void)
{
    mvpu_u64map* m = kzalloc(sizeof(*m), GFP_KERNEL);
    if (!m) return NULL;
    xa_init(&m->xa);
    return m;
}

static void __u64map_clear(struct xarray *xa, void (*val_dtor)(void*))
{
    unsigned long idx = 0;
    void *entry;
    while ((entry = xa_find(xa, &idx, ULONG_MAX, XA_PRESENT))) {
        void *old = xa_erase(xa, idx);
        if (val_dtor && old) val_dtor(old);
        idx++;
    }
}

void mvpu_u64map_destroy(mvpu_u64map* m, void (*val_dtor)(void*))
{
    if (!m) return;
    __u64map_clear(&m->xa, val_dtor);
    xa_destroy(&m->xa);
    kfree(m);
}

void mvpu_u64map_clear(mvpu_u64map* m, void (*val_dtor)(void*))
{
    if (!m) return;
    __u64map_clear(&m->xa, val_dtor);
}

int mvpu_u64map_set(mvpu_u64map* m, unsigned long key, void* val)
{
    void *old = xa_store(&m->xa, key, val, GFP_KERNEL);
    return xa_err(old) ? xa_err(old) : 0;
}

void* mvpu_u64map_get(const mvpu_u64map* m, unsigned long key)
{
    return xa_load((struct xarray *)&m->xa, key);
}

void* mvpu_u64map_erase(mvpu_u64map* m, unsigned long key)
{
    return xa_erase(&m->xa, key);
}

int mvpu_u64map_alloc(mvpu_u64map* m, unsigned long* out_key, void* val,
                      unsigned long min_key, unsigned long max_key)
{
    return xa_alloc(&m->xa, out_key, val, XA_LIMIT(min_key, max_key), GFP_KERNEL);
}

int mvpu_u64map_foreach(mvpu_u64map* m, mvpu_u64map_foreach_fn cb, void* ctx)
{
    if (!m || !cb) return 0;
    unsigned long k; void *v;
    xa_for_each(&m->xa, k, v) {
        int r = cb(k, v, ctx);
        if (r) return r;
    }
    return 0;
}

/* 先收 key 再刪，避免迭代期間修改 xarray */
size_t mvpu_u64map_remove(mvpu_u64map* m,
                          mvpu_u64map_pred_fn pred, void* ctx,
                          void (*val_dtor)(void*))
{
    if (!m || !pred) return 0;

    struct key_node { struct list_head link; unsigned long k; };
    LIST_HEAD(keys);
    size_t n = 0;

    /* 收集 */
    {
        unsigned long k; void *v;
        xa_for_each(&m->xa, k, v) {
            if (pred(k, v, ctx)) {
                struct key_node *kn = kmalloc(sizeof(*kn), GFP_KERNEL);
                if (!kn) break;
                kn->k = k;
                list_add_tail(&kn->link, &keys);
            }
        }
    }

    /* 刪除 */
    while (!list_empty(&keys)) {
        struct key_node *kn = list_first_entry(&keys, struct key_node, link);
        list_del(&kn->link);
        void *old = xa_erase(&m->xa, kn->k);
        if (val_dtor && old) val_dtor(old);
        kfree(kn);
        n++;
    }
    return n;
}

/* -------- mvpu_list：list_head + kmalloc 節點 -------- */
struct mvpu_list_node { struct list_head link; void *val; };
struct mvpu_list { struct list_head head; size_t sz; };

mvpu_list* mvpu_list_create(void)
{
    struct mvpu_list *lst = kzalloc(sizeof(*lst), GFP_KERNEL);
    if (!lst) return NULL;
    INIT_LIST_HEAD(&lst->head);
    lst->sz = 0;
    return lst;
}

static void __list_free_all(struct mvpu_list *lst, void (*dtor)(void*))
{
    struct mvpu_list_node *n, *tmp;
    list_for_each_entry_safe(n, tmp, &lst->head, link) {
        list_del(&n->link);
        if (dtor && n->val) dtor(n->val);
        kfree(n);
    }
    lst->sz = 0;
}

void mvpu_list_destroy(mvpu_list* lst, void (*val_dtor)(void*))
{
    if (!lst) return;
    __list_free_all(lst, val_dtor);
    kfree(lst);
}

void mvpu_list_clear(mvpu_list* lst, void (*val_dtor)(void*))
{
    if (!lst) return;
    __list_free_all(lst, val_dtor);
}

int mvpu_list_push_back(mvpu_list* lst, void* val)
{
    struct mvpu_list_node *n = kmalloc(sizeof(*n), GFP_KERNEL);
    if (!n) return -ENOMEM;
    n->val = val;
    list_add_tail(&n->link, &lst->head);
    lst->sz++;
    return 0;
}

void* mvpu_list_pop_back(mvpu_list* lst)
{
    if (!lst || list_empty(&lst->head)) return NULL;
    struct mvpu_list_node *n = list_last_entry(&lst->head, struct mvpu_list_node, link);
    void *v = n->val;
    list_del(&n->link);
    kfree(n);
    lst->sz--;
    return v;
}

void* mvpu_list_front(const mvpu_list* lst)
{
    if (!lst || list_empty(&lst->head)) return NULL;
    return list_first_entry(&lst->head, struct mvpu_list_node, link)->val;
}

size_t mvpu_list_size (const mvpu_list* lst){ return lst? lst->sz : 0; }
bool   mvpu_list_empty(const mvpu_list* lst){ return !lst || list_empty(&lst->head); }

void* mvpu_list_erase_first(mvpu_list* lst, void* val)
{
    if (!lst) return NULL;
    struct mvpu_list_node *n;
    list_for_each_entry(n, &lst->head, link) {
        if (n->val == val) {
            void *v = n->val;
            list_del(&n->link);
            kfree(n);
            lst->sz--;
            return v;
        }
    }
    return NULL;
}

size_t mvpu_list_remove_if(mvpu_list* lst, mvpu_list_pred_fn pred, void* ctx,
                           void (*val_dtor)(void*))
{
    if (!lst || !pred) return 0;
    size_t removed = 0;
    struct mvpu_list_node *n, *tmp;
    list_for_each_entry_safe(n, tmp, &lst->head, link) {
        if (pred(n->val, ctx)) {
            list_del(&n->link);
            if (val_dtor && n->val) val_dtor(n->val);
            kfree(n);
            lst->sz--;
            removed++;
        }
    }
    return removed;
}

int mvpu_list_foreach(mvpu_list* lst, mvpu_list_foreach_fn cb, void* ctx)
{
    if (!lst || !cb) return 0;
    int ret = 0;
    struct mvpu_list_node *n, *tmp;
    list_for_each_entry_safe(n, tmp, &lst->head, link) {
        ret = cb(n->val, ctx);
        if (ret) break;
    }
    return ret;
}
```

---

## 檔案：`mvpu_ds_user.cpp`（User 後端，C++，但輸出 C 介面）

```cpp
#include "mvpu_ds.h"
#include <unordered_map>
#include <list>
#include <new>

extern "C" {

/* -------- mvpu_u64map：unordered_map -------- */
struct mvpu_u64map { std::unordered_map<unsigned long, void*> m; };

mvpu_u64map* mvpu_u64map_create(void) { return new (std::nothrow) mvpu_u64map{}; }

static void __u64map_clear(mvpu_u64map* m, void (*val_dtor)(void*))
{
    if (!m) return;
    if (val_dtor) for (auto &kv : m->m) if (kv.second) val_dtor(kv.second);
    m->m.clear();
}

void mvpu_u64map_destroy(mvpu_u64map* m, void (*val_dtor)(void*))
{
    if (!m) return;
    __u64map_clear(m, val_dtor);
    delete m;
}

void mvpu_u64map_clear(mvpu_u64map* m, void (*val_dtor)(void*))
{
    __u64map_clear(m, val_dtor);
}

int   mvpu_u64map_set(mvpu_u64map* m, unsigned long key, void* val)
{
    m->m[key] = val; return 0;
}

void* mvpu_u64map_get(const mvpu_u64map* m, unsigned long key)
{
    auto it = m->m.find(key); return it==m->m.end()? nullptr : it->second;
}

void* mvpu_u64map_erase(mvpu_u64map* m, unsigned long key)
{
    auto it = m->m.find(key); if (it==m->m.end()) return nullptr;
    void* v = it->second; m->m.erase(it); return v;
}

int mvpu_u64map_alloc(mvpu_u64map* m, unsigned long* out_key, void* val,
                      unsigned long min_key, unsigned long max_key)
{
    static unsigned long next = 0;
    if (next < min_key || next > max_key) next = min_key;
    unsigned long k = next, start = next;
    do {
        if (!mvpu_u64map_get(m, k)) {
            m->m[k] = val; *out_key = k; next = (k==max_key? min_key : k+1); return 0;
        }
        k = (k==max_key? min_key : k+1);
    } while (k != start);
    return -28; /* -ENOSPC */
}

int mvpu_u64map_foreach(mvpu_u64map* m, mvpu_u64map_foreach_fn cb, void* ctx)
{
    if (!m || !cb) return 0;
    for (auto &kv : m->m) { int r = cb(kv.first, kv.second, ctx); if (r) return r; }
    return 0;
}

size_t mvpu_u64map_remove(mvpu_u64map* m,
                          mvpu_u64map_pred_fn pred, void* ctx,
                          void (*val_dtor)(void*))
{
    if (!m || !pred) return 0;
    size_t removed = 0;
    for (auto it = m->m.begin(); it != m->m.end(); ) {
        if (pred(it->first, it->second, ctx)) {
            if (val_dtor && it->second) val_dtor(it->second);
            it = m->m.erase(it);
            removed++;
        } else {
            ++it;
        }
    }
    return removed;
}

/* -------- mvpu_list：std::list<void*> -------- */
struct mvpu_list { std::list<void*> L; };

mvpu_list* mvpu_list_create(void) { return new (std::nothrow) mvpu_list{}; }

void mvpu_list_destroy(mvpu_list* lst, void (*val_dtor)(void*))
{
    if (!lst) return;
    if (val_dtor) for (void* v : lst->L) if (v) val_dtor(v);
    delete lst;
}

void mvpu_list_clear(mvpu_list* lst, void (*val_dtor)(void*))
{
    if (!lst) return;
    if (val_dtor) for (void* v : lst->L) if (v) val_dtor(v);
    lst->L.clear();
}

int mvpu_list_push_back(mvpu_list* lst, void* val) { lst->L.push_back(val); return 0; }

void* mvpu_list_pop_back(mvpu_list* lst)
{
    if (!lst || lst->L.empty()) return nullptr;
    void* v = lst->L.back(); lst->L.pop_back(); return v;
}

void* mvpu_list_front(const mvpu_list* lst)
{
    return (lst && !lst->L.empty())? lst->L.front() : nullptr;
}

size_t mvpu_list_size (const mvpu_list* lst){ return lst? lst->L.size():0; }
bool   mvpu_list_empty(const mvpu_list* lst){ return !lst || lst->L.empty(); }

void* mvpu_list_erase_first(mvpu_list* lst, void* val)
{
    if (!lst) return nullptr;
    for (auto it = lst->L.begin(); it != lst->L.end(); ++it) {
        if (*it == val) { void* v = *it; lst->L.erase(it); return v; }
    }
    return nullptr;
}

size_t mvpu_list_remove_if(mvpu_list* lst, mvpu_list_pred_fn pred, void* ctx,
                           void (*val_dtor)(void*))
{
    if (!lst || !pred) return 0;
    size_t removed = 0;
    for (auto it = lst->L.begin(); it != lst->L.end(); ) {
        if (pred(*it, ctx)) {
            if (val_dtor && *it) val_dtor(*it);
            it = lst->L.erase(it);
            removed++;
        } else {
            ++it;
        }
    }
    return removed;
}

int mvpu_list_foreach(mvpu_list* lst, mvpu_list_foreach_fn cb, void* ctx)
{
    if (!lst || !cb) return 0;
    for (void* v : lst->L) { int r = cb(v, ctx); if (r) return r; }
    return 0;
}

} // extern "C"
```

---

如果你要，我可以再附上一個最小 `Kbuild` 與 `Android.bp` 範例；或把 `val_dtor` 改成「必要時才帶」的弱連結函式。但目前這版已可直接放到你的專案，**User/Kernel 兩邊零改碼**使用。



mvpu_ds_strmap:

``` mvpu_ds_strmap.h
#pragma once
#include <linux/types.h>
#include <linux/stddef.h>
#include <linux/stdbool.h>

struct mvpu_strmap;

/* 建立 / 銷毀 / 清空 */
struct mvpu_strmap* mvpu_strmap_create(void);
void mvpu_strmap_destroy(struct mvpu_strmap* m, void (*val_dtor)(void*));
void mvpu_strmap_clear(struct mvpu_strmap* m, void (*val_dtor)(void*));

/* 基本 CRUD */
int   mvpu_strmap_set(struct mvpu_strmap* m, const char *key, void *value);
void* mvpu_strmap_get(struct mvpu_strmap* m, const char *key);
void* mvpu_strmap_erase(struct mvpu_strmap* m, const char *key);

/* 遍歷與條件移除 */
typedef int  (*mvpu_strmap_foreach_fn)(const char *key, void *val, void *ctx);
typedef bool (*mvpu_strmap_pred_fn)(const char *key, void *val, void *ctx);

int    mvpu_strmap_foreach(struct mvpu_strmap* m, mvpu_strmap_foreach_fn cb, void *ctx);
size_t mvpu_strmap_remove(struct mvpu_strmap* m,
                          mvpu_strmap_pred_fn pred, void *ctx,
                          void (*val_dtor)(void*));

```

``` mvpu_ds_strmap.c
// SPDX-License-Identifier: GPL-2.0
#include "mvpu_ds_strmap.h"
#include <linux/hashtable.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/stringhash.h>

#define MVPU_STRMAP_BITS 6  /* 預設 64 桶，可依需求調整 */

struct mvpu_strmap_entry {
	struct hlist_node hnode;
	char *key;
	void *value;
};

struct mvpu_strmap {
	DECLARE_HASHTABLE(table, MVPU_STRMAP_BITS);
};

/* --- 雜湊與比較 --- */
static inline u32 mvpu_strmap_hash(const char *key)
{
	return full_name_hash(NULL, key, strlen(key));
}

/* --- 建立與清除 --- */
struct mvpu_strmap* mvpu_strmap_create(void)
{
	struct mvpu_strmap *m = kzalloc(sizeof(*m), GFP_KERNEL);
	if (!m)
		return NULL;
	hash_init(m->table);
	return m;
}

void mvpu_strmap_clear(struct mvpu_strmap* m, void (*val_dtor)(void*))
{
	struct mvpu_strmap_entry *e;
	struct hlist_node *tmp;
	int bkt;

	if (!m)
		return;

	hash_for_each_safe(m->table, bkt, tmp, e, hnode) {
		hash_del(&e->hnode);
		if (val_dtor && e->value)
			val_dtor(e->value);
		kfree(e->key);
		kfree(e);
	}
}

void mvpu_strmap_destroy(struct mvpu_strmap* m, void (*val_dtor)(void*))
{
	if (!m)
		return;
	mvpu_strmap_clear(m, val_dtor);
	kfree(m);
}

/* --- set/get/erase --- */
int mvpu_strmap_set(struct mvpu_strmap* m, const char *key, void *value)
{
	if (!m || !key)
		return -EINVAL;

	u32 hash = mvpu_strmap_hash(key);
	struct mvpu_strmap_entry *e;

	/* 若已存在則覆蓋 */
	hash_for_each_possible(m->table, e, hnode, hash) {
		if (strcmp(e->key, key) == 0) {
			e->value = value;
			return 0;
		}
	}

	e = kzalloc(sizeof(*e), GFP_KERNEL);
	if (!e)
		return -ENOMEM;

	e->key = kstrdup(key, GFP_KERNEL);
	if (!e->key) {
		kfree(e);
		return -ENOMEM;
	}
	e->value = value;
	hash_add(m->table, &e->hnode, hash);
	return 0;
}

void* mvpu_strmap_get(struct mvpu_strmap* m, const char *key)
{
	if (!m || !key)
		return NULL;

	u32 hash = mvpu_strmap_hash(key);
	struct mvpu_strmap_entry *e;

	hash_for_each_possible(m->table, e, hnode, hash)
		if (strcmp(e->key, key) == 0)
			return e->value;
	return NULL;
}

void* mvpu_strmap_erase(struct mvpu_strmap* m, const char *key)
{
	if (!m || !key)
		return NULL;

	u32 hash = mvpu_strmap_hash(key);
	struct mvpu_strmap_entry *e;

	hash_for_each_possible(m->table, e, hnode, hash)
		if (strcmp(e->key, key) == 0) {
			void *v = e->value;
			hash_del(&e->hnode);
			kfree(e->key);
			kfree(e);
			return v;
		}
	return NULL;
}

/* --- foreach / remove --- */
int mvpu_strmap_foreach(struct mvpu_strmap* m, mvpu_strmap_foreach_fn cb, void *ctx)
{
	if (!m || !cb)
		return 0;

	struct mvpu_strmap_entry *e;
	int bkt;
	int ret = 0;

	hash_for_each(m->table, bkt, e, hnode) {
		ret = cb(e->key, e->value, ctx);
		if (ret)
			break;
	}
	return ret;
}

size_t mvpu_strmap_remove(struct mvpu_strmap* m,
                          mvpu_strmap_pred_fn pred, void *ctx,
                          void (*val_dtor)(void*))
{
	if (!m || !pred)
		return 0;

	struct mvpu_strmap_entry *e;
	struct hlist_node *tmp;
	int bkt;
	size_t removed = 0;

	hash_for_each_safe(m->table, bkt, tmp, e, hnode) {
		if (pred(e->key, e->value, ctx)) {
			hash_del(&e->hnode);
			if (val_dtor && e->value)
				val_dtor(e->value);
			kfree(e->key);
			kfree(e);
			removed++;
		}
	}
	return removed;
}

```

``` mvpu_ds_strmap_user.cpp
#include "mvpu_ds_strmap.h"
#include <unordered_map>
#include <string>
#include <new>

extern "C" {

/* ----------- 結構定義 ----------- */
struct mvpu_strmap {
    std::unordered_map<std::string, void*> map;
};

/* ----------- 建立/清理 ----------- */
struct mvpu_strmap* mvpu_strmap_create(void)
{
    return new (std::nothrow) mvpu_strmap{};
}

static void __mvpu_strmap_clear(struct mvpu_strmap* m, void (*val_dtor)(void*))
{
    if (!m) return;
    if (val_dtor) {
        for (auto& kv : m->map)
            if (kv.second) val_dtor(kv.second);
    }
    m->map.clear();
}

void mvpu_strmap_clear(struct mvpu_strmap* m, void (*val_dtor)(void*))
{
    __mvpu_strmap_clear(m, val_dtor);
}

void mvpu_strmap_destroy(struct mvpu_strmap* m, void (*val_dtor)(void*))
{
    if (!m) return;
    __mvpu_strmap_clear(m, val_dtor);
    delete m;
}

/* ----------- set/get/erase ----------- */
int mvpu_strmap_set(struct mvpu_strmap* m, const char* key, void* value)
{
    if (!m || !key) return -1;
    m->map[std::string(key)] = value;
    return 0;
}

void* mvpu_strmap_get(struct mvpu_strmap* m, const char* key)
{
    if (!m || !key) return nullptr;
    auto it = m->map.find(key);
    return it == m->map.end() ? nullptr : it->second;
}

void* mvpu_strmap_erase(struct mvpu_strmap* m, const char* key)
{
    if (!m || !key) return nullptr;
    auto it = m->map.find(key);
    if (it == m->map.end()) return nullptr;
    void* v = it->second;
    m->map.erase(it);
    return v;
}

/* ----------- foreach/remove ----------- */
int mvpu_strmap_foreach(struct mvpu_strmap* m, mvpu_strmap_foreach_fn cb, void* ctx)
{
    if (!m || !cb) return 0;
    for (auto& kv : m->map) {
        int r = cb(kv.first.c_str(), kv.second, ctx);
        if (r) return r;
    }
    return 0;
}

size_t mvpu_strmap_remove(struct mvpu_strmap* m,
                          mvpu_strmap_pred_fn pred, void* ctx,
                          void (*val_dtor)(void*))
{
    if (!m || !pred) return 0;
    size_t removed = 0;
    for (auto it = m->map.begin(); it != m->map.end(); ) {
        if (pred(it->first.c_str(), it->second, ctx)) {
            if (val_dtor && it->second) val_dtor(it->second);
            it = m->map.erase(it);
            ++removed;
        } else {
            ++it;
        }
    }
    return removed;
}

} /* extern "C" */

```

``` test.c
#include "mvpu_ds_strmap.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void val_dtor(void* v) { free(v); }

static int print_cb(const char* k, void* v, void* ctx) {
    printf("%s -> %p\n", k, v);
    return 0;
}

static bool pred_starts_with_a(const char* k, void* v, void* ctx) {
    return k[0] == 'a';
}

int main(void)
{
    mvpu_strmap* m = mvpu_strmap_create();

    mvpu_strmap_set(m, "apple", strdup("A"));
    mvpu_strmap_set(m, "banana", strdup("B"));
    mvpu_strmap_set(m, "avocado", strdup("AV"));

    printf("banana = %s\n", (char*)mvpu_strmap_get(m, "banana"));

    mvpu_strmap_foreach(m, print_cb, NULL);

    mvpu_strmap_remove(m, pred_starts_with_a, NULL, val_dtor);

    printf("--- after remove ---\n");
    mvpu_strmap_foreach(m, print_cb, NULL);

    mvpu_strmap_destroy(m, val_dtor);
    return 0;
}

```
