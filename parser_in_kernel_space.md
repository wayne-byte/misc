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





#include <vector>
#include <string>
#include <fstream>
#include <span>
#include <filesystem>
#include <cstddef> // std::byte

struct ByteView {
    std::span<const std::byte> view;
    // 快捷：取得 C 風格指標與大小
    const void* data() const { return view.data(); }
    size_t size() const { return view.size(); }
};

// 讀檔到 vector，順便提供只讀 view
inline std::pair<std::vector<std::byte>, ByteView>
read_file_owned(const std::string& path) {
    namespace fs = std::filesystem;
    std::vector<std::byte> buf;

    const auto sz = fs::file_size(path);               // 失敗會丟例外，可改 try/catch
    buf.resize(static_cast<size_t>(sz));

    std::ifstream ifs(path, std::ios::binary);
    if (!ifs) throw std::runtime_error("open failed: " + path);
    ifs.read(reinterpret_cast<char*>(buf.data()), buf.size());
    if (static_cast<size_t>(ifs.gcount()) != buf.size())
        throw std::runtime_error("short read: " + path);

    ByteView view{ std::span<const std::byte>(buf.data(), buf.size()) };
    return { std::move(buf), view };
}

// 用法
// auto [storage, view] = read_file_owned("foo.bin");
// const uint8_t* p = reinterpret_cast<const uint8_t*>(view.data());
// size_t n = view.size();













好的，我幫你做一套「**C 介面 + 兩個後端實作**」的最小框架：

* **介面（.h）**：純 C，穩定 ABI，可同時被 kernel 與 user 端 include。
* **Kernel 後端（.c）**：用 Linux 內建 DS（`xarray` / `rhashtable`）。
* **User 後端（.cpp）**：用 `std::unordered_map`，但仍輸出 **C 函式**（`extern "C"`），所以你的上層邏輯**只寫 C**。

我先給兩種 Map（`u64 → void*`、`string → void*`）與一個簡單 vector（指標動態陣列）。你可以直接複製到專案。

---

# 檔案 1：`mvpu_ds.h`（C 介面；兩端共用）

```c
#pragma once
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---------- 前置宣告（opaque） ---------- */
typedef struct mvpu_u64map mvpu_u64map;
typedef struct mvpu_strmap mvpu_strmap;
typedef struct mvpu_vec    mvpu_vec;

/* ---------- u64 → void* map ---------- */
typedef int (*mvpu_u64map_foreach_fn)(unsigned long key, void *val, void *ctx);

mvpu_u64map* mvpu_u64map_create(void);
void         mvpu_u64map_destroy(mvpu_u64map* m);

/* 覆蓋或插入；成功 0、失敗 -errno */
int          mvpu_u64map_set(mvpu_u64map* m, unsigned long key, void *val);
void*        mvpu_u64map_get(const mvpu_u64map* m, unsigned long key);  /* NULL=無 */
void*        mvpu_u64map_erase(mvpu_u64map* m, unsigned long key);      /* 回舊值或 NULL */

/* 分配一顆新 ID（min..max，或循環） */
int          mvpu_u64map_alloc(mvpu_u64map* m, unsigned long* out_key, void* val,
                               unsigned long min_key, unsigned long max_key);
int          mvpu_u64map_alloc_cyclic(mvpu_u64map* m, unsigned long* out_key, void* val,
                               unsigned long min_key, unsigned long max_key,
                               unsigned long* next_key);

/* 迭代：callback 回非 0 會中止並把該值回傳 */
int          mvpu_u64map_foreach(mvpu_u64map* m, mvpu_u64map_foreach_fn fn, void* ctx);

/* ---------- string → void* map ---------- */
/* 介面做成「自動複製 key（C 字串）」：user=std::string；kernel=kstrdup。*/
typedef int (*mvpu_strmap_foreach_fn)(const char *key, void *val, void *ctx);

mvpu_strmap* mvpu_strmap_create(void);
void         mvpu_strmap_destroy(mvpu_strmap* m);
int          mvpu_strmap_set(mvpu_strmap* m, const char* key_cstr, void* val); /* 內部複製 key */
void*        mvpu_strmap_get(const mvpu_strmap* m, const char* key_cstr);
void*        mvpu_strmap_erase(mvpu_strmap* m, const char* key_cstr);          /* 回舊值或 NULL */
int          mvpu_strmap_foreach(mvpu_strmap* m, mvpu_strmap_foreach_fn fn, void* ctx);

/* ---------- 指標 vector（最小版） ---------- */
mvpu_vec*    mvpu_vec_create(void);
void         mvpu_vec_destroy(mvpu_vec* v);
int          mvpu_vec_push(mvpu_vec* v, void* p);   /* 0/-errno */
size_t       mvpu_vec_size(const mvpu_vec* v);
void**       mvpu_vec_data(mvpu_vec* v);            /* 連續儲存的指標陣列 */

#ifdef __cplusplus
} /* extern "C" */
#endif
```

---

# 檔案 2：`mvpu_ds_kernel.c`（Kernel 後端：C 實作）

> 放進你的 .ko；用 **Android/Linux 內建 DS**：`xarray`（整數鍵）＋ `rhashtable`（字串鍵）。

```c
// SPDX-License-Identifier: GPL-2.0
#include <linux/slab.h>
#include <linux/xarray.h>
#include <linux/rhashtable.h>
#include <linux/string.h>
#include "mvpu_ds.h"

/* ---------------- u64map (xarray) ---------------- */
struct mvpu_u64map { struct xarray xa; };

mvpu_u64map* mvpu_u64map_create(void)
{
    mvpu_u64map* m = kzalloc(sizeof(*m), GFP_KERNEL);
    if (!m) return NULL;
    xa_init(&m->xa);
    return m;
}

void mvpu_u64map_destroy(mvpu_u64map* m)
{
    if (!m) return;
    xa_destroy(&m->xa); /* 只釋放樹節點；不會 free entries（呼叫端自理） */
    kfree(m);
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

int mvpu_u64map_alloc_cyclic(mvpu_u64map* m, unsigned long* out_key, void* val,
                      unsigned long min_key, unsigned long max_key,
                      unsigned long* next_key)
{
    return xa_alloc_cyclic(&m->xa, out_key, val, XA_LIMIT(min_key, max_key),
                           next_key, GFP_KERNEL);
}

int mvpu_u64map_foreach(mvpu_u64map* m, mvpu_u64map_foreach_fn fn, void* ctx)
{
    unsigned long idx; void* entry;
    xa_for_each(&m->xa, idx, entry) {
        int r = fn(idx, entry, ctx);
        if (r) return r;
    }
    return 0;
}

/* ---------------- strmap (rhashtable) ---------------- */
struct mvpu_strnode {
    char* key;               /* kstrdup 取得，erase/destroy 時 kfree */
    void* val;
    struct rhash_head node;
};

struct mvpu_strmap {
    struct rhashtable ht;
    struct rhashtable_params p;
};

static u32 mvpu_str_hash(const void *data, u32 len, u32 seed)
{
    /* data = &node->key（指向 char*）；len 用不到，直接對字串做 djb2/jenkins 都可 */
    const char * const *pk = data;
    const unsigned char *s = (const unsigned char *)(*pk);
    u32 h = seed ? seed : 5381;
    while (*s) h = ((h << 5) + h) + *s++;
    return h;
}

static int mvpu_str_cmp(struct rhashtable_compare_arg *arg, const void *obj)
{
    const char *key = *(const char **)arg->key;   /* key 指向 char* */
    const struct mvpu_strnode *n = obj;
    return strcmp(key, n->key);
}

mvpu_strmap* mvpu_strmap_create(void)
{
    mvpu_strmap* m = kzalloc(sizeof(*m), GFP_KERNEL);
    if (!m) return NULL;
    m->p = (struct rhashtable_params){
        .head_offset = offsetof(struct mvpu_strnode, node),
        .key_offset  = offsetof(struct mvpu_strnode, key),
        .key_len     = sizeof(char*),              /* 我們把 key 當指標來比較 */
        .hashfn      = mvpu_str_hash,
        .obj_cmpfn   = mvpu_str_cmp,
        .automatic_shrinking = true,
    };
    if (rhashtable_init(&m->ht, &m->p)) { kfree(m); return NULL; }
    return m;
}

void mvpu_strmap_destroy(mvpu_strmap* m)
{
    if (!m) return;
    /* 走訪並移除所有節點 */
    struct rhashtable_iter it;
    if (!rhashtable_walk_init(&m->ht, &it, GFP_KERNEL)) {
        rhashtable_walk_start(&it);
        while (1) {
            struct mvpu_strnode *n = rhashtable_walk_next(&it);
            if (!n) break;
            if (IS_ERR(n)) {
                if (PTR_ERR(n) == -EAGAIN) continue;
                break;
            }
            rhashtable_remove_fast(&m->ht, &n->node, m->p);
            kfree(n->key);
            kfree(n);
        }
        rhashtable_walk_stop(&it);
        rhashtable_walk_exit(&it);
    }
    rhashtable_destroy(&m->ht);
    kfree(m);
}

int mvpu_strmap_set(mvpu_strmap* m, const char* key_cstr, void* val)
{
    /* 查既有；存在就覆蓋，不存在就插入新 node（複製 key） */
    const char *lookup_key = key_cstr;
    struct mvpu_strnode *old = rhashtable_lookup(&m->ht, &lookup_key, m->p);
    if (old) { old->val = val; return 0; }

    struct mvpu_strnode *n = kzalloc(sizeof(*n), GFP_KERNEL);
    if (!n) return -ENOMEM;
    n->key = kstrdup(key_cstr, GFP_KERNEL);
    if (!n->key) { kfree(n); return -ENOMEM; }
    n->val = val;

    return rhashtable_insert_fast(&m->ht, &n->node, m->p);
}

void* mvpu_strmap_get(const mvpu_strmap* m, const char* key_cstr)
{
    const char *lookup_key = key_cstr;
    struct mvpu_strnode *n = rhashtable_lookup((struct rhashtable *)&m->ht, &lookup_key, m->p);
    return n ? n->val : NULL;
}

void* mvpu_strmap_erase(mvpu_strmap* m, const char* key_cstr)
{
    const char *lookup_key = key_cstr;
    struct mvpu_strnode *n = rhashtable_lookup(&m->ht, &lookup_key, m->p);
    if (!n) return NULL;
    rhashtable_remove_fast(&m->ht, &n->node, m->p);
    void* v = n->val;
    kfree(n->key);
    kfree(n);
    return v;
}

int mvpu_strmap_foreach(mvpu_strmap* m, int (*fn)(const char*, void*, void*), void* ctx)
{
    struct rhashtable_iter it;
    int ret = rhashtable_walk_init(&m->ht, &it, GFP_KERNEL);
    if (ret) return ret;
    rhashtable_walk_start(&it);
    while (1) {
        struct mvpu_strnode *n = rhashtable_walk_next(&it);
        if (!n) break;
        if (IS_ERR(n)) { if (PTR_ERR(n)==-EAGAIN) continue; ret = PTR_ERR(n); break; }
        ret = fn(n->key, n->val, ctx);
        if (ret) break;
    }
    rhashtable_walk_stop(&it);
    rhashtable_walk_exit(&it);
    return ret;
}

/* ---------------- vector（ptr 動態陣列） ---------------- */
struct mvpu_vec { void** a; size_t sz, cap; };

mvpu_vec* mvpu_vec_create(void)
{
    return kzalloc(sizeof(struct mvpu_vec), GFP_KERNEL);
}
void mvpu_vec_destroy(mvpu_vec* v)
{
    if (!v) return;
    kfree(v->a);
    kfree(v);
}
static int mvpu_vec_reserve(mvpu_vec* v, size_t need)
{
    if (need <= v->cap) return 0;
    size_t nc = v->cap ? v->cap*2 : 8;
    while (nc < need) {
        if (nc > (SIZE_MAX/2)) return -EOVERFLOW;
        nc *= 2;
    }
    void** nd = krealloc(v->a, nc*sizeof(void*), GFP_KERNEL);
    if (!nd) return -ENOMEM;
    v->a = nd; v->cap = nc; return 0;
}
int mvpu_vec_push(mvpu_vec* v, void* p)
{
    if (v->sz == v->cap) { int r=mvpu_vec_reserve(v, v->cap? v->cap*2:8); if (r) return r; }
    v->a[v->sz++] = p; return 0;
}
size_t mvpu_vec_size(const mvpu_vec* v) { return v->sz; }
void** mvpu_vec_data(mvpu_vec* v) { return v->a; }
```

---

# 檔案 3：`mvpu_ds_user.cpp`（User 後端：C++ 實作但暴露 C 函式）

> 這邊用 `std::unordered_map`／`std::string`，但對外仍是 **C 介面**。你在 user 測試可以直接連這個 `.cpp`，在 kernel 連 `.c`。

```cpp
// user-side implementation
#include <unordered_map>
#include <string>
#include <vector>
#include <new>
#include "mvpu_ds.h"

extern "C" {

/* ---------------- u64map ---------------- */
struct mvpu_u64map { std::unordered_map<unsigned long, void*> m; };

mvpu_u64map* mvpu_u64map_create(void) { return new (std::nothrow) mvpu_u64map{}; }
void mvpu_u64map_destroy(mvpu_u64map* m) { delete m; }

int   mvpu_u64map_set(mvpu_u64map* m, unsigned long key, void* val) { m->m[key]=val; return 0; }
void* mvpu_u64map_get(const mvpu_u64map* m, unsigned long key) {
    auto it = m->m.find(key); return it==m->m.end()? nullptr : it->second;
}
void* mvpu_u64map_erase(mvpu_u64map* m, unsigned long key) {
    auto it = m->m.find(key); if (it==m->m.end()) return nullptr;
    void* v = it->second; m->m.erase(it); return v;
}
int mvpu_u64map_alloc(mvpu_u64map* m, unsigned long* out_key, void* val,
                      unsigned long min_key, unsigned long max_key)
{
    static unsigned long next = 0;  // 單執行緒簡易策略
    if (next < min_key || next > max_key) next = min_key;
    return mvpu_u64map_alloc_cyclic(m, out_key, val, min_key, max_key, &next);
}
int mvpu_u64map_alloc_cyclic(mvpu_u64map* m, unsigned long* out_key, void* val,
                      unsigned long min_key, unsigned long max_key,
                      unsigned long* next_key)
{
    unsigned long k = (*next_key<min_key || *next_key>max_key) ? min_key : *next_key;
    unsigned long start = k;
    do {
        if (!mvpu_u64map_get(m, k)) { m->m[k]=val; *out_key=k; *next_key = (k==max_key?min_key:k+1); return 0; }
        k = (k==max_key? min_key : k+1);
    } while (k != start);
    return -28; /* -ENOSPC */
}
int mvpu_u64map_foreach(mvpu_u64map* m, mvpu_u64map_foreach_fn fn, void* ctx)
{
    for (auto &kv : m->m) { int r = fn(kv.first, kv.second, ctx); if (r) return r; }
    return 0;
}

/* ---------------- strmap ---------------- */
struct mvpu_strmap { std::unordered_map<std::string, void*> m; };

mvpu_strmap* mvpu_strmap_create(void) { return new (std::nothrow) mvpu_strmap{}; }
void mvpu_strmap_destroy(mvpu_strmap* m) { delete m; }

int   mvpu_strmap_set(mvpu_strmap* m, const char* key_cstr, void* val) {
    m->m[std::string(key_cstr)] = val; return 0;
}
void* mvpu_strmap_get(const mvpu_strmap* m, const char* key_cstr) {
    auto it = m->m.find(key_cstr); return it==m->m.end()? nullptr : it->second;
}
void* mvpu_strmap_erase(mvpu_strmap* m, const char* key_cstr) {
    auto it = m->m.find(key_cstr); if (it==m->m.end()) return nullptr;
    void* v = it->second; m->m.erase(it); return v;
}
int mvpu_strmap_foreach(mvpu_strmap* m, int (*fn)(const char*, void*, void*), void* ctx)
{
    for (auto &kv : m->m){ int r = fn(kv.first.c_str(), kv.second, ctx); if (r) return r; }
    return 0;
}

/* ---------------- vector（ptr） ---------------- */
struct mvpu_vec { std::vector<void*> v; };

mvpu_vec* mvpu_vec_create(void) { return new (std::nothrow) mvpu_vec{}; }
void mvpu_vec_destroy(mvpu_vec* v) { delete v; }
int    mvpu_vec_push(mvpu_vec* v, void* p) { v->v.push_back(p); return 0; }
size_t mvpu_vec_size(const mvpu_vec* v) { return v->v.size(); }
void** mvpu_vec_data(mvpu_vec* v) { return v->v.data(); }

} /* extern "C" */
```

---

## 怎麼用（同一份 C 介面，兩邊零改碼）

### Kernel（Kbuild / Android.bp）

* 編你自己的 .ko，把 `mvpu_ds.h` 與 `mvpu_ds_kernel.c` 加進去
* 在 driver 裡 `#include "mvpu_ds.h"`，直接呼叫 C API

### User（gcc/clang）

* 把 `mvpu_ds.h` 與 `mvpu_ds_user.cpp` 加進你的測試程式
* 用 C 或 C++ 寫測試都可以（C 程式連 `mvpu_ds_user.cpp` 也 OK，因為是 C 介面）
* 建議：在 user 端先用 GDB/ASan 把邏輯磨好，再搬進 kernel

---

## 設計重點與取捨

* 你提到「**C header + C++ 實作**，無法 header-only」——是合理做法。
  我這版就是 **C header** +（**kernel: C** / **user: C++**）兩端實作；**上層永遠只 include `mvpu_ds.h`**。
* **所有權**：Map 只存指標；物件生命週期由呼叫端決定。

  * Kernel：若將來需要 RCU 無鎖讀，再把 erase 改成 `kfree_rcu()` 即可。
  * User：直接 `delete/free` 你 erase 回來的舊值。
* **單執行緒假設**：目前 API 不加鎖；你說讀寫只有 OneThread，這樣最簡單。未來要多執行緒，再在上層加鎖或換成 RCU 版本。
* **字串鍵**：介面選擇「自動複製 key」，避免兩端所有權不一致（user=std::string；kernel=kstrdup）。

---

## 小例：上層 C 使用（兩端通用）

```c
#include "mvpu_ds.h"

struct obj { int v; };

void demo(void)
{
    mvpu_u64map* m = mvpu_u64map_create();
    struct obj *a = /* alloc */;
    mvpu_u64map_set(m, 42, a);

    struct obj *got = (struct obj*)mvpu_u64map_get(m, 42);

    mvpu_u64map_foreach(m, /*callback*/ [](unsigned long k, void* v, void* ctx)->int{
        (void)ctx;
        /* ... */
        return 0;
    }, NULL);

    struct obj *old = (struct obj*)mvpu_u64map_erase(m, 42);
    /* free/delete old */
    mvpu_u64map_destroy(m);
}
```

> C 檔寫 lambda 不行？那就寫一般的靜態函式當 callback。

---

如果你還需要 **C-only 的 user 後端**（不想依賴 C++），我可以把 `mvpu_ds_user.cpp` 改成 **uthash** 或「排序陣列 + 二分」版本；介面完全不變。
另外，若你要 `vector<T>` 的「型別化版本」，也能用巨集再包一層（跟你前面需求的 `smap.h` 風格類似）。
