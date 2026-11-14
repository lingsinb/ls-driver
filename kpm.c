/* kpm.c — KernelSU KPM 形态 (不重编内核, 一次编译可跨多机型使用)
 *
 * 编译需要 kpatch/kpm SDK:
 *   git clone https://github.com/KernelSU-Next/KPatch
 *   KPM_SDK=<KPatch>/kpm make
 * 加载:
 *   kpatch load pkdriver.kpm
 * 卸载:
 *   kpatch unload pkdriver
 *
 * 与 LKM 版 opcode 完全一致, 用户态无需区分。
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/pid.h>
#include <linux/mm_types.h>
#include <linux/version.h>
#include <linux/random.h>
#include <linux/string.h>
#include <linux/mmap_lock.h>
#include <asm/memory.h>

#include "kpm.h"            /* KernelSU KPM SDK 提供 */
#include "../common/proto.h"
#include "../common/crypto.h"
#include "../common/ptwalk.h"

#define PK_KPM_NAME "ksud_diag"

static struct pk_crypt g_crypt;
static bool g_crypted;
static u32 g_last_seq;

static unsigned long (*kln)(const char *name);

static int k_rd_phys(__u64 pa, void *buf, __u32 len)
{
    if (!pfn_valid(PHYS_PFN(pa)) || !pfn_valid(PHYS_PFN(pa + len - 1)))
        return -1;
    memcpy(buf, __va(pa), len);
    return 0;
}

static int k_wr_phys(__u64 pa, const void *buf, __u32 len)
{
    if (!pfn_valid(PHYS_PFN(pa)) || !pfn_valid(PHYS_PFN(pa + len - 1)))
        return -1;
    memcpy(__va(pa), buf, len);
    return 0;
}

static struct task_struct *k_task(__u32 pid)
{
    struct pid *p = find_get_pid(pid);
    struct task_struct *t;

    if (!p)
        return NULL;
    t = get_pid_task(p, PIDTYPE_PID);
    put_pid(p);
    return t;
}

static __u64 k_ttbr0(struct task_struct *t)
{
    struct mm_struct *mm = t->mm ? t->mm : t->active_mm;

    if (!mm || !mm->pgd)
        return 0;
    return __pa((__u64)mm->pgd);
}

static int k_pid_by_name(const char *name, __u32 *out)
{
    struct task_struct *t;
    int found = -1;

    rcu_read_lock();
    for_each_process(t) {
        if (strstr(t->comm, name)) {
            *out = t->pid;
            found = 0;
            break;
        }
    }
    rcu_read_unlock();
    return found;
}

static __u64 k_mod_base(__u32 pid, const char *soname)
{
    struct task_struct *t = k_task(pid);
    struct mm_struct *mm;
    struct vm_area_struct *vma;
    __u64 base = 0;

    if (!t)
        return 0;
    mm = t->mm;
    if (!mm) {
        put_task_struct(t);
        return 0;
    }

    mmap_read_lock(mm);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
    {
        VMA_ITERATOR(vmi, mm, 0);
        for_each_vma(vmi, vma) {
            if (!vma->vm_file)
                continue;
            if (strstr(vma->vm_file->f_path.dentry->d_name.name, soname)) {
                if (!base || vma->vm_start < base)
                    base = vma->vm_start;
            }
        }
    }
#else
    for (vma = mm->mmap; vma; vma = vma->vm_next) {
        if (!vma->vm_file)
            continue;
        if (strstr(vma->vm_file->f_path.dentry->d_name.name, soname)) {
            if (!base || vma->vm_start < base)
                base = vma->vm_start;
        }
    }
#endif
    mmap_read_unlock(mm);
    put_task_struct(t);
    return base;
}

static long k_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
    struct pk_req req;
    struct pk_rsp rsp;
    struct pk_crypt c;
    struct pk_ptcfg cfg;
    __u32 op = cmd & 0xffff;

    (void)f;
    if ((cmd & 0xffff0000u) != PK_MAGIC)
        return -EINVAL;

    if (op == PK_OP_HANDSHAKE) {
        struct pk_handshake hs;
        __u8 client[PK_NONCE_LEN];
        __u8 sn[PK_NONCE_LEN];

        if (copy_from_user(&hs, (void __user *)arg, sizeof(hs)))
            return -EFAULT;

        memcpy(client, hs.server_nonce, PK_NONCE_LEN);
        get_random_bytes(sn, PK_NONCE_LEN);
        memcpy(hs.server_nonce, sn, PK_NONCE_LEN);
        get_random_bytes(hs.session_id, PK_SESSION_LEN);
        hs.status = 0;

        pk_crypt_init(&g_crypt, pk_seed_from_nonce(client, sn, PK_NONCE_LEN));
        g_crypted = true;
        g_last_seq = 0;

        if (copy_to_user((void __user *)arg, &hs, sizeof(hs)))
            return -EFAULT;
        return 0;
    }

    if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
        return -EFAULT;

    memset(&rsp, 0, sizeof(rsp));

    if (!g_crypted || req.h.seq <= g_last_seq)
        return -EACCES;
    g_last_seq = req.h.seq;

    /* 仅写类命令的数据区加密 */
    if (op == PK_OP_WRITE_PHYS || op == PK_OP_WRITE_VIRT) {
        c = g_crypt;
        pk_crypt_apply(&c, req.data, PK_MAX_XFER);
        g_crypt = c;
        if (req.h.crc != pk_crc32(req.data, req.h.len))
            return -EBADMSG;
    }

    switch (op) {
    case PK_OP_PING:
        rsp.status = 0;
        break;

    case PK_OP_GET_PID: {
        __u32 pid = 0;
        char name[33];
        memcpy(name, req.u.by_name.name, 32);
        name[32] = 0;
        rsp.status = (k_pid_by_name(name, &pid) == 0) ? ((rsp.value = pid), 0) : 1;
        break;
    }

    case PK_OP_GET_CR3: {
        struct task_struct *t = k_task(req.u.by_pid.pid);
        if (!t) { rsp.status = 2; break; }
        rsp.value = k_ttbr0(t);
        put_task_struct(t);
        rsp.status = rsp.value ? 0 : 3;
        break;
    }

    case PK_OP_MOD_BASE: {
        char name[33];
        memcpy(name, req.u.by_name.name, 32);
        name[32] = 0;
        rsp.value = k_mod_base(req.u.by_pid.pid, name);
        rsp.status = rsp.value ? 0 : 4;
        break;
    }

    case PK_OP_READ_PHYS:
        if (req.u.xfer.size > PK_MAX_XFER) { rsp.status = 5; break; }
        rsp.status = (k_rd_phys(req.u.xfer.addr, rsp.data, req.u.xfer.size) == 0) ? 0 : 6;
        rsp.len = rsp.status ? 0 : req.u.xfer.size;
        break;

    case PK_OP_WRITE_PHYS:
        if (req.u.xfer.size > PK_MAX_XFER) { rsp.status = 5; break; }
        rsp.status = (k_wr_phys(req.u.xfer.addr, req.data, req.u.xfer.size) == 0) ? 0 : 6;
        break;

    case PK_OP_READ_VIRT:
    case PK_OP_WRITE_VIRT: {
        struct task_struct *t = k_task(req.u.xfer.pid);
        if (!t) { rsp.status = 2; break; }
        cfg.ttbr0 = k_ttbr0(t);
        cfg.page_shift = PAGE_SHIFT;
        cfg.va_bits = VA_BITS;
        put_task_struct(t);

        if (req.u.xfer.size > PK_MAX_XFER) { rsp.status = 5; break; }

        if (op == PK_OP_READ_VIRT) {
            rsp.status = (pk_read_virt(&cfg, req.u.xfer.addr, rsp.data,
                                       req.u.xfer.size, k_rd_phys) == 0) ? 0 : 7;
            rsp.len = rsp.status ? 0 : req.u.xfer.size;
        } else {
            rsp.status = (pk_write_virt(&cfg, req.u.xfer.addr, req.data,
                                        req.u.xfer.size, k_wr_phys) == 0) ? 0 : 7;
        }
        break;
    }

    default:
        return -EINVAL;
    }

    if (copy_to_user((void __user *)arg, &rsp, sizeof(rsp)))
        return -EFAULT;
    return 0;
}

static const struct file_operations k_fops = {
    .owner          = THIS_MODULE,
    .unlocked_ioctl = k_ioctl,
    .compat_ioctl   = k_ioctl,
};

static struct miscdevice k_misc = {
    .minor = MISC_DYNAMIC_MINOR,
    .name  = PK_KPM_NAME,
    .fops  = &k_fops,
};

/* KernelSU KPM 入口 */
KPM_MODULE_INFO();

int __init kpm_module_init(void)
{
    int ret = misc_register(&k_misc);
    if (ret)
        return ret;
    kln = (void *)kallsyms_lookup_name("kallsyms_lookup_name");
    return 0;
}

void __exit kpm_module_exit(void)
{
    misc_deregister(&k_misc);
}
