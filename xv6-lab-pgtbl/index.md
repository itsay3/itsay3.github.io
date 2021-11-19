# Xv6 Lab Pgtbl: Pagetable Per Process


做到这个 lab 的时候跳着看了一下 xv6-book 第三章和代码就开始上手，结果当然是跑不起来。最后还是倒回去重新认真分析了相关代码。

<!--more-->

 ## 页表硬件

`pagetable_t`  (kernel/riscv.h) 页表指针，指向内存页的起始位置。

```c
typedef uint64 *pagetable_t;
```

`pte_t` (kernel/riscv.h) Page Table Entry,  页表表项，由 PPN (Physical Page Number) 和 Flags 组成。Flags 为页权限标志。

```c
typedef uint64 pte_t;
```

内存页大小为 4096 Bytes，`PTE` 为 8 Bytes。因此可计算出 `pagetable_t` 指向的页表可包含 512 个表项。

xv6 采用 Sv39 RISC-V。这意味着它只使用地址的低 39 位。其中低 12 位为页哪偏移 (`2 ^ 12 == 4096`)。剩余 27 位用于三级页表，每 9 位可以定位一个页表中的表项。三级页表中最高级的页表中的表项存储了第二级的地址，第二级页表储存最低级的地址。最终由最低级页表中表项的 44 位 PPN 和 虚拟地址的低 12 位构成物理地址。

![image-20211118161050974](https://pic-1252729785.cos.ap-shanghai.myqcloud.com/uPic/image-20211118161050974.png)

kernel/riskv.h 中定义了关于页表的宏

```c
#define PGSIZE 4096 // bytes per page
#define PGSHIFT 12  // bits of offset within a page

#define PGROUNDUP(sz)  (((sz)+PGSIZE-1) & ~(PGSIZE-1))
#define PGROUNDDOWN(a) (((a)) & ~(PGSIZE-1))

#define PTE_V (1L << 0) // valid
#define PTE_R (1L << 1)
#define PTE_W (1L << 2)
#define PTE_X (1L << 3)
#define PTE_U (1L << 4) // 1 -> user can access

// shift a physical address to the right place for a PTE.
#define PA2PTE(pa) ((((uint64)pa) >> 12) << 10)

#define PTE2PA(pte) (((pte) >> 10) << 12)

#define PTE_FLAGS(pte) ((pte) & 0x3FF)

// extract the three 9-bit page table indices from a virtual address.
#define PXMASK          0x1FF // 9 bits
#define PXSHIFT(level)  (PGSHIFT+(9*(level)))
#define PX(level, va) ((((uint64) (va)) >> PXSHIFT(level)) & PXMASK)

// one beyond the highest possible virtual address.
// MAXVA is actually one bit less than the max allowed by
// Sv39, to avoid having to sign-extend virtual addresses
// that have the high bit set.
#define MAXVA (1L << (9 + 9 + 9 + 12 - 1))
```



## Kernel 地址空间

Qemu 将 DRAM 映射在 0x80000000 到 0x86400000。其它设备映射在低于 0x80000000 的地址空间。Xv6 对 kernel 进行直接映射，即虚拟地址和物理地址相同。

有一部分虚拟地址并不是直接映射的。

* trampoline page 被映射在地址空间的顶部。并且它被映射了两次，另一次为直接映射。
* 进程的 kernel stack 也被映射在高地址空间，并且用 guard page 防止栈溢出。

kernel text 和 trampoline 的权限为 `PTE_R | PTE_X`，其余为 `PTE_R | PTE_W` 。

kernel/memlayout.h 中定义了地址空间相关的常量。

```c
// Physical memory layout

// qemu -machine virt is set up like this,
// based on qemu's hw/riscv/virt.c:
//
// 00001000 -- boot ROM, provided by qemu
// 02000000 -- CLINT
// 0C000000 -- PLIC
// 10000000 -- uart0 
// 10001000 -- virtio disk 
// 80000000 -- boot ROM jumps here in machine mode
//             -kernel loads the kernel here
// unused RAM after 80000000.

// the kernel uses physical memory thus:
// 80000000 -- entry.S, then kernel text and data
// end -- start of kernel page allocation area
// PHYSTOP -- end RAM used by the kernel

// qemu puts UART registers here in physical memory.
#define UART0 0x10000000L
#define UART0_IRQ 10

// virtio mmio interface
#define VIRTIO0 0x10001000
#define VIRTIO0_IRQ 1

// local interrupt controller, which contains the timer.
#define CLINT 0x2000000L
#define CLINT_MTIMECMP(hartid) (CLINT + 0x4000 + 8*(hartid))
#define CLINT_MTIME (CLINT + 0xBFF8) // cycles since boot.

// qemu puts programmable interrupt controller here.
#define PLIC 0x0c000000L
#define PLIC_PRIORITY (PLIC + 0x0)
#define PLIC_PENDING (PLIC + 0x1000)
#define PLIC_MENABLE(hart) (PLIC + 0x2000 + (hart)*0x100)
#define PLIC_SENABLE(hart) (PLIC + 0x2080 + (hart)*0x100)
#define PLIC_MPRIORITY(hart) (PLIC + 0x200000 + (hart)*0x2000)
#define PLIC_SPRIORITY(hart) (PLIC + 0x201000 + (hart)*0x2000)
#define PLIC_MCLAIM(hart) (PLIC + 0x200004 + (hart)*0x2000)
#define PLIC_SCLAIM(hart) (PLIC + 0x201004 + (hart)*0x2000)

// the kernel expects there to be RAM
// for use by the kernel and user pages
// from physical address 0x80000000 to PHYSTOP.
#define KERNBASE 0x80000000L
#define PHYSTOP (KERNBASE + 128*1024*1024)

// map the trampoline page to the highest address,
// in both user and kernel space.
#define TRAMPOLINE (MAXVA - PGSIZE)

// map kernel stacks beneath the trampoline,
// each surrounded by invalid guard pages.
#define KSTACK(p) (TRAMPOLINE - ((p)+1)* 2*PGSIZE)

// User memory layout.
// Address zero first:
//   text
//   original data and bss
//   fixed-size stack
//   expandable heap
//   ...
//   TRAPFRAME (p->trapframe, used by the trampoline)
//   TRAMPOLINE (the same page as in the kernel)
#define TRAPFRAME (TRAMPOLINE - PGSIZE)

```

创建地址空间的代码主要存在于 kernel/vm.c, kernel/proc.c 和  kernel/main.c。

kernel/vm.c 中定义了 kernel_pagetable，这是 xv6 kernel 使用的 pagetable。

```c
/*
 * the kernel's page table.
 */
pagetable_t kernel_pagetable;
```

`walk` 函数返回虚拟地址对应的 PTE。在 for 循环中处理三级页表，如果页表不存在则创建。

```c
// Return the address of the PTE in page table pagetable
// that corresponds to virtual address va.  If alloc!=0,
// create any required page-table pages.
//
// The risc-v Sv39 scheme has three levels of page-table
// pages. A page-table page contains 512 64-bit PTEs.
// A 64-bit virtual address is split into five fields:
//   39..63 -- must be zero.
//   30..38 -- 9 bits of level-2 index.
//   21..29 -- 9 bits of level-1 index.
//   12..20 -- 9 bits of level-0 index.
//    0..11 -- 12 bits of byte offset within the page.
pte_t *
walk(pagetable_t pagetable, uint64 va, int alloc)
{
  if(va >= MAXVA)
    panic("walk");

  for(int level = 2; level > 0; level--) {
    pte_t *pte = &pagetable[PX(level, va)];
    if(*pte & PTE_V) {
      pagetable = (pagetable_t)PTE2PA(*pte);
    } else {
      if(!alloc || (pagetable = (pde_t*)kalloc()) == 0)
        return 0;
      memset(pagetable, 0, PGSIZE);
      *pte = PA2PTE(pagetable) | PTE_V;
    }
  }
  return &pagetable[PX(0, va)];
}
```

`mappages` 在页表的 PTE 中写入 pa。`kvmmap` 套了个壳。

```c
// Create PTEs for virtual addresses starting at va that refer to
// physical addresses starting at pa. va and size might not
// be page-aligned. Returns 0 on success, -1 if walk() couldn't
// allocate a needed page-table page.
int
mappages(pagetable_t pagetable, uint64 va, uint64 size, uint64 pa, int perm)
{
  uint64 a, last;
  pte_t *pte;

  a = PGROUNDDOWN(va);
  last = PGROUNDDOWN(va + size - 1);
  for(;;){
    if((pte = walk(pagetable, a, 1)) == 0)
      return -1;
    if(*pte & PTE_V)
      panic("remap");
    *pte = PA2PTE(pa) | perm | PTE_V;
    if(a == last)
      break;
    a += PGSIZE;
    pa += PGSIZE;
  }
  return 0;
}

// add a mapping to the kernel page table.
// only used when booting.
// does not flush TLB or enable paging.
void
kvmmap(uint64 va, uint64 pa, uint64 sz, int perm)
{
  if(mappages(kernel_pagetable, va, sz, pa, perm) != 0)
    panic("kvmmap");
}
```

`kvminit`  创建了 `kernel_pagetable`，并对一些设备，kernel，trampoline 等进行了映射。可以看到除 trampoline 外都是直接映射。另外可以在 kernel/main.c 中看到 kvminit 执行之后才写了 satp，这意味着此时指令使用的地址为物理地址。

```c
void
kvminit()
{
  kernel_pagetable = (pagetable_t) kalloc();
  memset(kernel_pagetable, 0, PGSIZE);

  // uart registers
  kvmmap(UART0, UART0, PGSIZE, PTE_R | PTE_W);

  // virtio mmio disk interface
  kvmmap(VIRTIO0, VIRTIO0, PGSIZE, PTE_R | PTE_W);

  // CLINT
  kvmmap(CLINT, CLINT, 0x10000, PTE_R | PTE_W);

  // PLIC
  kvmmap(PLIC, PLIC, 0x400000, PTE_R | PTE_W);

  // map kernel text executable and read-only.
  kvmmap(KERNBASE, KERNBASE, (uint64)etext-KERNBASE, PTE_R | PTE_X);

  // map kernel data and the physical RAM we'll make use of.
  kvmmap((uint64)etext, (uint64)etext, PHYSTOP-(uint64)etext, PTE_R | PTE_W);

  // map the trampoline for trap entry/exit to
  // the highest virtual address in the kernel.
  kvmmap(TRAMPOLINE, (uint64)trampoline, PGSIZE, PTE_R | PTE_X);
}
```

kernel/proc.c 中的 `procinit` 为每个进程分配了 kernel stack 并映射到内存的高地址处。

```c
// initialize the proc table at boot time.
void
procinit(void)
{
  struct proc *p;
  
  initlock(&pid_lock, "nextpid");
  for(p = proc; p < &proc[NPROC]; p++) {
      initlock(&p->lock, "proc");

      // Allocate a page for the process's kernel stack.
      // Map it high in memory, followed by an invalid
      // guard page.
      char *pa = kalloc();
      if(pa == 0)
        panic("kalloc");
      uint64 va = KSTACK((int) (p - proc));
      kvmmap(va, (uint64)pa, PGSIZE, PTE_R | PTE_W);
      p->kstack = va;
  }
  kvminithart();
}
```

## 物理内存分配

kernel/main.c 中 `main` 调用 `kinit` 对 allocator 进行初始化，它将 kernel 之后的内存空间按页为单位维护成一个 `freelist`，可以看出 `freelist` 是一个 LIFO 的链表。

```c
struct run {
  struct run *next;
};

struct {
  struct spinlock lock;
  struct run *freelist;
} kmem;

void
kinit()
{
  initlock(&kmem.lock, "kmem");
  freerange(end, (void*)PHYSTOP);
}

void
freerange(void *pa_start, void *pa_end)
{
  char *p;
  p = (char*)PGROUNDUP((uint64)pa_start);
  for(; p + PGSIZE <= (char*)pa_end; p += PGSIZE)
    kfree(p);
}

// Free the page of physical memory pointed at by v,
// which normally should have been returned by a
// call to kalloc().  (The exception is when
// initializing the allocator; see kinit above.)
void
kfree(void *pa)
{
  struct run *r;

  if(((uint64)pa % PGSIZE) != 0 || (char*)pa < end || (uint64)pa >= PHYSTOP)
    panic("kfree");

  // Fill with junk to catch dangling refs.
  memset(pa, 1, PGSIZE);

  r = (struct run*)pa;

  acquire(&kmem.lock);
  r->next = kmem.freelist;
  kmem.freelist = r;
  release(&kmem.lock);
}
```

## 进程地址空间

![image-20211119143653295](https://pic-1252729785.cos.ap-shanghai.myqcloud.com/uPic/image-20211119143653295.png)

## A kernel page table per process ([hard](https://pdos.csail.mit.edu/6.S081/2020/labs/guidance.html))

```c
diff --git a/kernel/defs.h b/kernel/defs.h
index ebc4cad..32bcbff 100644
--- a/kernel/defs.h
+++ b/kernel/defs.h
@@ -92,6 +92,7 @@ int             fork(void);
 int             growproc(int);
 pagetable_t     proc_pagetable(struct proc *);
 void            proc_freepagetable(pagetable_t, uint64);
+void            proc_free_kernel_pagetable(pagetable_t);
 int             kill(int);
 struct cpu*     mycpu(void);
 struct cpu*     getmycpu(void);
@@ -179,6 +180,8 @@ int             copyout(pagetable_t, uint64, char *, uint64);
 int             copyin(pagetable_t, char *, uint64, uint64);
 int             copyinstr(pagetable_t, char *, uint64, uint64);
 void            vmprint(pagetable_t);
+pagetable_t     proc_kvminit(void);
+pagetable_t     global_kernel_pagetable(void);
 
 // plic.c
 void            plicinit(void);
diff --git a/kernel/proc.c b/kernel/proc.c
index dab1e1d..f7f5ef6 100644
--- a/kernel/proc.c
+++ b/kernel/proc.c
@@ -107,6 +107,14 @@ allocproc(void)
 found:
   p->pid = allocpid();
 
+  // Prepare kernel page table.
+  p->kernel_pagetable = proc_kvminit();
+
+  // map stack
+  uint64 va = KSTACK((int) (p - proc));
+  uint64 pa = kvmpa(va);
+  mappages(p->kernel_pagetable, va, PGSIZE, pa, PTE_R | PTE_W);
+
   // Allocate a trapframe page.
   if((p->trapframe = (struct trapframe *)kalloc()) == 0){
     release(&p->lock);
@@ -141,7 +149,10 @@ freeproc(struct proc *p)
   p->trapframe = 0;
   if(p->pagetable)
     proc_freepagetable(p->pagetable, p->sz);
+  if(p->kernel_pagetable)
+    proc_free_kernel_pagetable(p->kernel_pagetable);
   p->pagetable = 0;
+  p->kernel_pagetable = 0;
   p->sz = 0;
   p->pid = 0;
   p->parent = 0;
@@ -195,6 +206,25 @@ proc_freepagetable(pagetable_t pagetable, uint64 sz)
   uvmfree(pagetable, sz);
 }
 
+// Free a process's kernel page table only, not the physical memory.
+void
+proc_free_kernel_pagetable(pagetable_t pagetable)
+{
+  // there are 2^9 = 512 PTEs in a page table.
+  for(int i = 0; i < 512; i++){
+    pte_t pte = pagetable[i];
+    if((pte & PTE_V) && (pte & (PTE_R|PTE_W|PTE_X)) == 0){
+      // this PTE points to a lower-level page table.
+      uint64 child = PTE2PA(pte);
+      proc_free_kernel_pagetable((pagetable_t)child);
+      pagetable[i] = 0;
+    } else if(pte & PTE_V){
+      continue;
+    }
+  }
+  kfree((void*)pagetable);
+}
+
 // a user program that calls exec("/init")
 // od -t xC initcode
 uchar initcode[] = {
@@ -473,6 +503,11 @@ scheduler(void)
         // before jumping back to us.
         p->state = RUNNING;
         c->proc = p;
+
+        // Switch kernel page table
+        w_satp(MAKE_SATP(p->kernel_pagetable));
+        sfence_vma();
+
         swtch(&c->context, &p->context);
 
         // Process is done running for now.
@@ -483,6 +518,13 @@ scheduler(void)
       }
       release(&p->lock);
     }
+
+    // Switch to global kernel page table when no process is running.
+    if (found == 0) {
+      w_satp(MAKE_SATP(global_kernel_pagetable()));
+      sfence_vma();
+    }
+
 #if !defined (LAB_FS)
     if(found == 0) {
       intr_on();
diff --git a/kernel/proc.h b/kernel/proc.h
index 9c16ea7..0811f03 100644
--- a/kernel/proc.h
+++ b/kernel/proc.h
@@ -98,6 +98,7 @@ struct proc {
   uint64 kstack;               // Virtual address of kernel stack
   uint64 sz;                   // Size of process memory (bytes)
   pagetable_t pagetable;       // User page table
+  pagetable_t kernel_pagetable;
   struct trapframe *trapframe; // data page for trampoline.S
   struct context context;      // swtch() here to run process
   struct file *ofile[NOFILE];  // Open files
diff --git a/kernel/vm.c b/kernel/vm.c
index 699ca26..b7073e9 100644
--- a/kernel/vm.c
+++ b/kernel/vm.c
@@ -47,6 +47,43 @@ kvminit()
   kvmmap(TRAMPOLINE, (uint64)trampoline, PGSIZE, PTE_R | PTE_X);
 }
 
+pagetable_t
+global_kernel_pagetable()
+{
+  return kernel_pagetable;
+}
+
+pagetable_t
+proc_kvminit()
+{
+  pagetable_t kernel_pagetable = (pagetable_t) kalloc();
+  memset(kernel_pagetable, 0, PGSIZE);
+
+  // uart registers
+  mappages(kernel_pagetable, UART0, PGSIZE, UART0, PTE_R | PTE_W);
+
+  // virtio mmio disk interface
+  mappages(kernel_pagetable, VIRTIO0, PGSIZE, VIRTIO0, PTE_R | PTE_W);
+
+  // CLINT
+  mappages(kernel_pagetable, CLINT, 0x10000, CLINT, PTE_R | PTE_W);
+
+  // PLIC
+  mappages(kernel_pagetable, PLIC, 0x400000, PLIC, PTE_R | PTE_W);
+
+  // map kernel text executable and read-only.
+  mappages(kernel_pagetable, KERNBASE, (uint64)etext-KERNBASE, KERNBASE, PTE_R | PTE_X);
+
+  // map kernel data and the physical RAM we'll make use of.
+  mappages(kernel_pagetable, (uint64)etext, PHYSTOP-(uint64)etext, (uint64)etext, PTE_R | PTE_W);
+
+  // map the trampoline for trap entry/exit to
+  // the higest virtual address in the kernel.
+  mappages(kernel_pagetable, TRAMPOLINE, PGSIZE, (uint64)trampoline, PTE_R | PTE_X);
+
+  return kernel_pagetable;
+}
+
 // Switch h/w page table register to the kernel's page table,
 // and enable paging.
 void

```

弄清楚 xv6 的相关机制之后其实改起来并不困难。按照提示一步步来。

* 在 `struct proc` 中添加 `pagetable_t kernel_pagetable`。
* 实现一个类似 `kvminit` 的函数。
  新函数 `proc_kvminit` 的区别是将 `kvmmap` 调用改成 `mappages`。这是因为 `kvmmap` 默认使用的是全局的 `kernel_pagetable`。
* 添加 kernel stack 的映射到 `proc->kernel_pagetable`。
  这一步我最初是直接将 `procinit` 中的分配和映射过程删除，然后在 `allocproc` 中为进程分配。但在 kernel/virtio_disk.c 中的 `virtio_disk_rw` 中使用了 `kvmpa` 获取 stack 的物理地址。我没有深入看这一部分，用了个取巧的办法：不修改 `procinit`，直接在 `allocproc` 中将映射添加到私有的 `kernel_pagetable`。不过感觉这样也挺合理的。
* 在 `scheduler` 中实现切换 `kernel_pagetable`。
  切换参考 `kvminithart` 。函数体中的循环在找到 `RUNNABLE` 的进程后会将 `found` 赋值为 1。因此判断 `found == 0` 成立时切换为全局的 `kernel_pagetable`。
* 修改 `freeproc` 实现释放 `kernel_pagetable`。
  参考 `freepagetable` 跟踪到 `freewalk` 函数，这个函数用于在释放掉所有内存页之后释放页表。由于所有进程的 `kernel_pagetable` 都指向相同的物理页，所以只需要释放页表。因此实现和 `freewalk` 完全相同，稍作修改就可以用了。
