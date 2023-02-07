---
title: House_of_Apple2_利用条件
author: Aapcer
date: 2023-02-07 13:37:00 +0800
categories: [攻击方式利用, House_of_Apple]
tags: [House_of_Apple, PWN, IO利用]
math: true
mermaid: true
comments: false
---

## 引言

> 顺带上次文章，详解一下如何伪造fake_IO_FILE

## 利用_IO_wfile_overflow函数控制程序执行流

对`fp`的设置如下：

- `_flags`设置为`~(2 | 0x8 | 0x800)`，如果不需要控制`rdi`，设置为`0`即可；如果需要获得`shell`，可设置为`sh;`，注意前面有两个空格

- `vtable`设置为`_IO_wfile_jumps/_IO_wfile_jumps_mmap/_IO_wfile_jumps_maybe_mmap`地址（加减偏移），使其能成功调用`_IO_wfile_overflow`即可

- `_wide_data`设置为可控堆地址`A`，即满足`*(fp + 0xa0) = A`

- `_wide_data->_IO_write_base`设置为`0`，即满足`*(A + 0x18) = 0`

- `_wide_data->_IO_buf_base`设置为`0`，即满足`*(A + 0x30) = 0`

- `_wide_data->_wide_vtable`设置为可控堆地址`B`，即满足`*(A + 0xe0) = B`

- `_wide_data->_wide_vtable->doallocate`设置为地址`C`用于劫持`RIP`，即满足`*(B + 0x68) = C`

  调用链如下

  ```
  _IO_wfile_overflow
      _IO_wdoallocbuf
          _IO_WDOALLOCATE
              *(fp-&gt;_wide_data-&gt;_wide_vtable + 0x68)(fp)j
  ```

  具体调用条件分析
  
  `_IO_wfile_overflow`函数
  
  ```c
  wint_t
  _IO_wfile_overflow (FILE *f, wint_t wch)
  {
    if (f->_flags & _IO_NO_WRITES) /* SET ERROR */
      {
        f->_flags |= _IO_ERR_SEEN;
        __set_errno (EBADF);
        return WEOF;
      }
    /* If currently reading or no buffer allocated. */
    if ((f->_flags & _IO_CURRENTLY_PUTTING) == 0)
      {
        /* Allocate a buffer if needed. */
        if (f->_wide_data->_IO_write_base == 0)
      {
        _IO_wdoallocbuf (f);// 需要走到这里
        // ......
      }
      }
  }
  ```
  
  需要满足`f->_flags & _IO_NO_WRITES == 0`并且`f->_flags & _IO_CURRENTLY_PUTTING == 0`和`f->_wide_data->_IO_write_base == 0`
  
  `_IO_wdoallocbuf`函数
  
  ```c
  void
  _IO_wdoallocbuf (FILE *fp)
  {
    if (fp->_wide_data->_IO_buf_base)
      return;
    if (!(fp->_flags & _IO_UNBUFFERED))
      if ((wint_t)_IO_WDOALLOCATE (fp) != WEOF)// _IO_WXXXX调用
        return;
    _IO_wsetb (fp, fp->_wide_data->_shortbuf,
               fp->_wide_data->_shortbuf + 1, 0);
  }
  libc_hidden_def (_IO_wdoallocbuf)
  ```

需要满足`fp->_wide_data->_IO_buf_base != 0`和`fp->_flags & _IO_UNBUFFERED == 0`。

## 利用_IO_wfile_underflow_mmap函数控制程序执行流

对`fp`的设置如下：

- `_flags`设置为`~4`，如果不需要控制`rdi`，设置为`0`即可；如果需要获得`shell`，可设置为`sh;`，注意前面有个空格
- `vtable`设置为`_IO_wfile_jumps_mmap`地址（加减偏移），使其能成功调用`_IO_wfile_underflow_mmap`即可
- `_IO_read_ptr < _IO_read_end`，即满足`*(fp + 8) < *(fp + 0x10)`
- `_wide_data`设置为可控堆地址`A`，即满足`*(fp + 0xa0) = A`
- `_wide_data->_IO_read_ptr >= _wide_data->_IO_read_end`，即满足`*A >= *(A + 8)`
- `_wide_data->_IO_buf_base`设置为`0`，即满足`*(A + 0x30) = 0`
- `_wide_data->_IO_save_base`设置为`0`或者合法的可被`free`的地址，即满足`*(A + 0x40) = 0`
- `_wide_data->_wide_vtable`设置为可控堆地址`B`，即满足`*(A + 0xe0) = B`
- `_wide_data->_wide_vtable->doallocate`设置为地址`C`用于劫持`RIP`，即满足`*(B + 0x68) = C`

调用链如下

```
_IO_wfile_underflow_mmap
    _IO_wdoallocbuf
        _IO_WDOALLOCATE
            *(fp->_wide_data->_wide_vtable + 0x68)(fp)
```

具体调用条件分析

`_IO_wfile_underflow_mmap`函数

```c
static wint_t
_IO_wfile_underflow_mmap (FILE *fp)
{
  struct _IO_codecvt *cd;
  const char *read_stop;
 
  if (__glibc_unlikely (fp->_flags & _IO_NO_READS))
    {
      fp->_flags |= _IO_ERR_SEEN;
      __set_errno (EBADF);
      return WEOF;
    }
  if (fp->_wide_data->_IO_read_ptr < fp->_wide_data->_IO_read_end)
    return *fp->_wide_data->_IO_read_ptr;
 
  cd = fp->_codecvt;
 
  /* Maybe there is something left in the external buffer.  */
  if (fp->_IO_read_ptr >= fp->_IO_read_end
      /* No.  But maybe the read buffer is not fully set up.  */
      && _IO_file_underflow_mmap (fp) == EOF)
    /* Nothing available.  _IO_file_underflow_mmap has set the EOF or error
       flags as appropriate.  */
    return WEOF;
 
  /* There is more in the external.  Convert it.  */
  read_stop = (const char *) fp->_IO_read_ptr;
 
  if (fp->_wide_data->_IO_buf_base == NULL)
    {
      /* Maybe we already have a push back pointer.  */
      if (fp->_wide_data->_IO_save_base != NULL)
    {
      free (fp->_wide_data->_IO_save_base);
      fp->_flags &= ~_IO_IN_BACKUP;
    }
      _IO_wdoallocbuf (fp);// 需要走到这里
    }
    //......
}
```

需要设置`fp->_flags & _IO_NO_READS == 0`，设置`fp->_wide_data->_IO_read_ptr >= fp->_wide_data->_IO_read_end`，设置`fp->_IO_read_ptr < fp->_IO_read_end`不进入调用，设置`fp->_wide_data->_IO_buf_base == NULL`和`fp->_wide_data->_IO_save_base == NULL`。

## 利用_IO_wdefault_xsgetn函数控制程序执行流

**这条链执行的条件是调用到_IO_wdefault_xsgetn时rdx寄存器，也就是第三个参数不为0**。如果不满足这个条件，可选用其他链。

对`fp`的设置如下：

- `_flags`设置为`0x800`
- `vtable`设置为`_IO_wstrn_jumps/_IO_wmem_jumps/_IO_wstr_jumps`地址（加减偏移），使其能成功调用`_IO_wdefault_xsgetn`即可
- `_mode`设置为大于`0`，即满足`*(fp + 0xc0) > 0`
- `_wide_data`设置为可控堆地址`A`，即满足`*(fp + 0xa0) = A`
- `_wide_data->_IO_read_end == _wide_data->_IO_read_ptr`设置为`0`，即满足`*(A + 8) = *A`
- `_wide_data->_IO_write_ptr > _wide_data->_IO_write_base`，即满足`*(A + 0x20) > *(A + 0x18)`
- `_wide_data->_wide_vtable`设置为可控堆地址`B`，即满足`*(A + 0xe0) = B`
- `_wide_data->_wide_vtable->overflow`设置为地址`C`用于劫持`RIP`，即满足`*(B + 0x18) = C`

调用链如下

```
_IO_wdefault_xsgetn
    __wunderflow
        _IO_switch_to_wget_mode
            _IO_WOVERFLOW
                *(fp->_wide_data->_wide_vtable + 0x18)(fp)
```

具体调用条件分析

`_IO_wdefault_xsgetn`函数

```c
size_t
_IO_wdefault_xsgetn (FILE *fp, void *data, size_t n)
{
  size_t more = n;
  wchar_t *s = (wchar_t*) data;
  for (;;)
    {
      /* Data available. */
      ssize_t count = (fp->_wide_data->_IO_read_end
                       - fp->_wide_data->_IO_read_ptr);
      if (count > 0)
    {
      if ((size_t) count > more)
        count = more;
      if (count > 20)
        {
          s = __wmempcpy (s, fp->_wide_data->_IO_read_ptr, count);
          fp->_wide_data->_IO_read_ptr += count;
        }
      else if (count <= 0)
        count = 0;
      else
        {
          wchar_t *p = fp->_wide_data->_IO_read_ptr;
          int i = (int) count;
          while (--i >= 0)
        *s++ = *p++;
          fp->_wide_data->_IO_read_ptr = p;
            }
            more -= count;
        }
      if (more == 0 || __wunderflow (fp) == WEOF)
    break;
    }
  return n - more;
}
libc_hidden_def (_IO_wdefault_xsgetn)
```

由于`more`是第三个参数，所以不能为`0`。
直接设置`fp->_wide_data->_IO_read_ptr == fp->_wide_data->_IO_read_end`，使得`count`为`0`，不进入`if`分支。
随后当`more != 0`时会进入`__wunderflow`。

`__wunderflow`函数

```
wint_t
__wunderflow (FILE *fp)
{
  if (fp->_mode < 0 || (fp->_mode == 0 && _IO_fwide (fp, 1) != 1))
    return WEOF;
 
  if (fp->_mode == 0)
    _IO_fwide (fp, 1);
  if (_IO_in_put_mode (fp))
    if (_IO_switch_to_wget_mode (fp) == EOF)
      return WEOF;
    // ......
}
```

要想调用到`_IO_switch_to_wget_mode`，需要设置`fp->mode > 0`，并且`fp->_flags & _IO_CURRENTLY_PUTTING != 0`。

`_IO_switch_to_wget_mode`函数

```c
int
_IO_switch_to_wget_mode (FILE *fp)
{
  if (fp->_wide_data->_IO_write_ptr > fp->_wide_data->_IO_write_base)
    if ((wint_t)_IO_WOVERFLOW (fp, WEOF) == WEOF) // 需要走到这里
      return EOF;
    // .....
}
```

## 总结

> 感谢大佬tql，让我复制黏贴这么多，到时候做题要用到的时候自己直接回来看就可以了，主要看如何构造FAKE_IO_FILE，以后做题了记得把板子搞进来XD