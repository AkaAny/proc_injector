# 使用proc文件系统完成动态进程注入

Inject remote process **without** using **ptrace** (ROOT privilege required)

这个方法最好的地方在于它不需要ptrace，众所周知，ptrace已经被各种设备和保护方案限制和检查了

只要有/proc文件系统，并且进程目录下包含mem和syscall这两个文件，那么这个方法是可以尝试的

## POC

```shell
cmi:/ $ cd /data/local/tmp
cmi:/data/local/tmp $ su
cmi:/data/local/tmp # id
uid=0(root) gid=0(root) groups=0(root) context=u:r:magisk:s0
cmi:/data/local/tmp # chmod +x injector
cmi:/data/local/tmp # ./injector "32736"
pid: 32736
exe path: /data/local/tmp/simple_go
base addr:5e8f9d5000
syscall no: -1
pc str: 5e8fa535c0
pc:5e8fa535c0 7e5c0
```

注入的数据

```go
[]byte("akaany")
```

注入结果

```shell
127|cmi:/data/local/tmp # ./simple_go
pid:32736 suspend for res
[1] + Stopped (signal)     ./simple_go 
cmi:/data/local/tmp # SIGILL: illegal instruction
PC=0x5e8fa535c0 m=0 sigcode=1
instruction bytes: 0x61 0x6b 0x61 0x61 0x6e 0x79 0xff 0x17 0x0 0x0 0x0 0x0 0x0 0x0 0x0 0x0

goroutine 18 [running]:
main.main.func1()
        C:/Users/AkaAny/GolandProjects/hermes/main.go:11 fp=0x4000034fd0 sp=0x4000034fd0 pc=0x5e8fa535c0
runtime.goexit()
        C:/Users/AkaAny/go/go1.18/src/runtime/asm_arm64.s:1259 +0x4 fp=0x4000034fd0 sp=0x4000034fd0 pc=0x5e8fa2eaf4
created by main.main
        C:/Users/AkaAny/GolandProjects/hermes/main.go:10 +0x8c

goroutine 1 [chan receive]:
main.main()
        C:/Users/AkaAny/GolandProjects/hermes/main.go:16 +0xa4

r0      0x0
r1      0x0
r2      0x5e8fb1dfd8
r3      0x400010a680
r4      0x4000034800
r5      0x400010a6b8
r6      0x5e8fa535c0
r7      0x1
r8      0x1
r9      0x4000102060
r10     0x40001020a0
r11     0x0
r12     0x4000102060
r13     0x0
r14     0x0
r15     0x1
r16     0x7fdb9ea200
r17     0x7fdb9f9d90
r18     0x747684a000
r19     0x38
r20     0x20
r21     0x5e8fb1dac0
r22     0x4000004000
r23     0x0
r24     0x0
r25     0x0
r26     0x5e8faaa9e0
r27     0x5e8fa535c0
r28     0x400010a680
r29     0x0
lr      0x5e8fa2eaf4
sp      0x4000034fd0
pc      0x5e8fa535c0
fault   0x0

```

## 原理

某天突然想到，/proc文件系统下的mem文件可以忽略内存块属性而读写目标进程的内存，那么是不是只要写pc所在的地址，就可以控制这个进程的执行了呢

这个方案有一个问题，我们怎么知道pc地址呢？

经过一番查找，proc内还真就有这么个文件，syscall，它的行为是这样的

1. 当进程运行时（status文件内显示状态为R），内容为`running`

2. 当进程处于可恢复的阻断状态（status文件内显示状态为S），内容有两种情况
   (1). 阻塞原因为陷入系统调用（如等待用户输入），第一列为系统调用号，最后一列为pc
   
   (2). 阻塞原因非系统调用（比如收到SIGSTOP信号），第一列为-1，最后一列为pc

我们现在已经知道一种获取pc的方法，问题转换成了如何让进程处于S状态，又经过一番查找，发现有个信号满足了我们的要求

这个信号就是`SIGSTOP`，这个信号对目标进程来说是不可以阻断的，类似于NT的进程挂起（Suspend）

我们还需要一种让进程从S状态变为R状态的方法，这可以通过`SIGCONT`信号实现，类似于NT的进程恢复（Resume）

这些准备工作完成后，我们就的步骤就变成了这样

1. 向目标进程发送SIGSTOP信号
2. 读取`/proc/[pid]/syscall`文件，获得此时目标进程的pc地址
3. 向`/proc/[pid]/mem`的pc地址处写入shellcode
4. 向目标进程发送SIGCONT信号

接收到SIGCONT信号后，目标进程继续执行，这时执行的就是我们写入的shellcode了

## EXP

如果仅仅是控制目标进程，我们可以直接抄对应架构的shellcode，没有什么不能有`\0`的要求

如果是需要注入，那么我们还需要下点功夫，还需要让进程阻塞一次，以重新获得控制权，在shellcode执行后恢复现场

恢复现场包括指令数据的恢复和寄存器、栈的恢复（shellcode可以做到不使用栈）

我们在第一次挂起进程时，注入器需要备份目标进程pc处开始的shellcode长度的数据

shellcode执行前，需要把要用到的寄存器全部压栈

shellcode主体，调用dlopen函数加载so

shellcode执行完毕时，需要将用过的寄存器全部出栈，同时主动进行系统调用，向所在进程发送SIGSTOP信号（或尝试获取一个注入器拥有的信号量或bind socket等待注入器连接），以阻塞目标进程，重新将控制权交回注入器（shellcode在这个系统调用后需要将pc寄存器放回shellcode开始的位置）

注入器恢复原pc寄存器处shellcode长度的数据，同时按shellcode处的等待逻辑恢复目标进程的执行

