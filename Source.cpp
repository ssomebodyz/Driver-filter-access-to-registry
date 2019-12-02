#include <fstream>
#include <stdio.h>
#include <stdlib.h>
#include "System.h"
#include <iostream>
#include <sstream>
#include <Windows.h>
#include <iostream>
#include <fstream>
#pragma warning(disable:4996)

struct
{
	char process_name[128];
	char process_right[128];

}process_info[10];
struct
{
	char regedit_name[128];
	char regedit_right[128];

}regedit_info[10];
using std::cout;
using std::cin;
using std::endl;
using std::string;
HANDLE devicehandle = NULL;

void print_menu()
{
	std::cout << "1) Set/remove notifier\n";
	std::cout << "2) Update rules\n";
	std::cout << "3) Exit\n";
}
void CommandRoutine(DWORD ControlCode, std::string error_msg, std::string success_msg)
{
	const wchar_t* message = L"";
	ULONG returnLength = 0;
	if (devicehandle != INVALID_HANDLE_VALUE && devicehandle != NULL)
	{
		if (!DeviceIoControl(devicehandle, ControlCode, (LPVOID)message, __length(message), NULL, 0, &returnLength, 0))

		{
			std::cout << error_msg << std::endl;
		}

		else
		{
			std::cout << success_msg << std::endl;
		}
	}
}
void UpdateFile()
{
	std::cout << "Rules were sent" << std::endl;
	CHAR filePull[1024] = { 0 };
	ULONG returnLength = 0;
	std::string naaame;
	std::string rightlvl;
	std::string line;
	int ready_flag = 1;
	FILE* read_data = fopen("info.xml", "r");
	CHAR symbol = fgetc(read_data);
	filePull[0] = symbol;
	char check[50] = { 0 };
	int i = 0;
	for (int i = 1, symbol = fgetc(read_data); symbol != EOF; symbol = fgetc(read_data), i++)
	{
		filePull[i] = symbol;
	}
	filePull[strlen(filePull)] = '*';
	DeviceIoControl(devicehandle, 0x801, filePull, sizeof(filePull), filePull, sizeof(filePull), &returnLength, NULL);
}
void Exit()

{
	if (devicehandle) { CloseHandle(devicehandle); }
	exit(EXIT_SUCCESS);
}
void OpenDeviceLink()
{
	devicehandle = CreateFileW(L"\\\\.\\RegFltr", GENERIC_ALL, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM, 0);
	if (devicehandle == INVALID_HANDLE_VALUE)
	{
		std::cout << "Error opening Link" << std::endl;
	}
	else { std::cout << "Link was succwsfully opened" << std::endl; }
}
void sent_notifier()
{
	CHAR filePull[1024] = { 0 };
	ULONG returnLength = 0;
	cout << "Choose:" << endl << "1-set notifier\n2-remove notifier\n" << endl;
	scanf("%s", &filePull);
	printf("your choice is %c\n", filePull[0]);
	DeviceIoControl(devicehandle, 0x802, filePull, sizeof(filePull), filePull, sizeof(filePull), &returnLength, NULL);
}
int main(int argc, char* argv[])
{
	int mode;
	OpenDeviceLink();
	while (true)
	{
		print_menu();
		cin >> mode;
		switch (mode)
		{
		case 1:
		{
			sent_notifier();
			break;
		}
		case 2:
			UpdateFile();
			break;
		case 3:
			Exit();
			break;
		default:
			break;
		}
	}
}