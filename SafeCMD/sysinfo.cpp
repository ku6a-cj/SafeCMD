// system includes
#include <WinSock2.h>
#include <iphlpapi.h>
#include <time.h>
#include <iostream>
#include <WS2tcpip.h>
#define __MODULE__ "Ipconfig"
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "Ws2_32.lib")
#include<atlstr.h>
#include "sysinfo.h"
#include<string.h>

#define WIDTH 7
#define DIV 1024

int
sysinfo() {
	//structure declaration
	PFIXED_INFO FixedInfo = nullptr;
	DWORD		FixedInfoSize = 0;
	PIP_ADAPTER_INFO AdapterInfo = nullptr;
	PIP_ADAPTER_INFO Adapter = nullptr;
	PIP_ADDR_STRING  AddrString = nullptr;

	DWORD AdapterInfoSize = 0;
	UINT  Index = 0;


	CStringA Buffer = "";
	Buffer.GetBuffer(32);

	
	DWORD LastError = 0;
	DWORD Ret = 0;
	CStringA Message = "[*] This module will discover mock ipconfig utility\n";

	Ret = GetNetworkParams(nullptr, &FixedInfoSize);
	if (0 != Ret)
	{
		if (ERROR_BUFFER_OVERFLOW != Ret)
		{
			return  GetLastError();
		}
	}


	FixedInfo = (PFIXED_INFO)GlobalAlloc(GPTR, FixedInfoSize);
	if (NULL == FixedInfo)
	{
		return  GetLastError();
	}

	Ret = GetNetworkParams(FixedInfo, &FixedInfoSize);
	if (0 != Ret)
	{
		if (ERROR_BUFFER_OVERFLOW != Ret)
		{
			return  GetLastError();
		}
	}
	SYSTEM_INFO sysinfoo;
	// the address of KUSER_SHARED_DATA
	auto KSharedData = (PBYTE)0x7ffe0000;
	// calling the function with the address of the sysInfo variable
	GetNativeSystemInfo(&sysinfoo);

	printf("Host Name: %s\n", FixedInfo->HostName);
	switch (*(PULONG)(KSharedData + 0x26c)) {
	case 6:
		switch (*(PULONG)(KSharedData + 0x270)) {
		case 0:
			printf("OS Name: Microsoft Windows Vista");
			break;
		case 1:
			printf("OS Name: Microsoft Windows 7");
			break;
		case 2:
			printf("OS Name: Microsoft Windows 8");
			break;
		case 3:
			printf("OS Name: Microsoft Windows 8.1");
			break;
		default:
			printf("Unknown system version");
			break;
		}
		break;
	case 10:
		printf("OS Name: Microsoft Windows 10");
		break;
	case 11:
		printf("OS Name: Microsoft Windows 11");
		break;
	default:
		printf("Unknown system version");
		break;
	}


	PDWORD  pdwReturnedProductType = 0;
	printf("\n");
	//to do how to get a seviece pack version?
	/*bool infoProc = GetProductInfo(*(PULONG)(KSharedData + 0x26c), *(PULONG)(KSharedData + 0x26c), , , pdwReturnedProductType);
	if (infoProc == NULL)
	{
		printf("Error while getting infoProc");
	}
	printf("PDW>>> %d", pdwReturnedProductType);
	*/
	printf("OS Version: %d.%d Build: %d\n", *(PULONG)(KSharedData + 0x26c), *(PULONG)(KSharedData + 0x270), *(PULONG)(KSharedData + 0x260));
	//os manufacturer
	//os configuration

	//to do check if it is a windows or mac or linux

	printf("Procesor(s): %d Procesor(s) installed\n", sysinfoo.dwNumberOfProcessors);
	printf("Procesor(s) Type: %d \n", sysinfoo.dwProcessorType);



	printf("Procesors(s) Architecture: ");
	switch (sysinfoo.wProcessorArchitecture)
	{
	case 9:
		printf("x64 (AMD or Intel) \n");
		break;
	case 5:
		printf("ARM \n");
		break;
	case 12:
		printf("ARM64\n");
		break;
	case 6:
		printf("Intel Itanium-based\n");
		break;
	case 0:
		printf("x86\n");
		break;
	default:
		printf("Unknown\n");
		break;
	}

	//printf("wProcessorRevision: %d", sysinfoo.wProcessorRevision);

	printf("System Root Directory %ls \n", (PULONG)(KSharedData + 0x30));
	printf("Time zone: ");
	
	switch (*(PULONG)(KSharedData + 0x240))
	{
	case 2:
		printf("(UTC+01:00) Sarajevo, Skopje, Warsaw, Zagreb \n");
		break;
	default:
		printf("not implemented \n");
		break;
	}

	unsigned long long physicalMemory = 0;
	GetPhysicallyInstalledSystemMemory(&physicalMemory);
	printf("Total Physical Memory: %lld MB \n", physicalMemory/(1024));
	
	MEMORYSTATUSEX statex;

	statex.dwLength = sizeof(statex);
	GlobalMemoryStatusEx(&statex);

	_tprintf(TEXT("Available Physical Memory: %*I64d MB \n"),
		WIDTH, statex.ullAvailPhys / (DIV*DIV));
	_tprintf(TEXT("Virtual Memory: Max Size: %*I64d MB.\n"),
		WIDTH, statex.ullTotalVirtual / (DIV * DIV));
	_tprintf(TEXT("Virtual Memory: Available: %*I64d MB.\n"),
		WIDTH, statex.ullAvailVirtual / (DIV * DIV));

	return EXIT_SUCCESS;
}
