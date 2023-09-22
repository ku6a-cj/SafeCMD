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
#include <string>
#include <stdio.h>
#include <stdlib.h>
#include "ipConfig.h"

INT
ipConfig() {
	PFIXED_INFO FixedInfo = nullptr;
	DWORD		FixedInfoSize = 0;
	PIP_ADAPTER_INFO AdapterInfo = nullptr;
	PIP_ADAPTER_INFO Adapter = nullptr;
	PIP_ADDR_STRING  AddrString = nullptr;
	DWORD AdapterInfoSize = 0;
	UINT  Index = 0;
	struct tm newtime;
	CStringA Buffer = "";
	Buffer.GetBuffer(32);
	errno_t error;
	DWORD LastError = 0;
	DWORD Ret = 0;

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

	printf("Host name: %s\n", FixedInfo->HostName);
	printf("DNS servers: %s\n", FixedInfo->DnsServerList.IpAddress.String);
	switch (FixedInfo->NodeType)
	{
	case 1:
		printf("Node type: %s\n", "Broadcast");
		break;
	case 2:
		printf("Node type: %s\n", "P2P");
		break;
	case 4:
		printf("Node type: %s\n", "Mixed");
		break;
	case 8:
		printf("Node type: %s\n", "Hybrid");
		break;
	default:
		printf("\n");
	}
	printf("Net bios Scope ID: %s\n", FixedInfo->ScopeId);
	printf("Routing Enabled: %s\n", (FixedInfo->EnableRouting ? "Yes" : "No"));
	printf("Proxy Enabled: %s\n", (FixedInfo->EnableProxy ? "Yes" : "No"));
	printf("Net bios Resolution Uses DNS: %s\n", (FixedInfo->EnableDns ? "Yes" : "No"));

	Ret = GetAdaptersInfo(nullptr, &AdapterInfoSize);
	if (ERROR_SUCCESS != Ret)
	{
		if (ERROR_BUFFER_OVERFLOW != Ret)
		{
			return  GetLastError();
		}
	}

	AdapterInfo = (PIP_ADAPTER_INFO)GlobalAlloc(GPTR, AdapterInfoSize);
	if (nullptr == AdapterInfo)
	{
		return  GetLastError();
	}

	Ret = GetAdaptersInfo(AdapterInfo, &AdapterInfoSize);
	if (0 != Ret)
	{
		return GetLastError();
	}

	Adapter = AdapterInfo;

	while (Adapter)
	{
		switch (Adapter->Type)
		{
		case MIB_IF_TYPE_LOOPBACK:
			printf("\nLoopback adapter ");
			break;
		case MIB_IF_TYPE_SLIP:
			printf("\nSlip adapter ");
			break;
		case MIB_IF_TYPE_PPP:
			printf("\nPPP adapter ");
			break;
		case MIB_IF_TYPE_ETHERNET:
			printf("\nEthernet adapter ");
			break;
		case MIB_IF_TYPE_FDDI:
			printf("\nFDDI adapter ");
			break;
		case MIB_IF_TYPE_TOKENRING:
			printf("\nToken Ring adapter ");
			break;
		case MIB_IF_TYPE_OTHER:
		default:
			printf("\nSome other adapter ");
		}

		printf("%s%d:\n\n", "Ethernet", Adapter->Index);
		printf("\tDescription . . . . . . . . . . . : %s\n", Adapter->Description);
		printf("\tPhysical Address. . . . . . . . . : ");
		for (Index = 0; Index < Adapter->AddressLength; Index++)
		{
			if ((Adapter->AddressLength - 1) == Index)
			{
				// this is the last one
				printf("%.2X\n", (INT)Adapter->Address[Index]);
			}
			else
			{
				printf("%.2X-", (INT)Adapter->Address[Index]);
			}
		}


		printf("\tDHCP Enabled. . . . . . . . . . . : %s\n", (Adapter->DhcpEnabled ? "Yes" : "No"));

		//Message.Format("\tAutoconfiguration Enabled . . . . : %s\n");
		AddrString = &(Adapter->IpAddressList);
		while (AddrString)
		{
			printf("\tIPv4 Address. . . . . . . . . . . : %s\n", AddrString->IpAddress.String);
			printf("\tSubnet Mask . . . . . . . . . . . : %s\n", AddrString->IpMask.String);
			AddrString = AddrString->Next;
		}

#ifdef _WIN64
		error = _localtime64_s(&newtime, &Adapter->LeaseObtained);
#else
		error = _localtime32_s(&newtime, &Adapter->LeaseObtained);
#endif // WIN64
		if (error)
		{
			return GetLastError();
		}
		else
		{
			// switch it to MBCS
			error = asctime_s(Buffer.GetBuffer(), 32, &newtime);
			if (error)
			{
				return  GetLastError();
			}
			else
			{
				printf("\tLease Obtained. . . . . . . . . . : %s", Buffer.GetBuffer());
			}
		}
#ifdef _WIN64
		error = _localtime64_s(&newtime, &Adapter->LeaseExpires);
#else
		error = _localtime32_s(&newtime, &Adapter->LeaseExpires);
#endif // _WIN64
		if (error)
		{
			//printf("[!] _localtime*_s: ", GetLastError());
		}
		else
		{
			// switch is to MBCS
			error = asctime_s(Buffer.GetBuffer(), 32, &newtime);
			if (error)
			{
				//printf("[!] asctime_s: ", GetLastError());
			}
			else
			{
				printf("\tLease Expires . . . . . . . . . . : %s", Buffer.GetBuffer());
			}
		}

		printf("\tDefault Gateway . . . . . . . . . : %s\n", Adapter->GatewayList.IpAddress.String);

		AddrString = Adapter->GatewayList.Next;
		while (AddrString)
		{
			printf("%51s\n", AddrString->IpAddress.String);
		}

		printf("\tDHCP Server . . . . . . . . . . . : %s\n", Adapter->DhcpServer.IpAddress.String);

		Adapter = Adapter->Next;
	}
	GlobalFree(AdapterInfo);
	return 0;
}