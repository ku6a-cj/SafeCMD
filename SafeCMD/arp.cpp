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
#include<string.h>
#include"arp.h"


#define IPADDR_BUF_SIZE 128
#define IPTYPE_BUF_SIZE 128
#define PHYSADDR_BUF_SIZES 256



VOID
Usage()
{
	printf("\n \
ARP - s inet_addr eth_addr[if_addr] \n \
ARP - d inet_addr[if_addr]			\n \
ARP - a[inet_addr][-N if_addr][-v]	\n \
\n \
- a            Displays current ARP entries by interrogating the current	\n \
protocol data.If inet_addr is specified, the IPand Physical					\n \
addresses for only the specified computer are displayed.If					\n \
more than one network interface uses ARP, entries for each ARP				\n \
table are displayed.														\n \
- g            Same as - a.													\n \
- v            Displays current ARP entries in verbose mode.All invalid		\n \
entries and entries on the loop - back interface will be shown.				\n \
inet_addr     Specifies an internet address.								\n \
- N if_addr    Displays the ARP entries for the network interface specified	\n \
by if_addr.																	\n \
- d            Deletes the host specified by inet_addr.inet_addr may be		\n \
wildcarded with * to delete all hosts.										\n \
- s            Adds the host and associates the Internet address inet_addr	\n \
with the Physical address eth_addr.The Physical address is					\n \
given as 6 hexadecimal bytes separated by hyphens.The entry					\n \
is permanent.																\n \
eth_addr      Specifies a physical address.									\n \
if_addr       If present, this specifies the Internet address of the		\n \
interface whose address translation table should be modified.				\n \
If not present, the first applicable interface will be used.				\n \
Example :																	\n \
	> arp - s 157.55.85.212   00 - aa - 00 - 62 - c6 - 09  ....Adds a static entry.	\n \
	> arp - a                                    ....Displays the arp table.			\n   ");

	return;
}

VOID
GetConnectionTable(CStringA Protocol)
{
	CStringA printf = "";
#ifdef _DEBUG
	_tprintf(L"[*] %s:%d: Obtaining connectiontable for %s...\n", __FUNCTION__, __LINE__, Protocol.GetBuffer());
#endif // _DEBUG

	DWORD Ret = NO_ERROR;

	if (0 == Protocol.CompareNoCase("tcp"))
	{
		PMIB_TCPTABLE TcpTable = nullptr;
		Ret = MyGetTcpTable(TcpTable, TRUE);
		if (NO_ERROR != Ret)
		{
			_tprintf(L"[!] %s:%d: Could not obtain tcp connection table\n", __FUNCTION__, __LINE__);
			if (TcpTable) GlobalFree(TcpTable);

			return;
		}
		else
		{
			PrintTcpTable(TcpTable);
			GlobalFree(TcpTable);
		}
	}
	else if (0 == Protocol.CompareNoCase("udp"))
	{
		Ret = NO_ERROR;
		PMIB_UDPTABLE UdpTable = nullptr;
		Ret = MyGetUdpTable(UdpTable, TRUE);
		if (NO_ERROR != Ret)
		{
			_tprintf(L"[!] %s:%d: Could not obtain udp connection table\n", __FUNCTION__, __LINE__);
			if (UdpTable) GlobalFree(UdpTable);

			return;
		}
		else
		{
			PrintUdpTable(UdpTable);
			GlobalFree(UdpTable);

			return;
		}
	}
	else
	{
		_tprintf(L"[!] %s:%d: Cannot obtain connection table for that protocol\n", __FUNCTION__, __LINE__);
		return;
	}
}


VOID
WINAPI
GetStats(CStringA Protocol)
{
	CStringA Message = "";
#ifdef _DEBUG
	printf("[*] %s:%d: Obtaining stats for %s...\n", __FUNCTION__, __LINE__, Protocol.GetBuffer());
#endif // _DEBUG

	DWORD Ret = NO_ERROR;
	// param check
	if (CStringA() == Protocol)
	{
		// default just get all stats
		// ip and ip6
		PMIB_IPSTATS IpStatsv4 = nullptr;
		PMIB_IPSTATS IpStatsv6 = nullptr;

		// grab the ip4 stats
		//
		Ret = MyGetIpStats(IpStatsv4, AF_INET);
		if (NO_ERROR != Ret)
		{
			printf("[!] %s:%d: Could not get IP stats for family %s\n", __FUNCTION__, __LINE__, "AF_INET");
		}
		else
		{
			PrintIpStats(IpStatsv4, AF_INET);
		}

		// grab the ip6 stats
		//
		Ret = MyGetIpStats(IpStatsv6, AF_INET6);
		if (NO_ERROR != Ret)
		{
			printf("[!] %s:%d: Could not get IP stats for family %s\n", __FUNCTION__, __LINE__, "AF_INET6");
		}
		else
		{
			PrintIpStats(IpStatsv6, AF_INET6);
		}
		// free what might have been allocated
		if (IpStatsv4) GlobalFree(IpStatsv4);
		if (IpStatsv6) GlobalFree(IpStatsv6);

		// tcp and tcp6
		PMIB_TCPSTATS TcpStats4 = nullptr;
		PMIB_TCPSTATS TcpStats6 = nullptr;

		// grab the tcp4 stats
		//
		Ret = MyGetTcpStats(TcpStats4, AF_INET);
		if (NO_ERROR != Ret)
		{
			printf("[!] %s:%d: Could not get TCP stats for family %s\n", __FUNCTION__, __LINE__, "AF_INET");
		}
		else
		{
			PrintTcpStats(TcpStats4, AF_INET);
		}

		// grab the tcp6 stats
		//
		Ret = MyGetTcpStats(TcpStats6, AF_INET6);
		if (NO_ERROR != Ret)
		{
			printf("[!] %s:%d: Could not get TCP stats for family %s\n", __FUNCTION__, __LINE__, "AF_INET6");
		}
		else
		{
			PrintTcpStats(TcpStats6, AF_INET6);
		}

		// free what might have been allocated
		//
		if (TcpStats4) GlobalFree(TcpStats4);
		if (TcpStats6) GlobalFree(TcpStats6);

		// udp and udp6
		PMIB_UDPSTATS UdpStats4 = nullptr;
		PMIB_UDPSTATS UdpStats6 = nullptr;

		// grab the udp stats
		//
		Ret = MyGetUdpStats(UdpStats4, AF_INET);
		if (NO_ERROR != Ret)
		{
			printf("[!] %s:%d: Could not get UDP stats for family %s\n", __FUNCTION__, __LINE__, "AF_INET");
		}
		else
		{
			PrintUdpStats(UdpStats4, AF_INET);
		}

		// grab the udp6 stats
		//
		Ret = MyGetUdpStats(UdpStats6, AF_INET6);
		if (NO_ERROR != Ret)
		{
			printf("[!] %s:%d: Could not get UDP stats for family %s\n", __FUNCTION__, __LINE__, "AF_INET6");
		}
		else
		{
			PrintUdpStats(UdpStats6, AF_INET6);
		}

		// clean up what might have been allocated
		//
		if (UdpStats4) GlobalFree(UdpStats4);
		if (UdpStats6) GlobalFree(UdpStats6);

		// icmp and icmp6
		PMIB_ICMP    Icmp4 = nullptr;
		PMIB_ICMP_EX IcmpEx6 = nullptr;

		// grab the icmp stats
		//
		Ret = MyGetIcmpStats(Icmp4, AF_INET);
		if (NO_ERROR != Ret)
		{
			printf("[!] %s:%d: Could not get UDP stats for family %s\n", __FUNCTION__, __LINE__, "AF_INET");
		}
		else
		{
			PrintIcmpStats(&(Icmp4->stats), AF_INET);
		}

		// grab the icmp6 stats
		//
		Ret = MyGetIcmpStatsEx(IcmpEx6, AF_INET6);
		if (NO_ERROR != Ret)
		{
			printf("[!] %s:%d: Could not get ICMP stats for family %s\n", __FUNCTION__, __LINE__, "AF_INET6");
		}
		else
		{
			PrintIcmpStatsEx(IcmpEx6, AF_INET6);
		}

		if (Icmp4) GlobalFree(Icmp4);
		if (IcmpEx6) GlobalFree(IcmpEx6);

		GetConnectionTable(CStringA("tcp"));
		GetConnectionTable(CStringA("udp"));
	}

	// matching specific protocols
	//
	// ip
	//
	else if (0 == Protocol.CompareNoCase("ip"))
	{
#ifdef _DEBUG
		printf("[*] %s:%d: ip chosen\n", __FUNCTION__, __LINE__);
#endif // _DEBUG

		PMIB_IPSTATS IpStatsv4 = nullptr;

		// grab the ip4 stats
		//
		Ret = MyGetIpStats(IpStatsv4, AF_INET);
		if (NO_ERROR != Ret)
		{
			printf("[!] %s:%d: Could not get IP stats for family %s\n", __FUNCTION__, __LINE__, "AF_INET");
		}
		else
		{
			PrintIpStats(IpStatsv4, AF_INET);
		}

		if (IpStatsv4) GlobalFree(IpStatsv4);

		return;
	}
	// ip6
	// 
	else if (0 == Protocol.CompareNoCase("ip6"))
	{
#ifdef _DEBUG
		printf("[*] %s:%d: ip6 chosen\n", __FUNCTION__, __LINE__);
#endif // _DEBUG

		PMIB_IPSTATS IpStatsv6 = nullptr;

		Ret = MyGetIpStats(IpStatsv6, AF_INET6);
		if (NO_ERROR != Ret)
		{
			printf("[!] %s:%d: Could not get IP stats for family %s\n", __FUNCTION__, __LINE__, "AF_INET6");
		}
		else
		{
			PrintIpStats(IpStatsv6, AF_INET6);
		}

		if (IpStatsv6) GlobalFree(IpStatsv6);

		return;
	}
	// tcp
	//
	else if (0 == Protocol.CompareNoCase("tcp"))
	{
#ifdef _DEBUG
		printf("[*] %s:%d: tcp chosen\n", __FUNCTION__, __LINE__);
#endif // _DEBUG

		PMIB_TCPSTATS TcpStats4 = nullptr;

		// grab the tcp4 stats
		//
		Ret = MyGetTcpStats(TcpStats4, AF_INET);
		if (NO_ERROR != Ret)
		{
			printf("[!] %s:%d: Could not get TCP stats for family %s\n", __FUNCTION__, __LINE__, "AF_INET");
		}
		else
		{
			PrintTcpStats(TcpStats4, AF_INET);
		}

		if (TcpStats4) GlobalFree(TcpStats4);
	}
	// tcp6
	//
	else if (0 == Protocol.CompareNoCase("tcp6"))
	{
#ifdef _DEBUG
		printf("[*] %s:%d: tcp6 chosen\n", __FUNCTION__, __LINE__);
#endif // _DEBUG

		PMIB_TCPSTATS TcpStats6 = nullptr;

		Ret = MyGetTcpStats(TcpStats6, AF_INET6);
		if (NO_ERROR != Ret)
		{
			printf("[!] %s:%d: Could not get TCP stats for family %s\n", __FUNCTION__, __LINE__, "AF_INET6");
		}
		else
		{
			PrintTcpStats(TcpStats6, AF_INET6);
		}

		if (TcpStats6) GlobalFree(TcpStats6);
	}
	// udp
	//
	else if (0 == Protocol.CompareNoCase("udp"))
	{
#ifdef _DEBUG
		Message.Format("[*] %s:%d: udp chosen\n", __FUNCTION__, __LINE__);
#endif // _DEBUG

		PMIB_UDPSTATS UdpStats4 = nullptr;

		Ret = MyGetUdpStats(UdpStats4, AF_INET);
		if (NO_ERROR != Ret)
		{
			printf("[!] %s:%d: Could not get UDP stats for family %s\n", __FUNCTION__, __LINE__, "AF_INET");
		}
		else
		{
			PrintUdpStats(UdpStats4, AF_INET);
		}

		if (UdpStats4) GlobalFree(UdpStats4);
	}
	// udp6
	//
	else if (0 == Protocol.CompareNoCase("udp6"))
	{
#ifdef _DEBUG
		Message.Format("[*] %s:%d: udp6 chosen\n", __FUNCTION__, __LINE__);
#endif // _DEBUG

		PMIB_UDPSTATS UdpStats6 = nullptr;

		Ret = MyGetUdpStats(UdpStats6, AF_INET6);
		if (NO_ERROR != Ret)
		{
			Message.Format("[!] %s:%d: Could not get UDP stats for family %s\n", __FUNCTION__, __LINE__, "AF_INET6");
		}
		else
		{
			PrintUdpStats(UdpStats6, AF_INET6);
		}

		if (UdpStats6) GlobalFree(UdpStats6);
	}
	// icmp
	//
	else if (0 == Protocol.CompareNoCase("icmp"))
	{
#ifdef _DEBUG
		Message.Format("[*] %s:%d: icmp chosen\n", __FUNCTION__, __LINE__);
#endif // _DEBUG

		PMIB_ICMP    Icmp4 = nullptr;

		// grab the icmp stats
		//
		Ret = MyGetIcmpStats(Icmp4, AF_INET);
		if (NO_ERROR != Ret)
		{
			Message.Format("[!] %s:%d: Could not get UDP stats for family %s\n", __FUNCTION__, __LINE__, "AF_INET");
		}
		else
		{
			PrintIcmpStats(&(Icmp4->stats), AF_INET);
		}

		if (Icmp4) GlobalFree(Icmp4);
	}
	// icmp6
	//
	else if (0 == Protocol.CompareNoCase("icmp6"))
	{
#ifdef _DEBUG
		Message.Format("[*] %s:%d: icmp6 chosen\n", __FUNCTION__, __LINE__);
#endif // _DEBUG

		PMIB_ICMP_EX IcmpEx6 = nullptr;
		// grab the icmp6 stats
		//
		Ret = MyGetIcmpStatsEx(IcmpEx6, AF_INET6);
		if (NO_ERROR != Ret)
		{
			Message.Format("[!] %s:%d: Could not get ICMP stats for family %s\n", __FUNCTION__, __LINE__, "AF_INET6");
		}
		else
		{
			PrintIcmpStatsEx(IcmpEx6, AF_INET6);
		}

		if (IcmpEx6) GlobalFree(IcmpEx6);
	}
	else
	{
		Message.Format("[!] %s:%d: What protocol is that?!\n", __FUNCTION__, __LINE__);
		return;
	}
}


DWORD
WINAPI
MyGetIpStats(PMIB_IPSTATS& IpStats, ULONG Family)
{
	CStringA Message = "";
#ifdef _DEBUG
	Message.Format("[*] %s:%d: Obtaining the IP %lu stats...\n", __FUNCTION__, __LINE__, Family);
#endif // _DEBUG

	IpStats = (PMIB_IPSTATS)GlobalAlloc(GPTR, sizeof(MIB_IPSTATS));
	if (!IpStats) return GetLastError();

	// rets NO_ERROR on success
	return GetIpStatisticsEx(IpStats, Family);
}


DWORD
WINAPI
MyGetIcmpStats(PMIB_ICMP& IcmpStats, ULONG Family)
{
	CStringA Message = "";
#ifdef _DEBUG
	Message.Format("[*] %s:%d: Obtaining the ICMP %lu stats...\n", __FUNCTION__, __LINE__, Family);

#endif // _DEBUG

	IcmpStats = (PMIB_ICMP)GlobalAlloc(GPTR, sizeof(MIB_ICMP));
	if (!IcmpStats) return GetLastError();

	return GetIcmpStatistics(IcmpStats);
}


DWORD
WINAPI
MyGetIcmpStatsEx(PMIB_ICMP_EX& IcmpStats, ULONG Family)
{
	CStringA Message = "";
#ifdef _DEBUG
	Message.Format("[*] %s:%d: Obtaining the ICMP %lu stats...\n", __FUNCTION__, __LINE__, Family);

#endif // _DEBUG

	IcmpStats = (PMIB_ICMP_EX)GlobalAlloc(GPTR, sizeof(MIB_ICMP_EX));
	if (!IcmpStats) return GetLastError();

	return GetIcmpStatisticsEx(IcmpStats, Family);
}


DWORD
WINAPI
MyGetTcpStats(PMIB_TCPSTATS& TcpStats, ULONG Family)
{
	CStringA Message = "";
#ifdef _DEBUG
	Message.Format("[*] %s:%d: Obtaining the TCP %lu stats...\n", __FUNCTION__, __LINE__, Family);
	
#endif // _DEBUG

	TcpStats = (PMIB_TCPSTATS)GlobalAlloc(GPTR, sizeof(MIB_TCPSTATS));
	if (!TcpStats) return GetLastError();

	switch (Family)
	{
	case AF_INET:
		return GetTcpStatistics(TcpStats);
		break;
	case AF_INET6:
		return GetTcpStatisticsEx(TcpStats, Family);
		break;
	default:
		return ERROR_GEN_FAILURE;
		break;
	}


}


DWORD
WINAPI
MyGetUdpStats(PMIB_UDPSTATS& UdpStats, ULONG Family)
{
#ifdef _DEBUG
	CStringA Message = "";
	Message.Format("[*] %s:%d: Obtaining the UDP %lu stats...\n", __FUNCTION__, __LINE__, Family);
	
#endif // _DEBUG

	UdpStats = (PMIB_UDPSTATS)GlobalAlloc(GPTR, sizeof(MIB_UDPSTATS));
	if (!UdpStats) return GetLastError();

	if (AF_INET == Family)
	{
		return GetUdpStatistics(UdpStats);
	}
	else
	{
		return GetUdpStatisticsEx(UdpStats, Family);
	}
}


VOID
WINAPI
PrintIpStats(PMIB_IPSTATS IpStats, ULONG Family)
{
	CStringA Message = "";
#ifdef _DEBUG
	Message.Format("[*] %s:%d: Dumping IP stats for %lu...\n", __FUNCTION__, __LINE__, Family);
	
#endif // _DEBUG

	// param check
	if (NULL == IpStats)
	{
		Message.Format("[!] %s:%d: Bad params\n", __FUNCTION__, __LINE__);
	
		return;
	}

	CStringA Forwarding = "";

	switch (IpStats->dwForwarding)
	{
	case MIB_IP_FORWARDING:
		Forwarding = "Enabled";
		break;
	case MIB_IP_NOT_FORWARDING:
		Forwarding = "Not Enabled";
		break;
	case MIB_USE_CURRENT_FORWARDING:
		Forwarding = "Use current setting";
		break;
	default:
		Forwarding = "";
		break;
	}

	if (Family == AF_INET)
	{
		Message.Format("IPv4 Statistics\n");
		
		Message.Format("\
	dwForwarding       = %s\n\
	dwDefaultTTL       = %lu\n\
	dwInReceives       = %lu\n\
	dwInHdrErrors      = %lu\n\
	dwInAddrErrors     = %lu\n\
	dwForwDatagrams    = %lu\n\
	dwInUnknownProtos  = %lu\n\
	dwInDiscards       = %lu\n\
	dwInDelivers       = %lu\n\
	dwOutRequests      = %lu\n\
	dwRoutingDiscards  = %lu\n\
	dwOutDiscards      = %lu\n\
	dwOutNoRoutes      = %lu\n\
	dwReasmTimeout     = %lu\n\
	dwReasmReqds       = %lu\n\
	dwReasmOks         = %lu\n\
	dwReasmFails       = %lu\n\
	dwFragOks          = %lu\n\
	dwFragFails        = %lu\n\
	dwFragCreates      = %lu\n\
	dwNumIf            = %lu\n\
	dwNumAddr          = %lu\n\
	dwNumRoutes        = %lu\n",
			Forwarding.GetBuffer(),
			//IpStats->dwForwarding,
			IpStats->dwDefaultTTL,
			IpStats->dwInReceives,
			IpStats->dwInHdrErrors,
			IpStats->dwInAddrErrors,
			IpStats->dwForwDatagrams,
			IpStats->dwInUnknownProtos,
			IpStats->dwInDiscards,
			IpStats->dwInDelivers,
			IpStats->dwOutRequests,
			IpStats->dwRoutingDiscards,
			IpStats->dwOutDiscards,
			IpStats->dwOutNoRoutes,
			IpStats->dwReasmTimeout,
			IpStats->dwReasmReqds,
			IpStats->dwReasmOks,
			IpStats->dwReasmFails,
			IpStats->dwFragOks,
			IpStats->dwFragFails,
			IpStats->dwFragCreates,
			IpStats->dwNumIf,
			IpStats->dwNumAddr,
			IpStats->dwNumRoutes);
		
	}
	else if (Family == AF_INET6)
	{
		Message.Format("IPv6 Statistics\n");
		
		Message.Format("\
	dwForwarding       = %s\n\
	dwDefaultTTL       = %lu\n\
	dwInReceives       = %lu\n\
	dwInHdrErrors      = %lu\n\
	dwInAddrErrors     = %lu\n\
	dwForwDatagrams    = %lu\n\
	dwInUnknownProtos  = %lu\n\
	dwInDiscards       = %lu\n\
	dwInDelivers       = %lu\n\
	dwOutRequests      = %lu\n\
	dwRoutingDiscards  = %lu\n\
	dwOutDiscards      = %lu\n\
	dwOutNoRoutes      = %lu\n\
	dwReasmTimeout     = %lu\n\
	dwReasmReqds       = %lu\n\
	dwReasmOks         = %lu\n\
	dwReasmFails       = %lu\n\
	dwFragOks          = %lu\n\
	dwFragFails        = %lu\n\
	dwFragCreates      = %lu\n\
	dwNumIf            = %lu\n\
	dwNumAddr          = %lu\n\
	dwNumRoutes        = %lu\n",
			Forwarding.GetBuffer(),
			//IpStats->dwForwarding,
			IpStats->dwDefaultTTL,
			IpStats->dwInReceives,
			IpStats->dwInHdrErrors,
			IpStats->dwInAddrErrors,
			IpStats->dwForwDatagrams,
			IpStats->dwInUnknownProtos,
			IpStats->dwInDiscards,
			IpStats->dwInDelivers,
			IpStats->dwOutRequests,
			IpStats->dwRoutingDiscards,
			IpStats->dwOutDiscards,
			IpStats->dwOutNoRoutes,
			IpStats->dwReasmTimeout,
			IpStats->dwReasmReqds,
			IpStats->dwReasmOks,
			IpStats->dwReasmFails,
			IpStats->dwFragOks,
			IpStats->dwFragFails,
			IpStats->dwFragCreates,
			IpStats->dwNumIf,
			IpStats->dwNumAddr,
			IpStats->dwNumRoutes);
	
	}

	return;
}


VOID
WINAPI
PrintUdpStats(PMIB_UDPSTATS UdpStats, ULONG Family)
{
	CStringA Message = "";
#ifdef _DEBUG
	Message.Format("[*] %s:%d: Dumping UDP stats...\n", __FUNCTION__, __LINE__);

#endif // _DEBUG

	// param check
	if (NULL == UdpStats)
	{
		Message.Format("[!] %s:%d: Bad params\n", __FUNCTION__, __LINE__);
		
		return;
	}

	if (AF_INET == Family)
	{
		Message.Format("\nUDP Statistics\n");
	
		Message.Format("\
	dwInDatagrams      = %lu\n\
	dwNoPorts          = %lu\n\
	dwInErrors         = %lu\n\
	dwOutDatagrams     = %lu\n\
	dwNumAddrs         = %lu\n",
			UdpStats->dwInDatagrams,
			UdpStats->dwNoPorts,
			UdpStats->dwInErrors,
			UdpStats->dwOutDatagrams,
			UdpStats->dwNumAddrs);
	
	}
	else
	{
		Message.Format("\nUDPv6 Statistics\n");
	
		Message.Format("\
	dwInDatagrams      = %lu\n\
	dwNoPorts          = %lu\n\
	dwInErrors         = %lu\n\
	dwOutDatagrams     = %lu\n\
	dwNumAddrs         = %lu\n",
			UdpStats->dwInDatagrams,
			UdpStats->dwNoPorts,
			UdpStats->dwInErrors,
			UdpStats->dwOutDatagrams,
			UdpStats->dwNumAddrs);
	
	}

	return;
}


VOID
WINAPI
PrintTcpStats(PMIB_TCPSTATS TcpStats, ULONG Family)
{
	CStringA Message = "";
#ifdef _DEBUG
	Message.Format("[*] %s:%d: Dumping TCP stats...\n", __FUNCTION__, __LINE__);

#endif // _DEBUG

	// param check
	if (NULL == TcpStats)
	{
		Message.Format("[!] %s:%d: Bad params\n", __FUNCTION__, __LINE__);

		return;
	}
	if (AF_INET == Family)
	{
		Message.Format("\nTCPv4 Statistics\n");
		
		Message.Format("\
	dwRtoAlgorithm     = %lu\n\
	dwRtoMin           = %lu\n\
	dwRtoMax           = %lu\n\
	dwMaxConn          = %lu\n\
	dwActiveOpens      = %lu\n\
	dwPassiveOpens     = %lu\n\
	dwAttemptFails     = %lu\n\
	dwEstabResets      = %lu\n\
	dwCurrEstab        = %lu\n\
	dwInSegs           = %lu\n\
	dwOutSegs          = %lu\n\
	dwRetransSegs      = %lu\n\
	dwInErrs           = %lu\n\
	dwOutRsts          = %lu\n\
	dwNumConns         = %lu\n",
			TcpStats->dwRtoAlgorithm,
			TcpStats->dwRtoMin,
			TcpStats->dwRtoMax,
			TcpStats->dwMaxConn,
			TcpStats->dwActiveOpens,
			TcpStats->dwPassiveOpens,
			TcpStats->dwAttemptFails,
			TcpStats->dwEstabResets,
			TcpStats->dwCurrEstab,
			TcpStats->dwInSegs,
			TcpStats->dwOutSegs,
			TcpStats->dwRetransSegs,
			TcpStats->dwInErrs,
			TcpStats->dwOutRsts,
			TcpStats->dwNumConns);
	
	}
	else if (AF_INET6 == Family)
	{
		Message.Format("\nTCPv6 Statistics\n");
	
		Message.Format("\
	dwRtoAlgorithm     = %lu\n\
	dwRtoMin           = %lu\n\
	dwRtoMax           = %lu\n\
	dwMaxConn          = %lu\n\
	dwActiveOpens      = %lu\n\
	dwPassiveOpens     = %lu\n\
	dwAttemptFails     = %lu\n\
	dwEstabResets      = %lu\n\
	dwCurrEstab        = %lu\n\
	dwInSegs           = %lu\n\
	dwOutSegs          = %lu\n\
	dwRetransSegs      = %lu\n\
	dwInErrs           = %lu\n\
	dwOutRsts          = %lu\n\
	dwNumConns         = %lu\n",
			TcpStats->dwRtoAlgorithm,
			TcpStats->dwRtoMin,
			TcpStats->dwRtoMax,
			TcpStats->dwMaxConn,
			TcpStats->dwActiveOpens,
			TcpStats->dwPassiveOpens,
			TcpStats->dwAttemptFails,
			TcpStats->dwEstabResets,
			TcpStats->dwCurrEstab,
			TcpStats->dwInSegs,
			TcpStats->dwOutSegs,
			TcpStats->dwRetransSegs,
			TcpStats->dwInErrs,
			TcpStats->dwOutRsts,
			TcpStats->dwNumConns);
	
	}

	return;
}


VOID
WINAPI
PrintIcmpStats(MIBICMPINFO* IcmpStats, ULONG Family)
{
	CStringA Message = "";
#ifdef _DEBUG
	Message.Format("[*] %s:%d: Dumping ICMP stats...\n", __FUNCTION__, __LINE__);

#endif // _DEBUG

	// param check
	if (NULL == IcmpStats)
	{
		Message.Format("[!] %s:%d: Bad params\n", __FUNCTION__, __LINE__);
		
		return;
	}

	Message.Format("\n%-20s %10s %10s\n", "ICMP Statistics", "IN", "OUT");


	Message.Format("%-20s %10s %10s\n", "--------------------", "------", "------");
	
	Message.Format("%20s %10lu %10lu\n", "dwMsgs", IcmpStats->icmpInStats.dwMsgs, IcmpStats->icmpOutStats.dwMsgs);
	
	Message.Format("%20s %10lu %10lu\n", "dwErrors", IcmpStats->icmpInStats.dwErrors, IcmpStats->icmpOutStats.dwErrors);
	
	Message.Format("%20s %10lu %10lu\n", "dwDestUnreachs", IcmpStats->icmpInStats.dwDestUnreachs, IcmpStats->icmpOutStats.dwDestUnreachs);
	Message.Format("%20s %10lu %10lu\n", "dwTimeExcds", IcmpStats->icmpInStats.dwTimeExcds, IcmpStats->icmpOutStats.dwTimeExcds);
	Message.Format("%20s %10lu %10lu\n", "dwParmProbs", IcmpStats->icmpInStats.dwParmProbs, IcmpStats->icmpOutStats.dwParmProbs);
	Message.Format("%20s %10lu %10lu\n", "dwSrcQuenchs", IcmpStats->icmpInStats.dwSrcQuenchs, IcmpStats->icmpOutStats.dwSrcQuenchs);
	Message.Format("%20s %10lu %10lu\n", "dwRedirects", IcmpStats->icmpInStats.dwRedirects, IcmpStats->icmpOutStats.dwRedirects);
	Message.Format("%20s %10lu %10lu\n", "dwEchos", IcmpStats->icmpInStats.dwEchos, IcmpStats->icmpOutStats.dwEchos);
	Message.Format("%20s %10lu %10lu\n", "dwEchoReps", IcmpStats->icmpInStats.dwEchoReps, IcmpStats->icmpOutStats.dwEchoReps);
	Message.Format("%20s %10lu %10lu\n", "dwTimestamps", IcmpStats->icmpInStats.dwTimestamps, IcmpStats->icmpOutStats.dwTimestamps);
	Message.Format("%20s %10lu %10lu\n", "dwTimestampReps", IcmpStats->icmpInStats.dwTimestampReps, IcmpStats->icmpOutStats.dwTimestampReps);
	Message.Format("%20s %10lu %10lu\n", "dwAddrMasks", IcmpStats->icmpInStats.dwAddrMasks, IcmpStats->icmpOutStats.dwAddrMasks);
	Message.Format("%20s %10lu %10lu\n", "dwAddrMaskReps", IcmpStats->icmpInStats.dwAddrMaskReps, IcmpStats->icmpOutStats.dwAddrMaskReps);

	return;
}


VOID
WINAPI
PrintIcmpStatsEx(PMIB_ICMP_EX IcmpEx, ULONG Family)
{
	CStringA Message = "";
#ifdef _DEBUG
	Message.Format("[*] %s:%d: Dumping ICMP In stats...\n", __FUNCTION__, __LINE__);
#endif // _DEBUG

	// param check
	if (NULL == IcmpEx)
	{
		Message.Format("[!] %s:%d: Bad params\n", __FUNCTION__, __LINE__);
		return;
	}

	Message.Format("\n%-20s %10s %10s\n", "ICMPv6 Statistics", "IN", "OUT");

	Message.Format("%-20s %10s %10s\n", "--------------------", "------", "------");

	Message.Format("%20s %10lu %10lu\n", "Errors", IcmpEx->icmpInStats.dwErrors, IcmpEx->icmpInStats.dwErrors);

	Message.Format("%20s %10lu %10lu\n", "Messages", IcmpEx->icmpInStats.dwMsgs, IcmpEx->icmpOutStats.dwMsgs);

	return;
}


VOID
WINAPI
PrintTcpTable(PMIB_TCPTABLE TcpTable)
{
	CStringA Message = "";
#ifdef _DEBUG
	Message.Format("[*] %s:%d: Dumping the TCP table entries...\n", __FUNCTION__, __LINE__);
#endif // _DEBUG
	// param check
	if (NULL == TcpTable)
	{
		Message.Format("[!] %s:%d: Bad params\n", __FUNCTION__, __LINE__);
		return;
	}

	struct in_addr LocalAddr = { 0 };
	struct in_addr RemoteAddr = { 0 };
	CStringA ConnState = "CLOSED";
	CStringA LocalAddress = "";
	CStringA ForeignAddress = "";
	DWORD LocalPort = 0;
	DWORD ForeignPort = 0;

	Message.Format("\nActive TCP Connections\n\n");
	Message.Format("%5s %-20s %-20s %-s\n", "Proto", "Local Address", "Foreign Address", "State");

	Message.Format("%5s %-20s %-20s %-s\n", "-----", "------------------", "------------------", "--------");

	// loop over the table entries
	DWORD Index = 0;
	for (; Index < TcpTable->dwNumEntries; ++Index)
	{
		// check the state of the connection
		switch (TcpTable->table[Index].State)
		{
		case MIB_TCP_STATE_CLOSED:
			ConnState = "CLOSED";
			break;
		case MIB_TCP_STATE_LISTEN:
			ConnState = "LISTEN";
			break;
		case MIB_TCP_STATE_SYN_SENT:
			ConnState = "SYN SENT";
			break;
		case MIB_TCP_STATE_SYN_RCVD:
			ConnState = "SYN RCVD";
			break;
		case MIB_TCP_STATE_ESTAB:
			ConnState = "ESTABLISHED";
			break;
		case MIB_TCP_STATE_FIN_WAIT1:
			ConnState = "FIN WAIT1";
			break;
		case MIB_TCP_STATE_FIN_WAIT2:
			ConnState = "FIN WAIT2";
			break;
		case MIB_TCP_STATE_CLOSE_WAIT:
			ConnState = "CLOSE WAIT";
			break;
		case MIB_TCP_STATE_CLOSING:
			ConnState = "CLOSING";
			break;
		case MIB_TCP_STATE_LAST_ACK:
			ConnState = "LAST ACK";
			break;
		case MIB_TCP_STATE_TIME_WAIT:
			ConnState = "TIME WAIT";
			break;
		case MIB_TCP_STATE_DELETE_TCB:
			ConnState = "DELETE TCB";
			break;
		case MIB_TCP_STATE_RESERVED:
			ConnState = "RESERVED";
			break;
		default:
			ConnState = "State not known!\n";
			break;
		}
		// update the local addr
		LocalAddr.S_un.S_addr = TcpTable->table[Index].dwLocalAddr;

		// maybe there is a remote port
		if (0 != ConnState.CompareNoCase("listen"))
		{
			ForeignPort = TcpTable->table[Index].dwRemotePort;
		}
		else
		{
			ForeignPort = 0;
		}

		// update for foreign addr
		RemoteAddr.S_un.S_addr = TcpTable->table[Index].dwRemoteAddr;

		if (!inet_ntop(AF_INET, (PVOID) & (LocalAddr.S_un.S_addr), LocalAddress.GetBuffer(), NI_MAXHOST))
		{
			
			return ;
		}

		if (!inet_ntop(AF_INET, (PVOID) & (RemoteAddr.S_un.S_addr), ForeignAddress.GetBuffer(), NI_MAXHOST))
		{
			
			return ;
		}

		LocalPort = ntohs(0xffff & TcpTable->table[Index].dwLocalPort);
		ForeignPort = ntohs(0xffff & TcpTable->table[Index].dwRemotePort);

		// for alignment, it's best to put them into one string buffer
		CStringA LocalAddrAndPort = "";
		CStringA RemoteAddrAndPort = "";

		LocalAddrAndPort.Format("%s:%u", LocalAddress.GetBuffer(), LocalPort);
		RemoteAddrAndPort.Format("%s:%u", ForeignAddress.GetBuffer(), ForeignPort);

		Message.Format("%*s %*s %*s %*s\n", -5, "TCP",
			-20, LocalAddrAndPort.GetBuffer(),
			-20, RemoteAddrAndPort.GetBuffer(),
			-10, ConnState.GetBuffer()
		);
	}

}


DWORD
WINAPI
MyGetTcpTable(PMIB_TCPTABLE& TcpTable, BOOL Order)
{
	CStringA Message = "";
#ifdef _DEBUG
	Message.Format("[*] %s:%d: Obtaining the TCP table...\n", __FUNCTION__, __LINE__);
#endif // _DEBUG

	DWORD Ret = 0;
	DWORD TcpTableSize = 0;

	Ret = GetTcpTable(TcpTable, &TcpTableSize, Order);
	if (NO_ERROR != Ret)
	{
		if (ERROR_INSUFFICIENT_BUFFER != Ret)
		{
			return  GetLastError();
		}
		else
		{
			TcpTable = (PMIB_TCPTABLE)GlobalAlloc(GPTR, TcpTableSize);
			if (!TcpTable) return  GetLastError();
		}
	}

	Ret = GetTcpTable(TcpTable, &TcpTableSize, Order);
	if (NO_ERROR == Ret)
	{
#ifdef _DEBUG
		Message.Format("[*] %s:%d: Successfully obtained TCP data\n", __FUNCTION__, __LINE__);
		
#endif // _DEBUG

		return Ret;
	}
	else
	{
		return  GetLastError();
	}
}


VOID
WINAPI
PrintUdpTable(PMIB_UDPTABLE UdpTable)
{
	CStringA Message = "";
#ifdef _DEBUG
	Message.Format("[*] %s:%d: Dumping UDP table with %d entries\n", __FUNCTION__, __LINE__, UdpTable->dwNumEntries);
#endif // _DEBUG
	// param check
	if (NULL == UdpTable)
	{
		Message.Format("[!] %s:%d: Bad params\n", __FUNCTION__, __LINE__);
		return;
	}

	struct in_addr TempAddr = { 0 };
	Message.Format("\nActive UDP Connections\n\n");

	Message.Format("%5s %-20s\n", "Proto", "Local Address");

	Message.Format("%5s %-20s\n", "-----", "------------------");

	DWORD Index = 0;
	DWORD Port = 0;
	for (; Index < UdpTable->dwNumEntries; Index++)
	{
		Port = ntohs((UdpTable->table[Index].dwLocalPort & 0xffff));
		TempAddr.S_un.S_addr = UdpTable->table[Index].dwLocalAddr;
		CStringA Address = "";
		if (!inet_ntop(AF_INET, (PVOID) & (TempAddr.S_un.S_addr), Address.GetBuffer(), NI_MAXHOST))
		{
			return;
		}

		// for alignment, it's best to put them into one string buffer
		CStringA LocalAddrAndPort = "";


		LocalAddrAndPort.Format("%s:%u", Address.GetBuffer(), Port);


		Message.Format("%*s %*s\n", -5, "UDP",
			-20, LocalAddrAndPort.GetBuffer()
		);
	}
	return;
}


DWORD
WINAPI
MyGetUdpTable(PMIB_UDPTABLE& UdpTable, BOOL Order)
{
	CStringA Message = "";
#ifdef _DEBUG
	Message.Format("[*] %s:%d: Obtaining UDP table entries...\n", __FUNCTION__, __LINE__);
#endif // _DEBUG

	DWORD Ret = 0;
	DWORD UdpTableSize = 0;

	Ret = GetUdpTable(UdpTable, &UdpTableSize, Order);
	// check for error
	if (NO_ERROR != Ret)
	{
		// check for overflow
		if (ERROR_INSUFFICIENT_BUFFER != Ret)
		{
			return  GetLastError();
		}
		else
		{
			// make some space for data now that we know the size needed
			//
			UdpTable = (PMIB_UDPTABLE)GlobalAlloc(GPTR, UdpTableSize);
		}
	}
	// make the call a second time with proper size
	Ret = GetUdpTable(UdpTable, &UdpTableSize, Order);
	if (NO_ERROR == Ret)
	{
#ifdef _DEBUG
		Message.Format("[+] %s:%d: Successfully obtain TCP table data\n", __FUNCTION__, __LINE__);
#endif // _DEBUG
		return Ret;
	}
	else
	{
		return  GetLastError();
	}
	// the table has a struct for dwNumEntries and MIB_UDPROW table[ANY_SIZE] for the entries
	// MIB_UDPROW has dwLocalAddr (IPv4) and dwLocalPort (the port)
	//
}


INT
WINAPI
StringToPhysicalAddress(PCHAR Ether, PCHAR OutEther)
{
	const char DASH = '-';
	register char c;
	register int val;

	if (strlen(Ether) != 17)
	{
		return ERROR_INVALID_PARAMETER;
	}
	if (Ether[2] != DASH || Ether[5] != DASH || Ether[8] != DASH ||
		Ether[11] != DASH || Ether[14] != DASH)
	{
		return ERROR_INVALID_PARAMETER;
	}

	if (!isxdigit(Ether[0]) || !isxdigit(Ether[1]) ||
		!isxdigit(Ether[3]) || !isxdigit(Ether[4]) ||
		!isxdigit(Ether[6]) || !isxdigit(Ether[7]) ||
		!isxdigit(Ether[9]) || !isxdigit(Ether[10]) ||
		!isxdigit(Ether[12]) || !isxdigit(Ether[13]) ||
		!isxdigit(Ether[15]) || !isxdigit(Ether[16]))
	{
		return ERROR_INVALID_PARAMETER;
	}

	DWORD Index = 0;
	for (; Index < 6; Index++)
	{
		val = 0;
		c = toupper(Ether[Index * 3]);
		c = c - (isdigit(c) ? '0' : ('A' - 10)); //offset adjustment
		val += c;
		val = (val << 4); // val * 16 
		c = toupper(Ether[Index * 3 + 1]);
		c = c - (isdigit(c) ? '0' : ('A' - 10)); // offset adjustement
		val += c;
		Ether[Index] = val;
	}

	return NO_ERROR;
}


BOOL
WINAPI
PhysicalAddressToString(BYTE MacAddress[], DWORD MacAddrLen, CHAR StringOut[])
{
	// param check
	if (NULL == MacAddress || 0 == MacAddrLen || NULL == StringOut)
	{
		return FALSE;
	}
	StringOut[0] = '\0';
	DWORD Index = 0;
	for (; Index < MacAddrLen; Index++)
	{
		if (MacAddrLen - 1 == Index)
		{
			sprintf_s(StringOut + (Index * 3), IPADDR_BUF_SIZE - (Index * 3), "%02X", ((INT)MacAddress[Index]) & 0xff);
		}
		else
		{
			sprintf_s(StringOut + (Index * 3), IPADDR_BUF_SIZE - (Index * 3), "%02X-", ((INT)MacAddress[Index]) & 0xff);
		}
	}
	return TRUE;
}


VOID
WINAPI
DoGetIpNetworkTable(void)
{
	CStringA Message = "";
	DWORD LastError = 0;
	PMIB_IPNETTABLE IpArpTable = nullptr;

	LastError = GetIpNetworkTable(IpArpTable, TRUE);
#ifdef _DEBUG
	Message.Format("[*] %s:%d GetIpNetworkTable returned %d\n", __FUNCTION__, __LINE__, LastError);
#endif // _DEBUG

	if (NO_ERROR == LastError)
	{
		// successful here
		//
		PrintIpNetworkTable(IpArpTable);

		//if (IpArpTable) free(IpArpTable);
		return;
	}
	else if (ERROR_NO_DATA == LastError)
	{
		printf("[*] No entries in arp table\n");
		if (IpArpTable) GlobalFree(IpArpTable);
		return;
	}
	else
	{
		if (IpArpTable) GlobalFree(IpArpTable);
		return;
	}
}


VOID
WINAPI
SetIpNetworkTableEntry(CStringA IpAddress, CStringA MacAddress, CStringA Interface)
{
	// TODO - complete this
	return;
}


VOID
WINAPI
DeleteIpNetworkTableEntry(CStringA IpAddress, CStringA Interface)
{
	// TODO - complete this
	return;
}


DWORD
WINAPI
GetIpNetworkTable(PMIB_IPNETTABLE& IpNetTable, BOOL Order)
{
	DWORD ActualSize = 0;
	DWORD Ret = NO_ERROR;

	Ret = GetIpNetTable(IpNetTable, &ActualSize, Order);
	if (NO_ERROR != Ret)
	{
		if (ERROR_INSUFFICIENT_BUFFER == Ret)
		{
			IpNetTable = (PMIB_IPNETTABLE)GlobalAlloc(GPTR, ActualSize);
			if (!IpNetTable)
			{
				return  GetLastError();
			}
		}
	}
	// try again
	Ret = GetIpNetTable(IpNetTable, &ActualSize, Order);
	if (NO_ERROR != Ret)
	{
		return  GetLastError();
	}

	return Ret;
}


DWORD
WINAPI
GetIpAddressTable(PMIB_IPADDRTABLE& IpAddrTable, BOOL Order)
{
	DWORD Ret = NO_ERROR;
	DWORD AcutalSize = 0;
	CStringA Message = "";

	// make the first call to get the buffer size
	//
	Ret = GetIpAddrTable(IpAddrTable, &AcutalSize, Order);
	if (NO_ERROR != Ret)
	{
		if (ERROR_INSUFFICIENT_BUFFER != Ret)
		{
			return  GetLastError();
		}
		else
		{
			IpAddrTable = (PMIB_IPADDRTABLE)GlobalAlloc(GPTR, AcutalSize);
			if (!IpAddrTable)
			{
				return  GetLastError();
			}
		}
	}
	// try again
	Ret = NO_ERROR;
	Ret = GetIpAddrTable(IpAddrTable, &AcutalSize, Order);
	if (NO_ERROR != Ret)
	{
		return  GetLastError();
	}

#ifdef _DEBUG
	Message.Format("[*] %s:%d returned %d\n", __FUNCTION__, __LINE__, Ret);
#endif // _DEBUG

	return Ret;
}


VOID
WINAPI
PrintIpNetworkTable(PMIB_IPNETTABLE IpNetTable)
{
	// param check
	if (nullptr == IpNetTable)
	{
		return;
	}

	DWORD	Index = 0,
		Ret = 0,
		CurrentIndex = 0;

	struct in_addr AddrTemp1;
	PMIB_IPADDRTABLE IpAddrTable = nullptr;


	CStringA Type = "";
	CStringA Message = "";
	CHAR PrintableMacAddress[PHYSADDR_BUF_SIZES] = { 0 };
	CHAR IpAddress[IPADDR_BUF_SIZE] = { 0 };


	Type.GetBuffer(IPTYPE_BUF_SIZE);
	//IpAddress.GetBuffer(IPADDR_BUF_SIZE);

	// grab the ip address table so it can be mapped by interface index to ip address
	//
	Ret = GetIpAddressTable(IpAddrTable, TRUE);
#ifdef _DEBUG
	Message.Format("[*] %s:%d GetIpAddressTable returned %d\n", __FUNCTION__, __LINE__, Ret);
#endif // _DEBUG

	if (NO_ERROR != Ret)
	{
		Message.Format("[*] %s:%d GetIpAddressTable returned 0x%x\n", __FUNCTION__, __LINE__, Ret);
		if (IpAddrTable) free(IpAddrTable);

		return;
	}
	// the ARP table should be sorted by interface index
	//
	CurrentIndex = IpNetTable->table[0].dwIndex;
	if (InterfaceIndexToInterfaceIp(IpAddrTable, CurrentIndex, IpAddress))
	{
		Message.Format("Interface: ");

		Message.Format("%s", IpAddress);

		Message.Format(" --- ");

		Message.Format("0x%X\n", CurrentIndex);
		Message.Format("  Internet Address      Physical Address      Type\n");
	}
	else
	{
#ifdef _DEBUG
		printf("[!] Could not do the conversion\n");
#endif // _DEBUG

		//return;
	}

	for (Index = 0; Index < IpNetTable->dwNumEntries; ++Index)
	{
		if (IpNetTable->table[Index].dwIndex != CurrentIndex)
		{
			CurrentIndex = IpNetTable->table[Index].dwIndex;

			if (InterfaceIndexToInterfaceIp(IpAddrTable, CurrentIndex, IpAddress))
			{
				Message.Format("Interface: ");

				Message.Format("%s", IpAddress);

				Message.Format(" --- ");

				Message.Format("0x%X\n", CurrentIndex);
				Message.Format("  Internet Address      Physical Address      Type\n");
			}
			else
			{
#ifdef _DEBUG
				Message.Format("[!] Could not convert Interface 0x%X to an IP\n", IpNetTable->table[Index].dwIndex);
#endif // _DEBUG
				continue;
			}
		}

		PhysicalAddressToString(
			IpNetTable->table[Index].bPhysAddr,		// MAC address
			IpNetTable->table[Index].dwPhysAddrLen,	// MAC address length
			PrintableMacAddress						// Buffer to hold address
		);

		AddrTemp1.S_un.S_addr = IpNetTable->table[Index].dwAddr;
		switch (IpNetTable->table[Index].dwType)
		{
		case MIB_IPNET_TYPE_OTHER:
			Type = "other";
			break;
		case MIB_IPNET_TYPE_INVALID:
			Type = "invalidated";
			break;
		case MIB_IPNET_TYPE_DYNAMIC:
			Type = "dynamic";
			break;
		case MIB_IPNET_TYPE_STATIC:
			Type = "static";
			break;
		default:
			Type = "invalid type";
		}
		CStringA Address = "";
		if (!inet_ntop(AF_INET, (PVOID) & (AddrTemp1.S_un.S_addr), Address.GetBuffer(), NI_MAXHOST))
		{
			return;
		}
		Message.Format("  %-16s      %-17s     %-11s\n", Address.GetBuffer(), PrintableMacAddress, Type.GetBuffer());

	} // end for loop
	if (IpAddrTable) free(IpAddrTable);
}


VOID
WINAPI
PrintIpAddressTable(PMIB_IPADDRTABLE IpAddrTable)
{
	struct in_addr AddrTemp1;
	struct in_addr AddrTemp2;
	CStringA Message = "";
	CStringA Address = "";
	CStringA Mask = "";
	Address.GetBuffer(IPADDR_BUF_SIZE);
	Mask.GetBuffer(IPADDR_BUF_SIZE);

	// param check
	//
	if (NULL == IpAddrTable)
	{
		return;
	}

	DWORD Index = 0;
	for (; Index < IpAddrTable->dwNumEntries; ++Index)
	{
		AddrTemp1.S_un.S_addr = IpAddrTable->table[Index].dwAddr;
		AddrTemp2.S_un.S_addr = IpAddrTable->table[Index].dwMask;

		CStringA TmpFix = "";
		CStringA TmpFix2 = "";
		if (!inet_ntop(AF_INET, (PVOID) & (AddrTemp1.S_un.S_addr), TmpFix.GetBuffer(), NI_MAXHOST))
		{
			return;
		}
		if (!inet_ntop(AF_INET, (PVOID) & (AddrTemp2.S_un.S_addr), TmpFix2.GetBuffer(), NI_MAXHOST))
		{
			return;
		}

		//Address = inet_ntoa(AddrTemp1);
		//Mask = inet_ntoa(AddrTemp2);
		Message.Format(
			"  %s\t 0x%X\t %s\t %s\t %u\n",
			//Address.GetBuffer(),
			TmpFix.GetBuffer(),
			IpAddrTable->table[Index].dwIndex,
			//Mask.GetBuffer(),
			TmpFix2.GetBuffer(),
			(IpAddrTable->table[Index].dwBCastAddr ? "255.255.255.255" : "0.0.0.0"),
			IpAddrTable->table[Index].dwReasmSize
		);
	}
}


BOOL
WINAPI
InterfaceIndexToInterfaceIp(PMIB_IPADDRTABLE IpAddrTable, DWORD InterfaceIndex, CHAR IpAddress[])
{
	CStringA Message = "";
#ifdef _DEBUG	 
	Message.Format("[*] %s:%d\n", __FUNCTION__, __LINE__);
#endif // _DEBUG	

	struct in_addr Temp = { 0 };
	PCHAR IpAddy = nullptr;
	//PCHAR IpAddy = inet_ntoa(Temp);

	if (NULL == IpAddrTable || NULL == IpAddress)
	{
		return FALSE;
	}
	DWORD Idx = 0;
	IpAddress[0] = '\0';

	for (; Idx < IpAddrTable->dwNumEntries; Idx++)
	{
		if (InterfaceIndex == IpAddrTable->table[Idx].dwIndex)
		{
			Temp.S_un.S_addr = IpAddrTable->table[Idx].dwAddr;
			CStringA TmpFix = "";
			if (!inet_ntop(AF_INET, (PVOID) & (Temp.S_un.S_addr), IpAddy, NI_MAXHOST))
			{
				return FALSE;
			}
			//IpAddy = inet_ntoa(Temp);
			if (IpAddy)
			{
				strcpy_s(IpAddress, IPADDR_BUF_SIZE, IpAddy);
				return TRUE;
			}
			else
			{
				return FALSE;
			}
		}
	}
	return FALSE;
}