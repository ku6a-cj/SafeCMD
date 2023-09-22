#pragma once
#pragma once

#include <WinSock2.h>
#include <WS2tcpip.h>
#include <iphlpapi.h>
#include <time.h>
#include <iostream>
#include <Windows.h>
#include <atlstr.h>

#ifndef WIN_SUCCESS
#define WIN_SUCCESS(x) ((x) == NO_ERROR)
#endif // !WIN_SUCCESS

/// <summary>
/// Determines what stats to obtain, all or per protocol
/// </summary>
/// <param name="Protocol"The protocol to obtain stats for</param>
/// <returns>VOID</returns>
VOID
WINAPI
GetStats(CStringA Protocol);

/// <summary>
/// Obtains the connection table for a given protocol: tcp/udp
/// </summary>
/// <param name="Protocol">The protocol for which to obtain the connection table for</param>
/// <returns>VOID</returns>
VOID
WINAPI
GetConnectionTable(CStringA Protocol);

/// <summary>
/// Obtains IP stats
/// </summary>
/// <param name="IpStats">Pointer to the MIB_IPSTATS struct</param>
/// <param name="Family">The protocol family for which to retrieve statistics: AF_INET, AF_INET6</param>
/// <returnsNO_ERROR on success></returns>
DWORD
WINAPI
MyGetIpStats(PMIB_IPSTATS& IpStats, ULONG Family);

/// <summary>
/// Obtains the ICMP stats
/// </summary>
/// <param name="IcmpStats">Pointer to the MIB_ICMP struct</param>
/// <param name="Family">The protocol family for which to retrieve statistics: AF_INET, AF_INET6</param>
/// <returns>NO_ERROR on success</returns>
DWORD
WINAPI
MyGetIcmpStats(PMIB_ICMP& IcmpStats, ULONG Family);


/// <summary>
/// Obtains the TCP stats
/// </summary>
/// <param name="TcpStats">Pointer to the MIB_TCPSTATS struct</param>
/// <param name="Family">The protocol family for which to retrieve statistics: AF_INET, AF_INET6</param>
/// <returns>DWORD</returns>
DWORD
WINAPI
MyGetTcpStats(PMIB_TCPSTATS& TcpStats, ULONG Family);

/// <summary>
/// Obtains the UDP stats
/// </summary>
/// <param name="UdpStats">Pointer to the MIB_UDPSTATS struct</param>
/// <param name="Family">The protocol family for which to retrieve statistics: AF_INET, AF_INET6</param>
/// <returns>NO_ERROR on success</returns>
DWORD
WINAPI
MyGetUdpStats(PMIB_UDPSTATS& UdpStats, ULONG Family);

/// <summary>
/// Dumps the UDP stats
/// </summary>
/// <param name="UdpStats">Pointer to the MIB_UDPSTATS struct</param>
/// <returns>VOID</returns>
VOID
WINAPI
PrintUdpStats(PMIB_UDPSTATS UdpStats, ULONG Family);

/// <summary>
/// Dumps the ICMP v4 stats
/// </summary>
/// <param name="IcmpStats">Pointer to MIBICMPINFO struct</param>
/// <parma name="Family">The Family: AF_INET, AF_INET6</param>
/// <returns>VOID</returns>
VOID
WINAPI
PrintIcmpStats(MIBICMPINFO* IcmpStats, ULONG Family);

/// <summary>
/// Obtains extended ICMP stats
/// </summary>
/// <param name="IcmpStats">Pointer to the MIB_ICMP_EX struct</param>
/// <parma name="Family">The Family: AF_INET, AF_INET6</param>
/// <returns>NO_ERROR on success</returns>
DWORD
WINAPI
MyGetIcmpStatsEx(PMIB_ICMP_EX& IcmpStats, ULONG Family);

/// <summary>
/// Dumps the extended ICMP stats
/// </summary>
/// <param name="IcmpEx">Pointer to the MIB_ICMP_EX struct</param>
/// <parma name="Family">The Family: AF_INET, AF_INET6</param>
/// <returns>VOID</returns>
VOID
WINAPI
PrintIcmpStatsEx(PMIB_ICMP_EX IcmpEx, ULONG Family);

/// <summary>
/// Dumps the IP stats
/// </summary>
/// <param name="IpStats">Pointer to the MIB_IPSTATS struct</param>
/// <parma name="Family">The Family: AF_INET, AF_INET6</param>
/// <returns></returns>
VOID
WINAPI
PrintIpStats(PMIB_IPSTATS IpStats, ULONG Family);

/// <summary>
/// Dumps the TCP stats
/// </summary>
/// <param name="TcpStats">Pointer to the MIB_TCPSTATS struct</param>
/// <returns>VOID</returns>
VOID
WINAPI
PrintTcpStats(PMIB_TCPSTATS TcpStats, ULONG Family);

/// <summary>
/// Dumps the entries of the TCP table
/// </summary>
/// <param name="TcpTable">Pointer to the MIB_TCPTABLE struct</param>
/// <returns>VOID</returns>
VOID
WINAPI
PrintTcpTable(PMIB_TCPTABLE TcpTable);

/// <summary>
/// Dumps the entries of the UDP table
/// </summary>
/// <param name="UdpTable">Pointer to the MIB_UDPTABLE struct</param>
/// <returns>VOID</returns>
VOID
WINAPI
PrintUdpTable(PMIB_UDPTABLE UdpTable);

/// <summary>
/// Obtains the UDP IPv4 table entries
/// </summary>
/// <param name="UdpTable">Pointer to MIB_UDPTABLE struct</param>
/// <param name="Order">Boolean value specifying if the table should be sorted</param>
/// <returns>NO_ERROR on success</returns>
DWORD
WINAPI
MyGetUdpTable(PMIB_UDPTABLE& UdpTable, BOOL Order);

// create the function for the UDP6 table


/// <summary>
/// Obtains the TCP IPv4 table entries
/// </summary>
/// <param name="TcpTable">Pointer to the MIB_TCPTABLE struct</param>
/// <param name="Order">Boolean value specifying if the table should be sorted</param>
/// <returns>NO_ERROR on success</returns>
DWORD
WINAPI
MyGetTcpTable(PMIB_TCPTABLE& TcpTable, BOOL Order);

// create the function for the TCP6 table


// 

/// <summary>
/// Converts a string MAC address to its proper MAC address form
/// </summary>
/// <param name="Ether">The MAC address as a string</param>
/// <param name="OutEther">The pointer to store the converted MAC address</param>
/// <returns>INT</returns>
INT
WINAPI
StringToPhysicalAddress(PCHAR Ether, PCHAR OutEther);

/// <summary>
/// Converts MAC address to a usable string
/// </summary>
/// <param name="MacAddress">The MAC address as a BYTE array</param>
/// <param name="MacAddrLen">The length of the MAC address</param>
/// <param name="StringOut">The pointer to receive the converted value</param>
/// <returns>TRUE on success, or non-zero</returns>
BOOL
WINAPI
PhysicalAddressToString(BYTE MacAddress[], DWORD MacAddrLen, CHAR StringOut[]);

/// <summary>
/// Grabs the IP network table
/// </summary>
/// <returns>Nothing</returns>
VOID
WINAPI
DoGetIpNetworkTable(void);

/// <summary>
/// Adds an entry in the table
/// </summary>
/// <param name="IpAddress">The IP address to add</param>
/// <param name="MacAddress">The MAC address to add</param>
/// <param name="Interface">The interface to add it for</param>
/// <returns>Nothing</returns>
VOID
WINAPI
SetIpNetworkTableEntry(CStringA IpAddress, CStringA MacAddress, CStringA Interface = CStringA());

/// <summary>
/// Removes an entry in the table
/// </summary>
/// <param name="IpAddress">IP address to remove</param>
/// <param name="Interface">The Interface tied to it</param>
/// <returns>Nothing</returns>
VOID
WINAPI
DeleteIpNetworkTableEntry(CStringA IpAddress, CStringA Interface = CStringA());

/// <summary>
/// Obtains the IP network table
/// </summary>
/// <param name="IpNetTable">Pointer to MIB_IPNETTABLE</param>
/// <param name="Order">The order of the IP Net Table</param>
/// <returns>On NO_ERROR, returns pointer to IP Net Table</returns>
DWORD
WINAPI
GetIpNetworkTable(PMIB_IPNETTABLE& IpNetTable, BOOL Order = TRUE);

/// <summary>
/// Grabs the IP address table
/// </summary>
/// <param name="IpAddrTable">Pointer to MIB_IPADDRTABLE struct</param>
/// <param name="Order">Should the table be ordered</param>
/// <returns>DWORD</returns>
DWORD
WINAPI
GetIpAddressTable(PMIB_IPADDRTABLE& IpAddrTable, BOOL Order = TRUE);

/// <summary>
/// Dumps the IP Network Table
/// </summary>
/// <param name="IpNetTable">Pointer to MIB_IPNETTABLE struct</param>
/// <returns>VOID</returns>
VOID
WINAPI
PrintIpNetworkTable(PMIB_IPNETTABLE IpNetTable);

/// <summary>
/// Dumps the IP Address Table
/// </summary>
/// <param name="IpAddrTable">Pointer to the MIB_IPADDRTABLE struct</param>
/// <returns>VOID</returns>
VOID
WINAPI
PrintIpAddressTable(PMIB_IPADDRTABLE IpAddrTable);

/// <summary>
/// Converts the Index of the Interface to an IP address
/// </summary>
/// <param name="IpAddrTable">Pointer to the MIB_IPADDRTABLE struct</param>
/// <param name="Index">The interface index</param>
/// <param name="IpAddress">The IP address</param>
/// <returns></returns>
BOOL
WINAPI
InterfaceIndexToInterfaceIp(PMIB_IPADDRTABLE IpAddrTable, DWORD Index, CHAR IpAddress[]);

VOID
Usage();