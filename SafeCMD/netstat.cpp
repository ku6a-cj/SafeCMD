#include"netstat.h"
#include <iostream>
#include <stdio.h>
#include <windows.h>



int
netstat() {

	return EXIT_SUCCESS;
}

void
netstat_help() {
	printf("Displays protocol statistics and current TCP/IP network connections.\n\n");
	printf("NETSTAT [-a] [-b] [-e] [-f] [-n] [-o] [-p proto] [-r] [-s] [-t] [-x] [-y] [interval]\n\n");

	printf("\t-a            Displays all connections and listening ports.\n");
	printf("\t-b            Displays the executable involved in creating each connection or\n");
	printf("\t				listening port. In some cases well-known executables host\n");
	printf("\t				multiple independent components, and in these cases the\n");
	printf("\t				sequence of components involved in creating the connection\n");
	printf("\t				or listening port is displayed. In this case the executable\n");
	printf("\t				name is in [] at the bottom, on top is the component it called,\n");
	printf("\t				and so forth until TCP/IP was reached. Note that this option\n");
	printf("\t				can be time-consuming and will fail unless you have sufficient\n");
	printf("\t				permissions.\n");
	printf("\t-e            Displays Ethernet statistics. This may be combined with the -s option.\n");
	printf("\t-f            Displays Fully Qualified Domain Names (FQDN) for foreign addresses.\n");
	printf("\t-n            Displays addresses and port numbers in numerical form.\n");
	printf("\t-o            Displays the owning process ID associated with each connection.\n");
	printf("\t-p proto      Shows connections for the protocol specified by proto; proto may be any of : TCP, UDP, TCPv6, or UDPv6.If used with the - s option to display per - protocol statistics, proto may be any of : IP, IPv6, ICMP, ICMPv6, TCP, TCPv6, UDP, or UDPv6.\n");
	printf("\t-q            Displays all connections, listening ports, and bound nonlistening TCP ports.Bound nonlistening ports may or may not be associated with an active connection.\n");
	printf("\t-r            Displays the routing table.\n");
	printf("\t-s            Displays per-protocol statistics.  By default, statistics are shown for IP, IPv6, ICMP, ICMPv6, TCP, TCPv6, UDP, and UDPv6; the - p option may be used to specify a subset of the default.\n");
	printf("\t-t            Displays the current connection offload state.\n");
	printf("\t-x            Displays NetworkDirect connections, listeners, and shared endpoints.\n");
	printf("\t -y            Displays the TCP connection template for all connections. Cannot be combined with the other options.\n");
	printf("\t interval      Redisplays selected statistics, pausing interval seconds between each display.Press CTRL + C to stop redisplaying statistics.If omitted, netstat will print the current configuration information once.\n");
}

void
netstat_a() {

	// determine how much memory we need to allocate
	DWORD cbNeeded = 0, cReturned = 0;
	if (!EnumPorts(NULL, 2, NULL, 0, &cbNeeded, &cReturned))
	{
		if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
		{
			// error
		}
	}


	PORT_INFO_2* pPrintInfo = (PORT_INFO_2*)malloc(cbNeeded);
	if (pPrintInfo == NULL)
	{
		// not enough memory
	}

	if (!EnumPorts(NULL, 2, (LPBYTE)pPrintInfo, cbNeeded,
		&cbNeeded, &cReturned))
	{
		// error
	}

	for (DWORD ii = 0; ii<cReturned; ii++)
	{
		printf("%ls   %ls    %ls    %d\n",pPrintInfo[ii].pPortName, pPrintInfo[ii].pMonitorName, pPrintInfo[ii].pDescription, pPrintInfo[ii].fPortType);
	}

	free(pPrintInfo);

}