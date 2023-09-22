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
#include<string.h>
#include"arp.h"
#include"sysinfo.h"
#include <iostream>
#include "net.h"
#include "netstat.h"

int
main() {
	
	while(1){
	//printf("Commands posible to use: \n1)ipconfig \n2)netstat \n3)net \n4)arp \n5)systeminfo\n");
	printf("Write command name: ");
	std::string command = "command";
	std::getline(std::cin, command);
	//std::cout << "command = " << command<<std::endl;
	printf("\n");
	if (command == "ipconfig")
	{
		ipConfig();
	}else if (command == "arp -d") {
		printf("function not yet implementet\n");
	}
	else if (command == "arp -h") {
		Usage();
	}
	else if (command == "arp -a") {
		DoGetIpNetworkTable();
	}
	else if (command == "systeminfo") {
		sysinfo();
	}
	else if (command == "net -h") {
		net_help();
	}
	else if (command == "netstat -h") {
		netstat_help();
	}
	else if (command == "netstat -a") {
		netstat_a();
	}
	else if (command == "net USER") {
		net_user();
	}
	else if (command == "exit") {
		break;
	}
	else if (command == "net LOCALGROUP") {
		net_localgroup();
	}
	else if (command == "net SHARE") {
		net_share();
	}
	else {
		printf("bad parameter\n");
	}
	}

	return 0;

}