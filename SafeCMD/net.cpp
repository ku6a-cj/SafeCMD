#include"net.h"
#include <iostream>
#include <stdio.h>
#include<Windows.h>
#include<lmaccess.h>
#include<atlstr.h>
#include <winnetwk.h>


int
net() {

	return EXIT_SUCCESS;
}

void 
net_help() {
printf("The syntax of this command is:\n");
printf("\tNET\n");
printf("\t[ACCOUNTS | COMPUTER | CONFIG | CONTINUE | FILE | GROUP | HELP |\n");
printf("\t    HELPMSG | LOCALGROUP | PAUSE | SESSION | SHARE | START |\n");
printf("\t    STATISTICS | STOP | TIME | USE | USER | VIEW]\n");
}

void
net_user() {
    DWORD len;
    UINT error = 8;
    wchar_t userbuf[30];
    len = 255;
    GetUserNameW(userbuf, &len);
    printf("User name: %ls\n", userbuf);

    DWORD len2=255;
    wchar_t pcbuff[30];
    GetComputerNameEx(ComputerNameNetBIOS,pcbuff,&len2);
    printf("Computer name: %ls\n", pcbuff);

    USER_INFO_0* buffer;
    DWORD entries;
    DWORD total_endtries;
    DWORD resume_handle =0;

    NET_API_STATUS a = NetUserEnum(
        NULL,
        0,
        0,
        (BYTE**)&buffer,
        4096,
        &entries,
        &total_endtries,
        &resume_handle
    );
    std::cout << "Account list:" << "\n";
    for (unsigned i = 0; i < entries; i++)
    {
        std::string username = std::string(CW2A(buffer[i].usri0_name));
        std::cout << username <<"\n";
    }

};

void
net_localgroup() {
    LPLOCALGROUP_USERS_INFO_0 pBuf = NULL;
    DWORD dwLevel = 0;
    DWORD dwFlags = LG_INCLUDE_INDIRECT;
    DWORD dwPrefMaxLen = MAX_PREFERRED_LENGTH;
    DWORD dwEntriesRead = 0;
    DWORD dwTotalEntries = 0;
    NET_API_STATUS nStatus;
    DWORD len;
    UINT error = 8;
    wchar_t userbuf[30];
    len = 255;
    GetUserNameW(userbuf, &len);

    nStatus = NetLocalGroupEnum(
        NULL, //local pc
        dwLevel,
        (LPBYTE*)&pBuf,
        dwPrefMaxLen,
        &dwEntriesRead,
        &dwTotalEntries,
        NULL);

    for (unsigned i = 0; i < dwTotalEntries; i++)
    {
        std::string group = std::string(CW2A(pBuf[i].lgrui0_name));
        std::cout <<"*" << group << "\n";
    }

};

void
net_share() {
    
    /*to do fix it 
    HANDLE lphEnum;
    
    DWORD WNOEA =  WNetOpenEnumA(
        RESOURCE_GLOBALNET,
        RESOURCETYPE_ANY,
        0,
        NULL,
        &lphEnum
    );
   
    DWORD lpcCount = 1;
    wchar_t  lpBuffer[30];
    DWORD len=255;
    NET_API_STATUS NET_API_FUNCTION  SharedResoutrces = WNetEnumResourceA(
        lphEnum,
        &lpcCount,
        (LPBYTE*)&lpBuffer,
        &len );

    for (unsigned i = 0; i < len; i++)
    {
        std::cout << lpBuffer[i] << "\n";
    }
    */

};


