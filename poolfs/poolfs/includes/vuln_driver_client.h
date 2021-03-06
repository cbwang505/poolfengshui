#ifndef VULN_DRIVER_CLIENT_H
#define VULN_DRIVER_CLIENT_H

#include "Ioctl.h"
#include <stdbool.h>

#define DRIVER_PATH "\\\\.\\vulnerable_driver"

typedef enum _SYSTEM_INFORMATION_CLASS2 {
	SystemBasicInformation2 = 0,
	SystemPerformanceInformation2 = 2,
	SystemTimeOfDayInformation2 = 3,
	SystemProcessInformation2 = 5,
	SystemProcessorPerformanceInformation2 = 8,
	SystemModuleInformation2 = 11,
	SystemObjectInformation2 = 17,
	SystemInterruptInformation2 = 23,
	SystemExceptionInformation2 = 33,
	SystemRegistryQuotaInformation2 = 37,
	SystemLookasideInformation2 = 45,
	SystemExtendedHandleInformation2 = 64
} SYSTEM_INFORMATION_CLASS2;

// typedef struct _OBJECT_ATTRIBUTES {
// 	DWORD64           Length;
// 	HANDLE          RootDirectory;
// 	PUNICODE_STRING ObjectName;
// 	DWORD64           Attributes;
// 	PVOID           SecurityDescriptor;
// 	PVOID           SecurityQualityOfService;
// }  OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX
{
	PVOID Object;
	ULONG_PTR UniqueProcessId;
	HANDLE HandleValue;
	ULONG GrantedAccess;
	USHORT CreatorBackTraceIndex;
	USHORT ObjectTypeIndex;
	ULONG HandleAttributes;
	ULONG Reserved;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

typedef struct _SYSTEM_EXTENDED_HANDLE_INFORMATION
{
	ULONG_PTR NumberOfHandles;
	ULONG_PTR Reserved;
	SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
} SYSTEM_EXTENDED_HANDLE_INFORMATION, *PSYSTEM_EXTENDED_HANDLE_INFORMATION;

typedef NTSTATUS(__stdcall *NtQuerySystemInformation_t)(IN SYSTEM_INFORMATION_CLASS2 SystemInformatioNClass, IN OUT PVOID SystemInformation, IN ULONG SystemInformationLength, OUT PULONG ReturnLength OPTIONAL);

DWORD64 getObjectAddressWithHandle(HANDLE hObjectHandle, UINT nMaxSearchTry);

void open_driver(void);

uintptr_t alloc_ioctl(size_t alloc_size, unsigned long pooltype, int tag);

int overflow_ioctl(size_t buffer_size, char * data);

void free_ioctl();

int spray(size_t alloc_size, size_t nb_allocs, unsigned long pooltype, unsigned long tag, bool log);

int unspray(int spray_index);

int arbitrary_write(uintptr_t where, char *what, size_t size);

int arbitrary_read(uintptr_t where, char *what, size_t size);

int bp(void);

#endif
