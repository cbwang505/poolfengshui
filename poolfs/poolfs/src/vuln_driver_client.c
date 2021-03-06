#include <windows.h>
#include <ntstatus.h>
#include <stdio.h>
#include <stdbool.h>
#include <winternl.h>
#include "Ioctl.h"
#include "vuln_driver_client.h"


HANDLE driver_handle = 0;

NtQuerySystemInformation_t g_pNtQuerySystemInformation = NULL;

DWORD64 getObjectAddressWithHandle(HANDLE hObjectHandle, UINT nMaxSearchTry)
{
	NTSTATUS st;
	PSYSTEM_EXTENDED_HANDLE_INFORMATION handleInfo;
	ULONG handleInfoLen = 0x10000;
	DWORD pid = GetCurrentProcessId();

    if (!g_pNtQuerySystemInformation)
    {
        HMODULE h = LoadLibraryA("ntdll.dll");
        g_pNtQuerySystemInformation = (NtQuerySystemInformation_t)GetProcAddress(h, "NtQuerySystemInformation");

        if (!g_pNtQuerySystemInformation)
        {
            printf("[-]Failed to get the address of NtAllocateReserveObject");
            return 0;
        }
    }

	DWORD64 ret = 0;

	for (UINT j = 0; j < nMaxSearchTry; j++)
	{

		handleInfoLen = 0x10000;
		handleInfo = (PSYSTEM_EXTENDED_HANDLE_INFORMATION)malloc(handleInfoLen);
		while ((st = g_pNtQuerySystemInformation(
			SystemExtendedHandleInformation2,
			handleInfo,
			handleInfoLen,
			NULL
		)) == STATUS_INFO_LENGTH_MISMATCH)
			handleInfo = (PSYSTEM_EXTENDED_HANDLE_INFORMATION)realloc(handleInfo, handleInfoLen *= 2);


		// NtQuerySystemInformation stopped giving us STATUS_INFO_LENGTH_MISMATCH.
		if (!NT_SUCCESS(st)) {
			printf("[-]NtQuerySystemInformation failed !\n");
			return 0;
		}
		for (UINT i = 0; i < handleInfo->NumberOfHandles; i++)
		{
			if (handleInfo->Handles[i].HandleValue == hObjectHandle && pid == handleInfo->Handles[i].UniqueProcessId)
			{
				ret = ((DWORD64)(handleInfo->Handles[i].Object));
				free(handleInfo);
				return ret;
			}
		}
		free(handleInfo);
	}
	return 0;
}

void open_driver(void)
{
    printf("[+] Opening driver "DRIVER_PATH" ...\n");
    driver_handle = CreateFileA(DRIVER_PATH, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_WRITE | FILE_SHARE_READ, NULL, OPEN_ALWAYS, 0, NULL);
    if(driver_handle == INVALID_HANDLE_VALUE)
    {
        printf("Could not open %s file, error %d\n", DRIVER_PATH, GetLastError());
        exit(0);
    }
}

uintptr_t alloc_ioctl(size_t alloc_size, unsigned long pooltype, int tag)
{
    DWORD ret = 0;
    ioctl_alloc_t * ioctl_input = malloc(sizeof(ioctl_alloc_t));
    uintptr_t res = 0;
    DWORD nb_bytes = 0;

    ioctl_input->alloc_size = alloc_size;
    ioctl_input->pooltype = pooltype;
    ioctl_input->tag = tag;

    printf("[+] Allocating buffer with size 0x%X \n", alloc_size);

    ret = DeviceIoControl(driver_handle, IOCTL_ALLOC_BUFFER, ioctl_input, sizeof(ioctl_alloc_t), (LPVOID)&res, sizeof(res), &nb_bytes, 0);
    return res;
}

int overflow_ioctl(size_t buffer_size, char * data)
{
    ioctl_copy_t * ioctl_input = malloc(sizeof(ioctl_copy_t));
    int res;
    DWORD nb_bytes;

    ioctl_input->buffer_size = buffer_size;
    ioctl_input->data = data;

    DeviceIoControl(driver_handle, IOCTL_COPY, ioctl_input, sizeof(ioctl_copy_t), (LPVOID)&res, sizeof(res), &nb_bytes, 0);
    return res;
}

void free_ioctl()
{
    int res;
    DWORD nb_bytes;
    DeviceIoControl(driver_handle, IOCTL_FREE_BUFFER, NULL, 0, (LPVOID)&res, sizeof(res), &nb_bytes, 0);
}

int spray(size_t alloc_size, size_t nb_allocs, unsigned long pooltype, unsigned long tag, bool log)
{
    ioctl_spray_t * ioctl_input = malloc(sizeof(ioctl_spray_t));
    void * res = malloc(sizeof(size_t) + nb_allocs * sizeof(uintptr_t));
    uintptr_t *allocs = (uintptr_t*)((uintptr_t)res + sizeof(size_t));
    DWORD nb_bytes;

    ioctl_input->alloc_size = alloc_size;
    ioctl_input->nb_allocs = nb_allocs;
    ioctl_input->pooltype = pooltype;
    ioctl_input->tag = tag;

    printf("[+] Spraying 0x%X chunks of size  0x%X \n", nb_allocs, alloc_size);

    DeviceIoControl(driver_handle, IOCTL_SPRAY, ioctl_input, sizeof(ioctl_spray_t), res, sizeof(size_t) + (sizeof(uintptr_t) * nb_allocs), &nb_bytes, 0);

    printf("[+] Spray index %d\n", *(size_t *)res);
    if (log) {
        for (int i = 0; i < nb_allocs; i++) {
            printf("[+] Spray allocated at %p\n", allocs[i]);
        }
    }

    free(ioctl_input);
    return *(size_t *)res;
}

int unspray(int spray_index)
{
    size_t input;
    int res;
    DWORD nb_bytes;

    printf("[+] Unspraying %d...\n", spray_index);

    input = spray_index;

    DeviceIoControl(driver_handle, IOCTL_UNSPRAY, &input, sizeof(size_t), (LPVOID)&res, sizeof(res), &nb_bytes, 0);
    return res;
}

int arbitrary_read(uintptr_t where, char *what, size_t size)
{
    ioctl_arb_primitive_t * input = malloc(sizeof(ioctl_arb_primitive_t));
    DWORD ret = 0;
    DWORD nb_bytes;

    input->where = where;
    input->size = size;
    ret = DeviceIoControl(driver_handle, IOCTL_READ, input, sizeof(ioctl_arb_primitive_t), (LPVOID)what, size, &nb_bytes, 0);
    return ret;
}

int arbitrary_write(uintptr_t where, char *what, size_t size)
{
    ioctl_arb_primitive_t * input = malloc(sizeof(ioctl_arb_primitive_t) + size);
    int res;
    DWORD ret = 0;

    input->where = where;
    input->size = size;
    memcpy(input->what, what, size);
    DWORD nb_bytes;

    ret = DeviceIoControl(driver_handle, IOCTL_WRITE, input, sizeof(ioctl_arb_primitive_t) + size, (LPVOID)&res, sizeof(res), &nb_bytes, 0);
    return ret;
}

int bp(void)
{
    DWORD ret = 0;
    ret = DeviceIoControl(driver_handle, IOCTL_BP, NULL, 0, NULL, 0, NULL, 0);
    return ret;
}

#define DRIVER_PATH "\\\\.\\vulnerable_driver"
