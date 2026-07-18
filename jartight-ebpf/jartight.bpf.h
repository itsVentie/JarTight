#pragma once

struct file_event_t {
    unsigned int pid;
    char process_name[256];
    char file_path[512];
    unsigned int access_flags;
};