#define SEC(NAME) __attribute__((section(NAME), used))

#define BPF_MAP_TYPE_RINGBUF 27

struct bpf_map_def {
    unsigned int type;
    unsigned int key_size;
    unsigned int value_size;
    unsigned int max_entries;
    unsigned int map_flags;
};

struct bpf_map_def SEC("maps") events_map = {
    .type = BPF_MAP_TYPE_RINGBUF,
    .max_entries = 256 * 1024,
};

static void* (*bpf_ringbuf_reserve)(void *ringbuf, unsigned long long size, unsigned long long flags) = (void* ) 131;
static void (*bpf_ringbuf_submit)(void *data, unsigned long long flags) = (void* ) 132;
static unsigned long long (*bpf_get_current_pid_tgid)(void) = (void* ) 14;
static long (*bpf_get_current_comm)(void *buf, unsigned int size_of_buf) = (void* ) 16;

struct file_event_t {
    unsigned int pid;
    char process_name[256];
    char file_path[512];
    unsigned int access_flags;
};

SEC("sys_enter_NtCreateFile")
int handle_file_open(void* ctx) {
    struct file_event_t* event;

    event = bpf_ringbuf_reserve(&events_map, sizeof(struct file_event_t), 0);
    if (!event) {
        return 0;
    }

    unsigned long long pid_tgid = bpf_get_current_pid_tgid();
    event->pid = (unsigned int)(pid_tgid >> 32);

    bpf_get_current_comm(&event->process_name, sizeof(event->process_name));

    event->access_flags = 0;

    bpf_ringbuf_submit(event, 0);
    return 0;
}