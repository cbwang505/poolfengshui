#if TRUE
#define LOG_DEBUG(fmt, ...) printf("[+] " fmt "\n", __VA_ARGS__)
#else
#define LOG_DEBUG(fmt, ...) do {} while(0)
#endif
