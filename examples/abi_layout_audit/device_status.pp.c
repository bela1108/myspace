typedef unsigned short status_flags_t;

struct device_status_block {
    unsigned int magic;
    unsigned int revision;
    status_flags_t flags;
    unsigned long watchdog;
    unsigned long long sequence;
    unsigned char payload[8];
    unsigned int internal_token;
    unsigned int reserved;
};

struct packet_control {
    unsigned int mode;
    unsigned int code : 4;
    unsigned int code_ext : 12;
    unsigned int lane;
};
