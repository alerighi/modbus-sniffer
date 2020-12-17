/*
 * A sniffer for the Modbus protocol
 * (c) 2020 Alessandro Righi - released under the MIT license
 */

#define _DEFAULT_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <signal.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#define DIE(err) do { perror(err); exit(EXIT_FAILURE); } while (0)

/*
 * maximum Modbus packet size. By the standard is 300 bytes
 */
#define MODBUS_MAX_PACKET_SIZE 300

/* CLI params */
char *serial_port = "/dev/ttyAMA0";
char *output_dir = "/tmp/sniffer";
char parity = 'N';
int bits = 8;
int speed = 9600;
int stop_bits = 1;
int bytes_time_interval_us = 1500;
int max_packet_per_capture = 10000;

struct option long_options[] = {
    { "serial-port", required_argument, NULL, 'p' },
    { "output-dir",  required_argument, NULL, 'o' },
    { "speed",       required_argument, NULL, 's' },
    { "parity",      required_argument, NULL, 'P' },
    { "bits",        required_argument, NULL, 'b' },
    { "stop-bits",   required_argument, NULL, 'S' },
    { "interval",    required_argument, NULL, 't' },
    { "max-packets", required_argument, NULL, 'm' },
    { "help",        no_argument,       NULL, 'h' },
    { NULL,          0,                 NULL,  0  },
};

volatile int rotate_log = 1;

struct pcap_global_header {
    uint32_t magic_number;  /* magic number */
    uint16_t version_major; /* major version number */
    uint16_t version_minor; /* minor version number */
    int32_t  thiszone;      /* GMT to local correction */
    uint32_t sigfigs;       /* accuracy of timestamps */
    uint32_t snaplen;       /* max length of captured packets, in octets */
    uint32_t network;       /* data link type */
};

struct pcap_packet_header {
    uint32_t ts_sec;   /* timestamp seconds */
    uint32_t ts_usec;  /* timestamp microseconds */
    uint32_t incl_len; /* number of octets of packet saved in file */
    uint32_t orig_len; /* actual length of packet */
};

uint16_t crc16_table[] = {
    0x0000, 0xC0C1, 0xC181, 0x0140, 0xC301, 0x03C0, 0x0280, 0xC241,
    0xC601, 0x06C0, 0x0780, 0xC741, 0x0500, 0xC5C1, 0xC481, 0x0440,
    0xCC01, 0x0CC0, 0x0D80, 0xCD41, 0x0F00, 0xCFC1, 0xCE81, 0x0E40,
    0x0A00, 0xCAC1, 0xCB81, 0x0B40, 0xC901, 0x09C0, 0x0880, 0xC841,
    0xD801, 0x18C0, 0x1980, 0xD941, 0x1B00, 0xDBC1, 0xDA81, 0x1A40,
    0x1E00, 0xDEC1, 0xDF81, 0x1F40, 0xDD01, 0x1DC0, 0x1C80, 0xDC41,
    0x1400, 0xD4C1, 0xD581, 0x1540, 0xD701, 0x17C0, 0x1680, 0xD641,
    0xD201, 0x12C0, 0x1380, 0xD341, 0x1100, 0xD1C1, 0xD081, 0x1040,
    0xF001, 0x30C0, 0x3180, 0xF141, 0x3300, 0xF3C1, 0xF281, 0x3240,
    0x3600, 0xF6C1, 0xF781, 0x3740, 0xF501, 0x35C0, 0x3480, 0xF441,
    0x3C00, 0xFCC1, 0xFD81, 0x3D40, 0xFF01, 0x3FC0, 0x3E80, 0xFE41,
    0xFA01, 0x3AC0, 0x3B80, 0xFB41, 0x3900, 0xF9C1, 0xF881, 0x3840,
    0x2800, 0xE8C1, 0xE981, 0x2940, 0xEB01, 0x2BC0, 0x2A80, 0xEA41,
    0xEE01, 0x2EC0, 0x2F80, 0xEF41, 0x2D00, 0xEDC1, 0xEC81, 0x2C40,
    0xE401, 0x24C0, 0x2580, 0xE541, 0x2700, 0xE7C1, 0xE681, 0x2640,
    0x2200, 0xE2C1, 0xE381, 0x2340, 0xE101, 0x21C0, 0x2080, 0xE041,
    0xA001, 0x60C0, 0x6180, 0xA141, 0x6300, 0xA3C1, 0xA281, 0x6240,
    0x6600, 0xA6C1, 0xA781, 0x6740, 0xA501, 0x65C0, 0x6480, 0xA441,
    0x6C00, 0xACC1, 0xAD81, 0x6D40, 0xAF01, 0x6FC0, 0x6E80, 0xAE41,
    0xAA01, 0x6AC0, 0x6B80, 0xAB41, 0x6900, 0xA9C1, 0xA881, 0x6840,
    0x7800, 0xB8C1, 0xB981, 0x7940, 0xBB01, 0x7BC0, 0x7A80, 0xBA41,
    0xBE01, 0x7EC0, 0x7F80, 0xBF41, 0x7D00, 0xBDC1, 0xBC81, 0x7C40,
    0xB401, 0x74C0, 0x7580, 0xB541, 0x7700, 0xB7C1, 0xB681, 0x7640,
    0x7200, 0xB2C1, 0xB381, 0x7340, 0xB101, 0x71C0, 0x7080, 0xB041,
    0x5000, 0x90C1, 0x9181, 0x5140, 0x9301, 0x53C0, 0x5280, 0x9241,
    0x9601, 0x56C0, 0x5780, 0x9741, 0x5500, 0x95C1, 0x9481, 0x5440,
    0x9C01, 0x5CC0, 0x5D80, 0x9D41, 0x5F00, 0x9FC1, 0x9E81, 0x5E40,
    0x5A00, 0x9AC1, 0x9B81, 0x5B40, 0x9901, 0x59C0, 0x5880, 0x9841,
    0x8801, 0x48C0, 0x4980, 0x8941, 0x4B00, 0x8BC1, 0x8A81, 0x4A40,
    0x4E00, 0x8EC1, 0x8F81, 0x4F40, 0x8D01, 0x4DC0, 0x4C80, 0x8C41,
    0x4400, 0x84C1, 0x8581, 0x4540, 0x8701, 0x47C0, 0x4680, 0x8641,
    0x8201, 0x42C0, 0x4380, 0x8341, 0x4100, 0x81C1, 0x8081, 0x4040,
};

void crc_check(char *buffer, int length)
{
    uint8_t byte;
    uint16_t crc = 0xFFFF;
    int valid_crc;

   while (length-- > 2) {
      byte = *buffer++ ^ crc;
      crc >>= 8;
      crc ^= crc16_table[byte];
   }

   valid_crc = (crc >> 8) == buffer[1] && (crc & 0xFF) == buffer[0];

   printf("CRC: %04X = %02X%02X [%s]\n", crc, buffer[1], buffer[0], valid_crc ? "OK" : "FAIL");
}

void usage(FILE *fp, char *progname, int exit_code)
{
    int n;

    fprintf(fp, "Usage: %s %n[-h] [-o out_dir] [-p port] [-s speed]\n", progname, &n);
    fprintf(fp, "%*c[-P parity] [-S stop_bits] [-b bits]\n\n", n, ' ');
    fprintf(fp, " -o, --output-dir   directory where to save the output\n");
    fprintf(fp, " -p, --serial-port  serial port to use\n");
    fprintf(fp, " -s, --speed        serial port speed (default 9600)\n");
    fprintf(fp, " -b, --bits         number of bits (default 8)\n");
    fprintf(fp, " -P, --parity       parity to use (default 'N')\n");
    fprintf(fp, " -S, --stop-bits    stop bits to use (default 1)\n");
    fprintf(fp, " -t, --interval     time interval between packets (default 1500)\n");
    fprintf(fp, " -m, --max-packets  maximum number of packets in capture file (default 10000)\n");

    exit(exit_code);
}

void parse_args(int argc, char **argv)
{
    int opt;

    while ((opt = getopt_long(argc, argv, "ho:p:s:P:S:b:", long_options, NULL)) >= 0) {
        switch (opt) {
        case 'o':
            output_dir = optarg;
            break;
        case 'p':
            serial_port = optarg;
            break;
        case 's':
            speed = atoi(optarg);
            break;
        case 'b':
            bits = atoi(optarg);
            break;
        case 'P':
            parity = optarg[0];
            break;
        case 'S':
            stop_bits = atoi(optarg);
            break;
        case 't':
            bytes_time_interval_us = atoi(optarg);
            break;
        case 'm':
            max_packet_per_capture = atoi(optarg);
            break;
        case 'h':
            usage(stdout, argv[0], EXIT_SUCCESS);
        default:
            usage(stderr, argv[0], EXIT_FAILURE);
        }
    }

    printf("output directory: %s\n", output_dir);
    printf("serial port: %s\n", serial_port);
    printf("port type: %d%c%d %d baud\n", bits, parity, stop_bits, speed);
    printf("time interval: %d\n", bytes_time_interval_us);
    printf("maximum packets in capture: %d", max_packet_per_capture);
}

/* https://blog.mbedded.ninja/programming/operating-systems/linux/linux-serial-ports-using-c-cpp */
void configure_serial_port(int fd)
{
    struct termios tty;

    if (tcgetattr(fd, &tty) < 0)
        DIE("tcgetattr");

    /* set parity */
    if (parity == 'N')
        tty.c_cflag &= ~PARENB;

    if (parity == 'E')
        tty.c_cflag |= PARENB;

    if (parity == 'O')
        tty.c_cflag |= PARODD | PARENB;

    /* set stop bits */
    if (stop_bits == 2)
        tty.c_cflag |= CSTOPB;
    else
        tty.c_cflag &= ~CSTOPB;

    /* set bits */
    tty.c_cflag &= ~CSIZE;

    switch (bits) {
    case 5: tty.c_cflag |= CS5; break;
    case 6: tty.c_cflag |= CS6; break;
    case 7: tty.c_cflag |= CS7; break;
    default: tty.c_cflag |= CS8; break;
    }

    /* disable RTS/CTS hardware flow control */
    tty.c_cflag &= ~CRTSCTS;

    /* turn on READ & ignore ctrl lines (CLOCAL = 1) */
    tty.c_cflag |= CREAD | CLOCAL;

    /* disable canonical mode */
    tty.c_lflag &= ~ICANON;

    /* disable echo */
    tty.c_lflag &= ~ECHO;

    /* disable erasure */
    tty.c_lflag &= ~ECHOE;

    /* disable new-line echo */
    tty.c_lflag &= ~ECHONL;

    /* disable interpretation of INTR, QUIT and SUSP */
    tty.c_lflag &= ~ISIG;

    /* turn off s/w flow ctrl */
    tty.c_iflag &= ~(IXON | IXOFF | IXANY);

    /* disable any special handling of received bytes */
    tty.c_iflag &= ~(IGNBRK | BRKINT | PARMRK | ISTRIP | INLCR | IGNCR | ICRNL);

    /* prevent special interpretation of output bytes (e.g. newline chars) */
    tty.c_oflag &= ~OPOST;

    /* prevent conversion of newline to carriage return/line feed */
    tty.c_oflag &= ~ONLCR;

#ifndef __linux__
    /* prevent conversion of tabs to spaces */
    tty.c_oflag &= ~OXTABS;

    /* prevent removal of C-d chars (0x004) in output */
    tty.c_oflag &= ~ONOEOT;
#endif

    /* how much to wait for a read */
    tty.c_cc[VTIME] = 0;

    /* minimum read size: 1 byte */
    tty.c_cc[VMIN] = 0;

    /* set port speed */
    cfsetispeed(&tty, speed);
    cfsetospeed(&tty, speed);

    if (tcsetattr(fd, TCSANOW, &tty) < 0)
        DIE("tcsetattr");
}

void write_global_header(int fd)
{
    struct pcap_global_header header = {
        .magic_number = 0xa1b2c3d4,
        .version_major = 2,
        .version_minor = 4,
        .thiszone = 0,
        .sigfigs = 0,
        .snaplen = 1024,
        .network = 147, /* custom USER */
    };

    if (write(fd, &header, sizeof header) < 0)
        DIE("write pcap");
}

void write_packet_header(int fd, int length)
{
    struct timespec t;
    struct pcap_packet_header header;

    clock_gettime(CLOCK_REALTIME, &t);

    header.ts_sec = t.tv_sec;
    header.ts_usec = t.tv_nsec / 1000;
    header.incl_len = length;
    header.orig_len = length;

    if (write(fd, &header, sizeof header) < 0)
        DIE("write pcap");
}

int open_logfile()
{
    int fd;
    time_t t;
    struct tm *l;
    char filename[PATH_MAX];
    char path[PATH_MAX];
    char latest_path[PATH_MAX];

    t = time(NULL);
    l = localtime(&t);

    strftime(filename, PATH_MAX, "modbus_%Y-%m-%d_%H_%M_%S.pcap", l);
    snprintf(path, PATH_MAX, "%s/%s", output_dir, filename);
    snprintf(latest_path, PATH_MAX, "%s/latest.pcap", output_dir);

    printf("opening logfile: %s\n", path);

    if ((fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644)) < 0)
        DIE("open pcap");

    if (access(latest_path, F_OK) == 0 && unlink(latest_path) < 0)
        perror("unlink latest.pcap error");

    if (symlink(path, latest_path) < 0)
        perror("symlink latest.pcap error");

    write_global_header(fd);

    return fd;
}

void signal_handler()
{
    rotate_log = 1;
}

int main(int argc, char **argv)
{
    int port, n_bytes = -1, res, size = 0, log_fd = -1, n_packets = 0;
    char buffer[MODBUS_MAX_PACKET_SIZE];
    struct timeval timeout;
    fd_set set;

    signal(SIGUSR1, signal_handler);

    parse_args(argc, argv);

    puts("starting modbus sniffer");

    if ((port = open(serial_port, O_RDONLY)) < 0)
        DIE("open port");

    configure_serial_port(port);

    while (n_bytes != 0) {
        if (rotate_log) {
            rotate_log = 0;

            if (log_fd > 0 && close(log_fd) < -1)
                DIE("close pcap");

            log_fd = open_logfile();
        }

        /* RTFM! these are overwritten after each select call and thus must be inizialized again */
        FD_ZERO(&set);
        FD_SET(port, &set);

        /* also these maybe overwritten in Linux */
        timeout.tv_sec = 0;
        timeout.tv_usec = bytes_time_interval_us;

        if ((res = select(port + 1, &set, NULL, NULL, &timeout)) < 0 && errno != EINTR)
            DIE("select");

        /* there is something to read...  */
        if (res > 0) {
            if ((n_bytes = read(port, buffer + size, MODBUS_MAX_PACKET_SIZE - size)) < 0)
                DIE("read port");

            size += n_bytes;
        }

        /* captured an entire packet */
        if (size > 0 && (res == 0 || size >= MODBUS_MAX_PACKET_SIZE || n_bytes == 0)) {
            printf("captured packet %d: length = %d, ", ++n_packets, size);

            if (n_packets % max_packet_per_capture == 0)
                rotate_log = 1;

            crc_check(buffer, size);
            write_packet_header(log_fd, size);

            if (write(log_fd, buffer, size) < 0)
                DIE("write pcap");

            size = 0;
        }
    }

    return EXIT_SUCCESS;
}
