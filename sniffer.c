/*
 * A sniffer for the Modbus protocol
 * (c) 2020-2022 Alessandro Righi - released under the MIT license
 * (c) 2021 vheat - released under the MIT license
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
#include <stdbool.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>

#if __has_include(<linux/serial.h>)
#define HAS_LINUX_SERIAL_H
#include <sys/ioctl.h>
#include <linux/serial.h>
#endif /* __has_include(<linux/serial.h>) */

#define DIE(err) do { perror(err); exit(EXIT_FAILURE); } while (0)

/*
 * maximum Modbus packet size. By the standard is 300 bytes
 */
#define MODBUS_MAX_PACKET_SIZE 300

struct cli_args {
    char *serial_port;
    char *output_file;
    char parity;
    int bits;
    uint32_t speed;
    int stop_bits;
    uint32_t bytes_time_interval_us;
    bool low_latency;
};

struct option long_options[] = {
    { "serial-port", required_argument, NULL, 'p' },
    { "output",      required_argument, NULL, 'o' },
    { "speed",       required_argument, NULL, 's' },
    { "parity",      required_argument, NULL, 'P' },
    { "bits",        required_argument, NULL, 'b' },
    { "stop-bits",   required_argument, NULL, 'S' },
    { "interval",    required_argument, NULL, 't' },
    { "low-latency", no_argument,       NULL, 'l' },
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
} __attribute__((packed));

struct pcap_packet_header {
    uint32_t ts_sec;   /* timestamp seconds */
    uint32_t ts_usec;  /* timestamp microseconds */
    uint32_t incl_len; /* number of octets of packet saved in file */
    uint32_t orig_len; /* actual length of packet */
} __attribute__((packed));

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

int crc_check(uint8_t *buffer, int length)
{
    uint8_t byte;
    uint16_t crc = 0xFFFF;
    int valid_crc;

   while (length-- > 2) {
      byte = *buffer++ ^ crc;
      crc >>= 8;
      crc ^= crc16_table[byte];
   }

   valid_crc = ((crc >> 8) == (buffer[1] & 0xFF))  && ((crc & 0xFF) == (buffer[0] & 0xFF)) ;

   fprintf(stderr, "CRC: %04X = %02X%02X [%s]\n", crc, buffer[1] & 0xFF, buffer[0] & 0xFF, valid_crc ? "OK" : "FAIL");
  
   return valid_crc;
}

void usage(FILE *fp, char *progname, int exit_code)
{
    int n;

    fprintf(fp, "Usage: %s %n[-hl] [-o output] [-p port] [-s speed]\n", progname, &n);
    fprintf(fp, "%*c[-P parity] [-S stop_bits] [-b bits]\n\n", n, ' ');
    fprintf(fp, " -o, --output       output file to use (defaults to stdout, file will be truncated if already existing)\n");
    fprintf(fp, " -p, --serial-port  serial port to use\n");
    fprintf(fp, " -s, --speed        serial port speed (default 9600)\n");
    fprintf(fp, " -b, --bits         number of bits (default 8)\n");
    fprintf(fp, " -P, --parity       parity to use (default 'N')\n");
    fprintf(fp, " -S, --stop-bits    stop bits to use (default 1)\n");
    fprintf(fp, " -t, --interval     time interval between packets (default 1500)\n");

#ifdef HAS_LINUX_SERIAL_H
    fprintf(fp, " -l, --low-latency  try to enable serial port low-latency mode (Linux-only)\n");
#endif /* HAS_LINUX_SERIAL_H */

    exit(exit_code);
}

void parse_args(int argc, char **argv, struct cli_args *args)
{
    int opt;

    /* default values */
    args->serial_port = "/dev/ttyAMA0";
    args->output_file = "-";
    args->parity = 'N';
    args->bits = 8;
    args->speed = 9600;
    args->stop_bits = 1;
    args->bytes_time_interval_us = 1500;
    args->low_latency = false;

    while ((opt = getopt_long(argc, argv, "ho:p:s:P:S:b:lt:", long_options, NULL)) >= 0) {
        switch (opt) {
        case 'o':
            args->output_file = optarg;
            break;
        case 'p':
            args->serial_port = optarg;
            break;
        case 's':
            args->speed = strtoul(optarg, NULL, 10);
            break;
        case 'b':
            args->bits = atoi(optarg);
            break;
        case 'P':
            args->parity = optarg[0];
            break;
        case 'S':
            args->stop_bits = atoi(optarg);
            break;
        case 't':
            args->bytes_time_interval_us = strtoul(optarg, NULL, 10);
            break;
        case 'h':
            usage(stdout, argv[0], EXIT_SUCCESS);
            break;
        case 'l':
            args->low_latency = true;
            break;
        default:
            usage(stderr, argv[0], EXIT_FAILURE);
        }
    }

    fprintf(stderr, "output file: %s\n", args->output_file);
    fprintf(stderr, "serial port: %s\n", args->serial_port);
    fprintf(stderr, "port type: %d%c%d %d baud\n", args->bits, args->parity, args->stop_bits, args->speed);
    fprintf(stderr, "time interval: %d\n", args->bytes_time_interval_us);
}

/* https://blog.mbedded.ninja/programming/operating-systems/linux/linux-serial-ports-using-c-cpp */
void configure_serial_port(int fd, const struct cli_args *args)
{
    struct termios tty;
    
#ifdef HAS_LINUX_SERIAL_H
    if (args->low_latency) {
        struct serial_struct serial;
        
        if (ioctl(fd, TIOCGSERIAL, &serial) < 0) {
            perror("error getting serial struct. Low latency mode not supported");
        } else {
            serial.flags |= ASYNC_LOW_LATENCY;
            if (ioctl(fd, TIOCSSERIAL, &serial) < 0)
                perror("error setting serial struct. Low latency mode not supported");
        }
    }
#endif /* HAS_LINUX_SERIAL_H */

    if (tcgetattr(fd, &tty) < 0)
        DIE("tcgetattr");

    /* set parity */
    if (args->parity == 'N')
        tty.c_cflag &= ~PARENB;

    if (args->parity == 'E')
        tty.c_cflag |= PARENB;

    if (args->parity == 'O')
        tty.c_cflag |= PARODD | PARENB;

    /* set stop bits */
    if (args->stop_bits == 2)
        tty.c_cflag |= CSTOPB;
    else
        tty.c_cflag &= ~CSTOPB;

    /* set bits */
    tty.c_cflag &= ~CSIZE;

    switch (args->bits) {
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
    cfsetispeed(&tty, args->speed);
    cfsetospeed(&tty, args->speed);

    if (tcsetattr(fd, TCSANOW, &tty) < 0)
        DIE("tcsetattr");
}

void write_global_header(FILE *fp)
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

    if (fwrite(&header, sizeof header, 1, fp) != 1)
        DIE("write pcap");
}

void write_packet_header(FILE *fp, int length)
{
    struct timespec t;
    struct pcap_packet_header header;

    clock_gettime(CLOCK_REALTIME, &t);

    header.ts_sec = t.tv_sec;
    header.ts_usec = t.tv_nsec / 1000;
    header.incl_len = length;
    header.orig_len = length;

    if (fwrite(&header, sizeof header, 1, fp) != 1)
        DIE("write pcap");

    fflush(fp);
}

FILE *open_logfile(const char *path)
{
    FILE *fp;
    if (!path || strcmp(path, "-") == 0) {
        fp = stdout;
        if (isatty(1)) {
            fprintf(stderr, "capture file is binary, redirect it to a file or use the --output option!\n");
            exit(EXIT_FAILURE);
        }
    } else {
        fp = fopen(path, "wb+");
        if (!fp) {
            DIE("cannot open output file");
        }
    }

    write_global_header(fp);

    return fp;
}

void signal_handler(int signum)
{
    (void)signum;
    
    rotate_log = 1;
}

void dump_buffer(uint8_t *buffer, uint16_t length) 
{
	int i;
	fprintf(stderr, "\tDUMP: ");
	for (i=0; i < length; i++) {
		fprintf(stderr, " %02X", (uint8_t)buffer[i]);
	}
	fprintf(stderr, "\n");
}

int main(int argc, char **argv)
{
    struct cli_args args = {0};
    int port, n_bytes = -1, res, n_packets = 0;
    size_t size = 0;
    uint8_t buffer[MODBUS_MAX_PACKET_SIZE];
    struct timeval timeout;
    fd_set set;
    FILE *log_fp = NULL;

    signal(SIGUSR1, signal_handler);

    parse_args(argc, argv, &args);

    fprintf(stderr, "starting modbus sniffer\n");

    if ((port = open(args.serial_port, O_RDONLY)) < 0)
        DIE("open port");

    configure_serial_port(port, &args);

    while (n_bytes != 0) {
        if (rotate_log || !log_fp) {
            if (log_fp) {
                fclose(log_fp);
            }
            log_fp = open_logfile(args.output_file);
            rotate_log = 0;
        }

        /* RTFM! these are overwritten after each select call and thus must be inizialized again */
        FD_ZERO(&set);
        FD_SET(port, &set);

        /* also these maybe overwritten in Linux */
        timeout.tv_sec = 0;
        timeout.tv_usec = args.bytes_time_interval_us;

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
            fprintf(stderr, "captured packet %d: length = %zu, ", ++n_packets, size);

            if (crc_check(buffer, size)) {
                dump_buffer(buffer, size);
            }
            write_packet_header(log_fp, size);

            if (fwrite(buffer, 1, size, log_fp) != size)
                DIE("write pcap");

            fflush(log_fp);
            size = 0;
        }
    }

    return EXIT_SUCCESS;
}
