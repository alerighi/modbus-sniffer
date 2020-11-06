/*
 * a sniffer for the Modbus (TM) protocol
 */

#define _DEFAULT_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <termios.h>
#include <syslog.h>
#include <time.h>
#include <signal.h>
#include <limits.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>

#define DIE(err) do { perror(err); exit(EXIT_FAILURE); } while (0)

#define SERIAL_PORT "/dev/ttyAMA0"
#define CAPTURE_DIR "/tmp/sniffer/"

/*
 * how much to wait between a byte and another
 * Modbus standard specifies a maximum of 1.56ms for 9600 bauds
 */
#define MODBUS_MAX_BYTES_INTERVAL_US 1560

/*
 * maximum Modbus packet size. By the standard is 300 bytes
 */
#define MODBUS_MAX_PACKET_SIZE 300

/*
 * maximum number of packet to have in a file
 * 10.000 seems a reasonable number here
 */
#define MAX_CAPTURE_FILE_PACKETS 10000

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
    0X0000, 0XC0C1, 0XC181, 0X0140, 0XC301, 0X03C0, 0X0280, 0XC241,
    0XC601, 0X06C0, 0X0780, 0XC741, 0X0500, 0XC5C1, 0XC481, 0X0440,
    0XCC01, 0X0CC0, 0X0D80, 0XCD41, 0X0F00, 0XCFC1, 0XCE81, 0X0E40,
    0X0A00, 0XCAC1, 0XCB81, 0X0B40, 0XC901, 0X09C0, 0X0880, 0XC841,
    0XD801, 0X18C0, 0X1980, 0XD941, 0X1B00, 0XDBC1, 0XDA81, 0X1A40,
    0X1E00, 0XDEC1, 0XDF81, 0X1F40, 0XDD01, 0X1DC0, 0X1C80, 0XDC41,
    0X1400, 0XD4C1, 0XD581, 0X1540, 0XD701, 0X17C0, 0X1680, 0XD641,
    0XD201, 0X12C0, 0X1380, 0XD341, 0X1100, 0XD1C1, 0XD081, 0X1040,
    0XF001, 0X30C0, 0X3180, 0XF141, 0X3300, 0XF3C1, 0XF281, 0X3240,
    0X3600, 0XF6C1, 0XF781, 0X3740, 0XF501, 0X35C0, 0X3480, 0XF441,
    0X3C00, 0XFCC1, 0XFD81, 0X3D40, 0XFF01, 0X3FC0, 0X3E80, 0XFE41,
    0XFA01, 0X3AC0, 0X3B80, 0XFB41, 0X3900, 0XF9C1, 0XF881, 0X3840,
    0X2800, 0XE8C1, 0XE981, 0X2940, 0XEB01, 0X2BC0, 0X2A80, 0XEA41,
    0XEE01, 0X2EC0, 0X2F80, 0XEF41, 0X2D00, 0XEDC1, 0XEC81, 0X2C40,
    0XE401, 0X24C0, 0X2580, 0XE541, 0X2700, 0XE7C1, 0XE681, 0X2640,
    0X2200, 0XE2C1, 0XE381, 0X2340, 0XE101, 0X21C0, 0X2080, 0XE041,
    0XA001, 0X60C0, 0X6180, 0XA141, 0X6300, 0XA3C1, 0XA281, 0X6240,
    0X6600, 0XA6C1, 0XA781, 0X6740, 0XA501, 0X65C0, 0X6480, 0XA441,
    0X6C00, 0XACC1, 0XAD81, 0X6D40, 0XAF01, 0X6FC0, 0X6E80, 0XAE41,
    0XAA01, 0X6AC0, 0X6B80, 0XAB41, 0X6900, 0XA9C1, 0XA881, 0X6840,
    0X7800, 0XB8C1, 0XB981, 0X7940, 0XBB01, 0X7BC0, 0X7A80, 0XBA41,
    0XBE01, 0X7EC0, 0X7F80, 0XBF41, 0X7D00, 0XBDC1, 0XBC81, 0X7C40,
    0XB401, 0X74C0, 0X7580, 0XB541, 0X7700, 0XB7C1, 0XB681, 0X7640,
    0X7200, 0XB2C1, 0XB381, 0X7340, 0XB101, 0X71C0, 0X7080, 0XB041,
    0X5000, 0X90C1, 0X9181, 0X5140, 0X9301, 0X53C0, 0X5280, 0X9241,
    0X9601, 0X56C0, 0X5780, 0X9741, 0X5500, 0X95C1, 0X9481, 0X5440,
    0X9C01, 0X5CC0, 0X5D80, 0X9D41, 0X5F00, 0X9FC1, 0X9E81, 0X5E40,
    0X5A00, 0X9AC1, 0X9B81, 0X5B40, 0X9901, 0X59C0, 0X5880, 0X9841,
    0X8801, 0X48C0, 0X4980, 0X8941, 0X4B00, 0X8BC1, 0X8A81, 0X4A40,
    0X4E00, 0X8EC1, 0X8F81, 0X4F40, 0X8D01, 0X4DC0, 0X4C80, 0X8C41,
    0X4400, 0X84C1, 0X8581, 0X4540, 0X8701, 0X47C0, 0X4680, 0X8641,
    0X8201, 0X42C0, 0X4380, 0X8341, 0X4100, 0X81C1, 0X8081, 0X4040
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

/* https://blog.mbedded.ninja/programming/operating-systems/linux/linux-serial-ports-using-c-cpp */
void configure_serial_port(int fd)
{
    struct termios tty;

    if (tcgetattr(fd, &tty) < 0)
        DIE("tcgetattr");

    /* clear parity bit */
    tty.c_cflag &= ~PARENB;

    /* clear stop field */
    tty.c_cflag &= ~CSTOPB;

    /* 8 bits per byte */
    tty.c_cflag |= CS8;

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

    /* Disable any special handling of received bytes */
    tty.c_iflag &= ~(IGNBRK | BRKINT | PARMRK | ISTRIP | INLCR | IGNCR | ICRNL);

    /* Prevent special interpretation of output bytes (e.g. newline chars) */
    tty.c_oflag &= ~OPOST;

    /* Prevent conversion of newline to carriage return/line feed */
    tty.c_oflag &= ~ONLCR;

#ifndef __linux__
    /* Prevent conversion of tabs to spaces */
    tty.c_oflag &= ~OXTABS;

    /*Prevent removal of C-d chars (0x004) in output */
    tty.c_oflag &= ~ONOEOT;
#endif

    /* how much to wait for a read */
    tty.c_cc[VTIME] = 0;

    /* minimum read size: 1 byte */
    tty.c_cc[VMIN] = 0;

    /* set port speed */
    cfsetispeed(&tty, B9600);
    cfsetospeed(&tty, B9600);

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
    char path[PATH_MAX];

    t = time(NULL);
    l = localtime(&t);

    strftime(path, PATH_MAX, CAPTURE_DIR "modbus_%Y-%m-%d_%H_%M_%S.pcap", l);

    printf("opening logfile: %s\n", path);

    if ((fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644)) < 0)
        DIE("open pcap");

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

    puts("starting modbus sniffer");

    if ((port = open(SERIAL_PORT, O_RDONLY)) < 0)
        DIE("open port");

    configure_serial_port(port);

    while (n_bytes != 0) {
        if (rotate_log) {
            rotate_log = 0;

            if (close(log_fd) < -1)
                DIE("close pcap");

            log_fd = open_logfile();
        }

        /* RTFM! these are overwritten after each select call and thus must be inizialized again */
        FD_ZERO(&set);
        FD_SET(port, &set);

        /* also these maybe overwritten in Linux */
        timeout.tv_sec = 0;
        timeout.tv_usec = MODBUS_MAX_BYTES_INTERVAL_US;

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

            if (n_packets % MAX_CAPTURE_FILE_PACKETS == 0)
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
