/*
 * TEMPLATE 
 */
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <errno.h>
#include <sys/sendfile.h>
#include "../sockwrap.h"
#include "../errlib.h"
#include <linux/limits.h>
#include <limits.h>
//#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>

//#define SRVPORT 1500

#define LISTENQ 15
#define MAXBUFL (sizeof(REQUESTC) + PATH_MAX)
#define FILE_BUF_LENGTH 4096

#define REQUESTC "GET "
#define QUITC "QUIT\r\n"
#define RES_OK "+OK\r\n"
#define RES_ERR "-ERR\r\n"
#define QUIT_REQ 0
#define FILE_REQ 1
#define INVALID_REQ (-1)
#define FILE_HEADER_LENGTH 13
#define REPLY 1
#define NO_REPLY 0
#define NET_TIMESTAMP_SIZE 4
#define NET_FILESIZE_SIZE 4
#define READ_TIMEOUT 40

#define MAX_UINT16T 0xffff
//#define STATE_OK 0x00
//#define STATE_V  0x01

/*la define di TRACE si può fare in compilazione con -DTRACE*/
#ifdef TRACE
#define trace(x) x
#else
#define trace(x)
#endif

char *prog_name;

ssize_t read_and_send(int read_fd, void *vptr, size_t nbytes, int write_fd) ;

void clean_close(int *fd, int reply) ;

int serve(int conn_fd) ;

/* if return equal to 0 check returns the file_path too */
int is_valid_cmd(char *str, size_t str_len, char *file_path);

int file_serve(int conn_fd, char *file_path) ;

int main (int argc, char *argv[])
{
	int socket_fd;
	int conn_fd = -1;
	int is_socket_open = 0;
	uint16_t lport_n, lport_h;
	prog_name = argv[0];
	struct sockaddr_in saddr;
	struct sockaddr_in cliaddr;
	socklen_t cliaddrlen = sizeof(cliaddr);

    Signal(SIGPIPE, SIG_IGN);
    if (argc != 2) {
		err_quit("Usage: %s <port number>\n", prog_name);
	}

	if (sscanf(argv[1], "%" SCNu16, &lport_h) != 1) {
		err_sys("Invalid port number\n");
	}
	lport_n = htons(lport_h);
	printf("creating the socket\n");
	/* create the socket and bind to all interfaces */
	socket_fd = Socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	printf("done, socket number %d\n", socket_fd);
	bzero(&saddr, sizeof(saddr));
	saddr.sin_family = AF_INET;
	saddr.sin_port = lport_n;
	saddr.sin_addr.s_addr = INADDR_ANY;
	showAddr("Binding to address", &saddr);
	Bind(socket_fd, (SA*) &saddr, sizeof(saddr));
	/* listen at the socket */
	Listen(socket_fd, LISTENQ);
	/* wait and serve requests */
	while (1) {
		trace(err_msg("(%s) waiting for connections ...", prog_name));

		while(1) {
		    if (is_socket_open == 0) {
                conn_fd = Accept(socket_fd,(SA*) &cliaddr, &cliaddrlen);
                trace(showAddr("Accepted connection from", &cliaddr));
                trace(err_msg("new socket: %d", conn_fd));
            }
//			setsockopt(conn_fd, SOL_SOCKET, SO_NOSIGPIPE, (void *)&set, sizeof(int));
			//return value for socket open or close
            is_socket_open = serve(conn_fd);
		}
	}
	return 0;
}

/*
 * returns 0 if connection is closed at the end of the service or 1 if connection is still
 * open
 */
int serve(int conn_fd) {
	ssize_t nread;
	int ret;
	char buf[MAXBUFL+1];
	char file_path[PATH_MAX+1];
	char *escape_str;

	trace(err_msg("(%s)reading from socket", prog_name));
	nread = my_protocol_readline(conn_fd, buf, MAXBUFL, READ_TIMEOUT);
	if (nread == 0) {
	/* connection closed by the client */
		trace(err_ret("(%s) Connection closed by the client", prog_name));
		clean_close(&conn_fd, NO_REPLY);
			return 0;
	} else if (nread < 0) {
		trace(err_ret("(%s) error - readline() failed", prog_name));
		clean_close(&conn_fd, REPLY);
			return 0;
	}
	buf[nread] = '\0';
	trace(escape_str = escape(buf));
	trace( printf("(%s) received: %s\n", prog_name, escape_str));
	trace(free(escape_str));
	/* check the all operands of string received */
	ret = is_valid_cmd(buf, (size_t) nread, file_path);
	switch (ret) {
		case FILE_REQ:
		    trace(printf("(%s) File request received: %s", prog_name, file_path));
			ret = file_serve(conn_fd, file_path);
			/* missing or other kind of error relating to the file */
			if (ret == -1) {
				clean_close(&conn_fd, REPLY);
				return 0;
			}
			return 1;
		case QUIT_REQ:
            trace(printf("(%s) Quit request received\n", prog_name));
            clean_close(&conn_fd, NO_REPLY);
            return 0;
		case INVALID_REQ:
		default:
			trace(err_msg("(%s) illegal command received", prog_name));
			clean_close(&conn_fd, REPLY);
			return 0;
	}
}
/* if return equal to 0 check returns the file_path too */
int is_valid_cmd(char *str, size_t str_len, char *file_path) {
    size_t length;
    int is_invalid_path;

    if (str[str_len - 2] != '\r' && str[str_len - 1] != '\n'){
        return INVALID_REQ;
    }

    if (strncmp(str, REQUESTC, strlen(REQUESTC)) == 0) {
        snprintf(file_path, PATH_MAX, str + strlen(REQUESTC));
        // if the buffer is no big enough i will put the terminator on last byte
        file_path[PATH_MAX] = '\0';
        is_invalid_path = ((strncmp(file_path, "../", 3) == 0) || file_path[0] == '/' ||
                           strncmp(file_path, "~/", 2) == 0);
        if (is_invalid_path)
            return INVALID_REQ;
        length = strlen(file_path);
        file_path[length - 2] = '\0';
        return FILE_REQ;
	} else if (strncmp(str, QUITC, strlen(QUITC)) == 0) {
		return QUIT_REQ;
	} else
		return INVALID_REQ;
}

void clean_close(int *fd, int reply) {
	int ret;

    trace(err_msg("(%s) Disconnecting...", prog_name));
    if (reply == REPLY) {
		trace(err_msg("(%s) Disconnecting from active socket and reply to the client", prog_name));
		if (sendn(*fd, RES_ERR, FILE_HEADER_LENGTH, MSG_NOSIGNAL) == -1) {
			trace(err_ret("(%s) Error sending disconnection reply", prog_name));
		}
	}
	ret = close(*fd);
	*fd = -1;
	if (ret != 0) {
		trace( err_ret("(%s) Error closing the socket"));
	}
}

int file_serve(int conn_fd, char *file_path) {
	int fd_in;
	struct stat filestat;
	struct flock fl;
	char read_buffer[FILE_BUF_LENGTH];
	char header[FILE_HEADER_LENGTH];
	uint32_t netfilesize;
	uint32_t netfiletstamp;

	/* setting read shared lock on file that we want to transfer in order
	 * to prevent update that could corrupt the file */
    memset(&fl, 0, sizeof(fl));

    fd_in = open(file_path, O_RDONLY);
    if (fd_in == -1) {
        trace(err_ret("(%s) Error opening the file", prog_name));
        return -1;
    }
	fstat(fd_in, &filestat);
    if (filestat.st_size >= UINT32_MAX) {
        trace(err_msg("(%s) Cannot represent the size on %d byte", prog_name, NET_FILESIZE_SIZE));
        return -1;
    }
	/* send header "+OK\r\n|size in 4 byte|timestamp| */
    netfilesize = htonl((uint32_t) filestat.st_size);
    netfiletstamp = htonl((uint32_t) filestat.st_mtim.tv_sec);
    /* we don't want to copy the terminator \0 */
    strncpy(header, RES_OK, sizeof(RES_OK) -1);
    memcpy(header + sizeof(RES_OK) - 1, &netfilesize, NET_FILESIZE_SIZE);
	memcpy(header + sizeof(RES_OK) -1 + 4, &netfiletstamp, NET_TIMESTAMP_SIZE);
	if (sendn(conn_fd, header, FILE_HEADER_LENGTH, MSG_NOSIGNAL) == -1) {
		trace(err_ret("(%s) Error sending the file header", prog_name));
		return -1;
	}
	/* start to send the requested file */
	if (read_and_send(fd_in, read_buffer, (size_t) filestat.st_size, conn_fd) == -1) {
		/* send error to caller in order to return again the error for closing
		 * the connection */
		return -1;
	}
	close(fd_in);

	return 0;
}

ssize_t read_and_send(int read_fd, void *vptr, size_t nbytes, int write_fd) {
	size_t nleft;
	ssize_t nread;
	ssize_t ret;
	char *ptr;

	ptr = vptr;
	nleft = nbytes;
	while (nleft > 0)
	{
		if ( (nread = read(read_fd, ptr, (size_t) FILE_BUF_LENGTH)) < 0)
		{
			if (INTERRUPTED_BY_SIGNAL)
			{
				nread = 0;
				continue; /* and call read() again */
			}
			else {
                trace(err_ret("(%s) error fail reading file data on disk", prog_name));
                return -1;
            }
		}
		else if (nread == 0) {
			break; /* EOF */
		}
        if ((ret = sendn(write_fd, ptr, (size_t) nread, MSG_NOSIGNAL)) != nread) {
            trace(err_ret("(%s) error fail sending file data on the socket", prog_name));
            return -1;
        };
        nleft -= nread;
    }
	return nbytes - nleft;
}
