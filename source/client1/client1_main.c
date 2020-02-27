/*
 * TEMPLATE
 */
#include <stdio.h>
#include <stdlib.h>
#include "../sockwrap.h"
#include "../errlib.h"
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <inttypes.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <linux/limits.h>

/* the size of the buffer include the necessary space for the command the file
 * name and the \r\n */
#define MAXBUFL (sizeof(REQUESTC) + PATH_MAX + 2)
#define REQUESTC "GET "
#define QUITC "QUIT\r\n"
#define RES_OK "+OK\r\n"
#define RES_ERR "-ERR\r\n"
#define READ_TIMEOUT 40
#define FILE_BUF_LENGTH 4096
#define OK 0
#define ERR 1
#define INVALID_RES (-1)
#define NET_TIMESTAMP_SIZE 4
#define NET_FILESIZE_SIZE 4

//#define TRACE
/*la define di TRACE si può fare in compilazione con -DTRACE*/
#ifdef TRACE
#define trace(x) x
#else
#define trace(x)

#endif

char *prog_name;

char *checked_read_number(char *ptr, int n, FILE *stream);

ssize_t create_request(char **str_req, char *filename);

int is_valid_response(char *response);

ssize_t read_file_info(int socket_fd, uint32_t *filesize, uint32_t *last_mod);

ssize_t read_and_save_file(int read_fd, void *vptr, size_t nbytes, int write_fd);

int main(int argc, char *argv[]) {
    /* MAXBUFFER+1 to include the string terminator */
    char rbuffer[MAXBUFL+1];
    char *dest_h, *dest_p;
    struct in_addr inaddr;
    struct addrinfo *addr_res;
    in_port_t tport_n;
    struct sockaddr_in daddr;
    struct sockaddr_in *solveaddr;
    int i;
    int socket_fd;
    uint32_t filesize;
    uint32_t last_mod;
    char *escape_str;
    ssize_t response;
    char *str_req;
    ssize_t req_len;
    ssize_t ssret;
    int iret;
    char buf[FILE_BUF_LENGTH];
    int saved_file_fd;
    unsigned int dup_count;
    char filename[MAXBUFL];
    size_t filename_len;
    struct stat saved_file_stat;
    int is_invalid_path;

    /* for errlib to know the program name */
    prog_name = argv[0];
    signal(SIGPIPE, SIG_IGN);
    if (argc < 4) {
        err_quit("usage: %s <dest_host> <dest_port> <filename> [<filename>...] [-r]", prog_name);
    }
    dest_h = argv[1];
    dest_p = argv[2];
    Getaddrinfo(dest_h, dest_p, NULL, &addr_res);
    solveaddr = (struct sockaddr_in *)addr_res->ai_addr;


    /* create the socket */
    trace (err_msg("Creating socket\n"));
    socket_fd = Socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    trace (err_msg("socket created successfully"));

    /* prepare address structure */
    bzero(&daddr, sizeof(daddr));
    daddr.sin_family = AF_INET;
    daddr.sin_port = solveaddr->sin_port;
    daddr.sin_addr.s_addr = solveaddr->sin_addr.s_addr;
    /* enstablish connection */
    freeaddrinfo(addr_res);
    trace(printf("(%s)", prog_name);showAddr("Connecting to target address", &daddr));
    Connect(socket_fd, (struct sockaddr *) &daddr, sizeof(daddr));
    trace (err_msg("Connection done"));
    for (i = 3; i < argc; i++){


        /* check that requested file is server working directory */
        is_invalid_path = ((strncmp(argv[i], "../", 3) == 0) || argv[i][0] == '/' ||
                           strncmp(argv[i], "~/", 2) == 0);
        if (is_invalid_path) {
            printf("Filerequest not allowed: root and upper directory are not accessible\n");
            return -1;
        }

        req_len = create_request(&str_req, argv[i]);
        if (req_len == -1) {
            trace(err_msg("(%s) Cannot create the request for the server", prog_name));
            return -1;
        }
        trace(escape_str = escape(str_req));
        trace(printf("(%s) Sending %s\n", prog_name, escape_str));
        trace(free(escape_str));
        if (writen(socket_fd, str_req, (size_t) req_len) != req_len) {
            trace(err_ret("(%s) Error while sending the request to the server", prog_name));
            return -1;
        }
        free(str_req);
        trace(printf("waiting for response\n"));
        // after READ_TIMEOUT seconds (./client1_ref) - timeout waiting for data from server
        response = readline_unbuffered_select(socket_fd, rbuffer, MAXBUFL, READ_TIMEOUT);
        if (response < 0) {
            err_sys ("(%s) error - readline_unbuffered_select() failed reading server response", prog_name);
            return -1;
        } else if (response == 0) {
            trace(err_ret("(%s) Server disconnected ... Closing socket"));
            break;
        }
        rbuffer[response] = '\0';
        trace(escape_str = escape(rbuffer));
        trace(printf("Received response from socket %03u : %s\n", socket_fd, escape_str));
        trace(free(escape_str));
        iret = is_valid_response(rbuffer);
        switch (iret) {
            case OK:
                ssret = read_file_info(socket_fd, &filesize, &last_mod);
                if (ssret < NET_FILESIZE_SIZE + NET_TIMESTAMP_SIZE) {
                    err_sys("(%s) Error reading file header from socket",prog_name);
                }
                /* if file exist then save another like "filename[(dup_count)]" max is (999)*/
//                filename_len = strlen(argv[i]);
//                filename = malloc((filename_len + 5 + 1) * sizeof(char));
//                strncpy(filename, argv[i], strlen(argv[i]));
                    strcpy(filename, argv[i]);
//                dup_count = 1;
//                while( access(filename, F_OK) == 0) {
//                    filename[filename_len] = '\0';
//                    snprintf(filename, filename_len + 5 , "%s(%u)", argv[i], dup_count++);
//                }
                saved_file_fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
                read_and_save_file(socket_fd, buf, filesize, saved_file_fd);
                fstat(saved_file_fd, &saved_file_stat);
                close(saved_file_fd);
                if (saved_file_stat.st_size != filesize) {
                    printf("File received have different size!!");
                } else {
                    printf("Received file %s\nReceived file size %"PRIu32"\nReceived file timestamp %"PRIu32"\n", \
                           filename, saved_file_stat.st_size, last_mod);
                }
//                free(filename);
                break;
            case ERR:
                /* if is not the last request I re establish a connection to request the
                 * other files */
                if (i != argc - 1) {
                    Close(socket_fd);
                    trace (err_msg("Creating socket\n"));
                    socket_fd = Socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
                    trace (err_msg("socket created successfully"));
                    Connect(socket_fd, (struct sockaddr *) &daddr, sizeof(daddr));
                    trace (err_msg("Connection done"));
                    return -1;
                }
                break;
            case INVALID_RES:
            default:
                trace(err_sys("(%s) Unrecognized response", prog_name));
                break;
        }
    }
    trace(escape_str = escape(QUITC));
    trace(printf("(%s) Sending %s\n", prog_name, escape_str));
    trace(free(escape_str));

    Writen(socket_fd, QUITC, strlen(QUITC));
    Close(socket_fd);
    trace (err_msg("Connection closed"));

    return 0;
}

ssize_t create_request(char **str_req_ptr, char *filename) {
    char *str_req;
    size_t req_len, filename_len;
    int is_invalid_path;

    /* calculating the size of request (2 for "\r\n" and 1 for '\0' */
    req_len = strlen(REQUESTC);
    filename_len = strlen(filename);
    ssize_t len = req_len + filename_len + 2 + 1 ;
    str_req = malloc(len * sizeof(char));
    if (str_req == NULL) {
        return -1;
    }
    str_req[0] = '\0';
    strcat(str_req, REQUESTC);
    strcat(str_req, filename);
    strcat(str_req, "\r\n");


    *str_req_ptr = str_req;
    return strlen(str_req);
}

int is_valid_response(char *response) {

    if (strcmp(response, RES_OK) == 0)
        return OK;
    else if(strcmp(response, RES_ERR) == 0)
        return ERR;

    return INVALID_RES;
}

ssize_t read_file_info(int socket_fd, uint32_t *filesize, uint32_t *last_mod) {
    ssize_t n;

    size_t header_size = NET_FILESIZE_SIZE + NET_TIMESTAMP_SIZE;
    char buf[4];

    if ((n = readn_select(socket_fd, buf, header_size, READ_TIMEOUT)) != header_size) {
        err_ret ("(%s) error - readn_select() failed", prog_name);
        return n;
    }
    memcpy(filesize, buf, NET_FILESIZE_SIZE);
    memcpy(last_mod, (buf + NET_FILESIZE_SIZE), NET_TIMESTAMP_SIZE);
    *filesize = ntohl((uint32_t) *filesize);
    *last_mod = ntohl((uint32_t) *last_mod);

    return n;
}

ssize_t read_and_save_file(int read_fd, void *vptr, size_t nbytes, int write_fd) {
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
                return -1; /* and call read() again */
            }
            else {
                trace(err_ret("(%s) error fail reading file data on socket", prog_name));
                return -1;
            }
        }
        else if (nread == 0) {
            break; /* EOF */
        }
        if ((ret = write(write_fd, ptr, (size_t) nread)) != nread) {
            trace(err_ret("(%s) error writing file data on disk", prog_name));
            return -1;
        };
        nleft -= nread;
    }
    return nbytes - nleft;
}
