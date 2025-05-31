#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <syslog.h>
#include <signal.h>
#include <arpa/inet.h>

#define PORT "9000"
#define BUFSIZE 1024
#define BACKLOG 10
#define FILE_PATH "/var/tmp/aesdsocketdata"

int sockfd=-1, new_fd=-1;  

void handle_sigterm(int sig) {
    syslog(LOG_INFO, "Caught signal, exiting");
    if (sockfd != -1) {
        shutdown(sockfd, SHUT_RDWR);  
        close(sockfd);                
    }
    if (new_fd != -1) {
        shutdown(new_fd, SHUT_RDWR);  
        close(new_fd);                
    }
    remove(FILE_PATH);
    exit(0);
}

void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

int main(int argc, char *argv[]) {
     int daemon_mode = 0;

    // Check for -d argument
    if (argc == 2 && strcmp(argv[1], "-d") == 0) {
        daemon_mode = 1;
    }
    
    int status;
    int yes = 1;
    char s[INET6_ADDRSTRLEN];
    struct sockaddr_storage their_addr; 
    socklen_t sin_size;
    struct addrinfo hints, *servinfo, *p;
    struct sigaction sa;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    if ((status = getaddrinfo(NULL, PORT, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(status));
        return -1;
    }

    openlog("tcp_server", LOG_PID | LOG_CONS, LOG_USER);
    for(p = servinfo; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype,
                p->ai_protocol)) == -1) {
            perror("server: socket");
            continue;
        }

        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes,
                sizeof(int)) == -1) {
            perror("setsockopt");
            return -1;
        }

        if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            perror("server: bind");
            continue;
        }

        break;
    }

    freeaddrinfo(servinfo);

    if (p == NULL)  {
        fprintf(stderr, "server: failed to bind\n");
        return -1;
    }

    if (listen(sockfd, BACKLOG) == -1) {
        perror("listen");
        return -1;
    }
    
    if (daemon_mode) {
        pid_t pid = fork();
        if (pid < 0) {
            perror("fork failed");
            exit(EXIT_FAILURE);
        }
        if (pid > 0) {
            exit(EXIT_SUCCESS);
        }


        if (setsid() < 0) {
            perror("setsid failed");
            exit(EXIT_FAILURE);
        }
    }
    
    sa.sa_handler = handle_sigterm;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGTERM, &sa, NULL) == -1) {
        perror("Error setting sigaction");
        return -1;
    }
    if (sigaction(SIGINT, &sa, NULL) == -1) {
	perror("Error setting SIGINT handler");
	return -1;
    }
    printf("server: waiting for connections...\n");
    
     while(1) {
     	sin_size = sizeof their_addr;
        new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size);
        if (new_fd == -1) {
            perror("accept");
            continue;
        }
        
        inet_ntop(their_addr.ss_family,
            get_in_addr((struct sockaddr *)&their_addr),
            s, sizeof s);
        syslog(LOG_INFO, "Accepted connection from %s\n", s);
        
        char buf[BUFSIZE];
    	size_t packet_size = 0;
    	char *packet_buffer = NULL;

	ssize_t num_bytes;
	while ((num_bytes = recv(new_fd, buf, BUFSIZE, 0)) > 0) {
		char *new_packet = realloc(packet_buffer, packet_size + num_bytes + 1);
		if (!new_packet) {
		    perror("realloc");
		    free(packet_buffer);
		    packet_buffer = NULL;
		    break;  // Discard this packet on memory error
		}
		packet_buffer = new_packet;
		memcpy(packet_buffer + packet_size, buf, num_bytes);
		packet_size += num_bytes;
		packet_buffer[packet_size] = '\0'; // Null-terminate for string ops

		// Check for newline (end of packet)
		char *newline_pos;
		while ((newline_pos = strchr(packet_buffer, '\n')) != NULL) {
		    size_t line_len = newline_pos - packet_buffer + 1;

		    // Open file for appending
		    FILE *fp = fopen(FILE_PATH, "a");
		    if (!fp) {
			perror("fopen");
			break;
		    }

		    fwrite(packet_buffer, 1, line_len, fp);
		    fclose(fp);
		    
		    fp = fopen(FILE_PATH, "r");
		    if (!fp) {
		        perror("fopen for read");
		        break;
		    }

		    char file_buf[BUFSIZE];
		    size_t read_bytes;
		    while ((read_bytes = fread(file_buf, 1, BUFSIZE, fp)) > 0) {
		        ssize_t sent = send(new_fd, file_buf, read_bytes, 0);
		        if (sent == -1) {
		            perror("send");
		            break;
		        }
		    }
		    fclose(fp);
            
		    // Shift buffer contents left after the newline
		    size_t remaining = packet_size - line_len;
		    memmove(packet_buffer, packet_buffer + line_len, remaining);
		    packet_size = remaining;

		    // Resize packet buffer
		    char *shrinked = realloc(packet_buffer, packet_size + 1);
		    if (shrinked) packet_buffer = shrinked;
		    packet_buffer[packet_size] = '\0';
		}
	}

	if (num_bytes == -1)
		perror("recv");

	free(packet_buffer);

	close(new_fd);
	syslog(LOG_INFO, "Closed connection from %s", s);
         
     }
}
