#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <syslog.h>
#include <signal.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <stdbool.h>
#include <time.h>
#include <sys/timerfd.h>
#include <sys/epoll.h>

#define PORT "9000"
#define BUFSIZE 1024
#define BACKLOG 10
#define FILE_PATH "/var/tmp/aesdsocketdata"

struct client_thread_data {
    int client_fd;                    // Client socket file descriptor
    struct sockaddr_storage client_addr;  // Client address info
    char client_ip[INET6_ADDRSTRLEN];     // Client IP string
    pthread_t thread_id;              // Thread ID for cleanup
    bool thread_complete_success;     // Thread completion status
};


struct thread_node {
    pthread_t thread_id;
    struct client_thread_data* client_data;
    struct thread_node* next;
};

struct thread_node* thread_list_head = NULL;
pthread_mutex_t thread_mutex = PTHREAD_MUTEX_INITIALIZER;

pthread_mutex_t file_mutex = PTHREAD_MUTEX_INITIALIZER;

pthread_t timestamp_thread;
bool timestamp_thread_running = false;

int sockfd=-1, new_fd=-1;  

void remove_thread_from_list(pthread_t thread_id) {
    pthread_mutex_lock(&thread_mutex);
    
    struct thread_node** current = &thread_list_head;
    while (*current != NULL) {
        if (pthread_equal((*current)->thread_id, thread_id)) {
            struct thread_node* to_remove = *current;
            *current = (*current)->next;
            // Note: client_data is freed in the thread itself, so we only free the node
            free(to_remove);
            break;
        }
        current = &(*current)->next;
    }
    
    pthread_mutex_unlock(&thread_mutex);
}

void* timestamp_thread_handler(void* arg) {
    (void)arg; // Suppress unused parameter warning
    
    while (1) {
        sleep(10); // Wait 10 seconds
        
        // Get current time
        time_t now;
        struct tm* tm_info;
        char timestamp_str[64];
        
        time(&now);
        tm_info = localtime(&now);
        
        // Format according to RFC 2822
        strftime(timestamp_str, sizeof(timestamp_str), 
                "timestamp:%a, %d %b %Y %H:%M:%S %z\n", tm_info);
        
        // Write to file with proper locking
        pthread_mutex_lock(&file_mutex);
        
        FILE *fp = fopen(FILE_PATH, "a");
        if (fp) {
            fwrite(timestamp_str, 1, strlen(timestamp_str), fp);
            fclose(fp);
            syslog(LOG_DEBUG, "Timestamp written: %s", timestamp_str);
        } else {
            perror("fopen for timestamp");
        }
        
        pthread_mutex_unlock(&file_mutex);
    }
    
    return NULL;
}

void handle_sigterm(int sig) {
    syslog(LOG_INFO, "Caught signal, exiting");

    if (timestamp_thread_running) {
        pthread_cancel(timestamp_thread);
        pthread_join(timestamp_thread, NULL);
        timestamp_thread_running = false;
    }

    if (sockfd != -1) {
        shutdown(sockfd, SHUT_RDWR);  
        close(sockfd);                
    }
    if (new_fd != -1) {
        shutdown(new_fd, SHUT_RDWR);  
        close(new_fd);                
    }

    pthread_mutex_lock(&thread_mutex);
    struct thread_node* current = thread_list_head;
    while (current != NULL) {
        pthread_join(current->thread_id, NULL);
        struct thread_node* to_free = current;
        current = current->next;
        // Note: client_data is freed in the thread itself
        free(to_free);
    }
    thread_list_head = NULL;
    pthread_mutex_unlock(&thread_mutex);

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

int setup_socket() {
    int status;
    int yes = 1;
    struct addrinfo hints, *servinfo, *p;
    
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    if ((status = getaddrinfo(NULL, PORT, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(status));
        return -1;
    }

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
    
    return 0;
}

int setup_daemon_mode() {
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
    
    return 0;
}

int setup_signal_handlers() {
    struct sigaction sa;
    
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
    
    return 0;
}

int start_timestamp_thread() {
    if (pthread_create(&timestamp_thread, NULL, timestamp_thread_handler, NULL) != 0) {
        perror("pthread_create for timestamp thread");
        return -1;
    }
    timestamp_thread_running = true;
    syslog(LOG_INFO, "Timestamp thread started");
    return 0;
}

int process_client_data(int client_fd) {
    char buf[BUFSIZE];
    size_t packet_size = 0;
    char *packet_buffer = NULL;
    ssize_t num_bytes;
    
    while ((num_bytes = recv(client_fd, buf, BUFSIZE, 0)) > 0) {
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

            pthread_mutex_lock(&file_mutex);

            // Open file for appending
            FILE *fp = fopen(FILE_PATH, "a");
            if (!fp) {
                perror("fopen");
                pthread_mutex_unlock(&file_mutex);
                break;
            }

            fwrite(packet_buffer, 1, line_len, fp);
            fclose(fp);
            
            fp = fopen(FILE_PATH, "r");
            if (!fp) {
                perror("fopen for read");
                pthread_mutex_unlock(&file_mutex);
                break;
            }

            char file_buf[BUFSIZE];
            size_t read_bytes;
            while ((read_bytes = fread(file_buf, 1, BUFSIZE, fp)) > 0) {
                ssize_t sent = send(client_fd, file_buf, read_bytes, 0);
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
            pthread_mutex_unlock(&file_mutex);
        }
    }

    if (num_bytes == 0) {
        syslog(LOG_INFO, "Client disconnected");
        free(packet_buffer);
        return -1;  // Exit thread
    }
    if (num_bytes == -1) {
        perror("recv");
        free(packet_buffer);
        return -1;  // Exit thread
    }
    return 0; 
}

void* client_thread_handler(void* thread_param) {
    struct client_thread_data* client_data = (struct client_thread_data*)thread_param;
    
    syslog(LOG_INFO, "Thread started for client %s", client_data->client_ip);
    
    // Process client data (this is your existing process_client_data logic)
    if (process_client_data(client_data->client_fd) != 0) {
        syslog(LOG_ERR, "Error processing client data for %s", client_data->client_ip);
        client_data->thread_complete_success = false;
    } else {
        client_data->thread_complete_success = true;
    }
    
    // Close client socket
    close(client_data->client_fd);
    syslog(LOG_INFO, "Thread completed for client %s", client_data->client_ip);
    
    // Free the client_data memory before returning
    free(client_data);
    
    return NULL;
}

int handle_client_connection() {
    struct sockaddr_storage their_addr;
    socklen_t sin_size = sizeof their_addr;
    char s[INET6_ADDRSTRLEN];
    
    new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size);
    if (new_fd == -1) {
        perror("accept");
        return -1;
    }
    
    inet_ntop(their_addr.ss_family,
        get_in_addr((struct sockaddr *)&their_addr),
        s, sizeof s);
    syslog(LOG_INFO, "Accepted connection from %s\n", s);

    struct client_thread_data* client_data = malloc(sizeof(struct client_thread_data));
    if (!client_data) {
        perror("malloc");
        close(new_fd);
        return -1;
    }

    client_data->client_fd = new_fd;
    client_data->client_addr = their_addr;
    strncpy(client_data->client_ip, s, INET6_ADDRSTRLEN);
    client_data->thread_complete_success = false;

    // Create thread first
    pthread_t client_thread;
    
    if (pthread_create(&client_thread, NULL, client_thread_handler, client_data) != 0) {
        perror("pthread_create");
        free(client_data);
        close(new_fd);
        return -1;
    }
    
    // Add thread to list after successful creation
    pthread_mutex_lock(&thread_mutex);
    struct thread_node* new_node = malloc(sizeof(struct thread_node));
    if (!new_node) {
        perror("malloc for thread node");
        pthread_mutex_unlock(&thread_mutex);
        return -1;
    }
    
    new_node->thread_id = client_thread;
    new_node->client_data = client_data;
    new_node->next = thread_list_head;
    thread_list_head = new_node;
    pthread_mutex_unlock(&thread_mutex);
    
    syslog(LOG_INFO, "Created thread for client %s", s);
    
    return 0;
}

void cleanup_finished_threads() {
    pthread_mutex_lock(&thread_mutex);
    // Remove completed threads from active_threads array
    // This is optional - you can also just let threads finish naturally
    pthread_mutex_unlock(&thread_mutex);
}

int main(int argc, char *argv[]) {
    int daemon_mode = 0;

    // Check for -d argument
    if (argc == 2 && strcmp(argv[1], "-d") == 0) {
        daemon_mode = 1;
    }
    
    // Setup socket
    if (setup_socket() != 0) {
        return -1;
    }
    
    // Setup logging
    openlog("tcp_server", LOG_PID | LOG_CONS, LOG_USER);
    
    // Setup daemon mode if requested
    if (daemon_mode) {
        if (setup_daemon_mode() != 0) {
            return -1;
        }
    }
    
    // Setup signal handlers
    if (setup_signal_handlers() != 0) {
        return -1;
    }

    // Start timestamp thread AFTER daemon mode setup
    if (start_timestamp_thread() != 0) {
        return -1;
    }
    
    printf("server: waiting for connections...\n");
    
    // Main server loop
    while(1) {
        if (handle_client_connection() != 0) {
            continue; // Continue accepting connections even if one fails
        }

        // cleanup finished threads periodically
        cleanup_finished_threads();
    }
}
