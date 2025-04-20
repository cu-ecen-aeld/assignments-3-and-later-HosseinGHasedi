#include <stdio.h>
#include <string.h> 
#include <unistd.h>
#include <fcntl.h>
#include <syslog.h>

int main(int argc, char *argv[]) {
    openlog(NULL, LOG_PID, LOG_USER);

    if (argc != 3) {
        syslog(LOG_ERR, "Usage: %s <filename> <text>\n", argv[0]);
        return 1;
    }

    char *filename = argv[1];
    char *text = argv[2];

    FILE *file = fopen(filename, "w");
    if (file == NULL) {
        syslog(LOG_ERR, "Failed to open file: %s\n", filename);
        return 1;
    }

    fprintf(file, "%s", text);
    fclose(file);

    syslog(LOG_INFO, "Writing %s to %s", text, filename);
    closelog();

    return 0;
}
