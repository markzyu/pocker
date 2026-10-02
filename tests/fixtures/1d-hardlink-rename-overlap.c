#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main() {
	int retval;
	int pid;
    char buffer[512];
       
    // Creation
    FILE *f = fopen("/x", "w");
    if (f == NULL) return errno;
    fprintf(f, "TEST");
    fclose(f);

    retval = link("/x", "/y");
    if (retval < 0) return errno;

    retval = rename("/x", "/y");
    if (retval < 0) return errno;

	return 0;
}
