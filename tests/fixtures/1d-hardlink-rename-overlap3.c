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
       
    // Create /x and /a
    FILE *f = fopen("/x", "w");
    if (f == NULL) return errno;
    fprintf(f, "TEST1");
    fclose(f);

    FILE *f2 = fopen("/a", "w");
    if (f2 == NULL) return errno;
    fprintf(f2, "TEST2");
    fclose(f2);

    retval = link("/x", "/y");
    if (retval < 0) return errno;

    retval = rename("/y", "/a");
    if (retval < 0) return errno;

	return 0;
}
