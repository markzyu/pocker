#include <errno.h>
#include <stdio.h>
#include <unistd.h>

int main() {
	int result;
	result = setuid(0);
	printf("result: %d errno: %d\n", result, errno);

	result = getuid();
	printf("newuid: %d.\n", result);
	return 0;
}
