#include <sys/syscall.h>
.global _start

#if defined(__x86_64__)
.intel_syntax noprefix

.text
_start:
    mov rdi, 123        # exit status
    mov rax, SYS_exit
    syscall
#elif defined(__arm__)
.text
_start:
    mov r0, 123        # exit status
    mov r7, SYS_exit
    syscall
#elif defined(__aarch64__)
.text
_start:
    mov x0, 123        # exit status
    mov x8, SYS_exit
    syscall
#endif
