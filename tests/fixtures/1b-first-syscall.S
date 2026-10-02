#include <asm/unistd.h>
.global _start

#if defined(__x86_64__)
.intel_syntax noprefix

.text
_start:
    mov rdi, 123
    mov rax, __NR_exit
    syscall
#elif defined(__arm__)
.text
_start:
    mov r0, #123
    mov r7, __NR_exit
    swi #0
#elif defined(__aarch64__)
.text
_start:
    mov x0, #123
    mov x8, __NR_exit
    svc #0
#endif
