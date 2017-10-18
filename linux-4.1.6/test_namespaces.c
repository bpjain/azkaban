#define _GNU_SOURCE
#include <sys/wait.h>
#include <sys/utsname.h>
#include <sched.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/sched.h>

#define errExit(msg)    do { perror(msg); exit(EXIT_FAILURE); \
} while (0)

static int              /* Start function for cloned child */
childFunc(void *arg)
{
    printf("Child called\n");
    while(1);
    return 0;           /* Child terminates now */
}

#define STACK_SIZE (1024 * 1024)    /* Stack size for cloned child */

int
main(int argc, char *argv[])
{
    char *stack;                    /* Start of stack buffer */
    char *stackTop;                 /* End of stack buffer */
    pid_t pid;
    char arg[5];

    /* Allocate stack for child */

    stack = malloc(STACK_SIZE);
    if (stack == NULL)
        errExit("malloc");
    stackTop = stack + STACK_SIZE;  /* Assume stack grows downward */

    /* Create child that has its own UTS namespace;
       child commences execution in childFunc() */

    pid = clone(childFunc, stackTop,
            CLONE_NEWMEM | CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWIPC |
            CLONE_NEWNET | CLONE_NEWUTS | SIGCHLD,
            (void *) arg);
    if (pid == -1)
        errExit("clone");

    /* Parent falls through to here */

    if (waitpid(pid, NULL, 0) == -1)    /* Wait for child */
        errExit("waitpid");

    exit(EXIT_SUCCESS);
}

