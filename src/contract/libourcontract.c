#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include <linux/limits.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "ourcontract.h"

/* entry of call stack */
typedef struct _frame {
    const char *name;
    FILE *out_fp;
    int state_fd;
    int depth;
    struct _frame *parent;
} frame;

/* call stack */
static frame *curr_frame = NULL;

static void push(const char *name)
{
    frame *new = malloc(sizeof(frame));

    if (new == NULL) {
        err_printf("push: malloc failed\n");
        exit(EXIT_FAILURE);
    }

    new->name = name;
    new->out_fp = NULL;
    new->state_fd = -1;
    if (curr_frame == NULL) new->depth = 1;
    else new->depth = curr_frame->depth + 1;

    new->parent = curr_frame;
    curr_frame = new;
}

static void pop()
{
    if (curr_frame == NULL) {
        err_printf("pop: call stack is empty\n");
        exit(EXIT_FAILURE);
    }

    frame *bye = curr_frame;
    if (bye->out_fp != NULL) fclose(bye->out_fp);
    if (bye->state_fd != -1) close(bye->state_fd);
    curr_frame = curr_frame->parent;
    free(bye);
}

/* argv of ourcontract-rt */
static int runtime_argc;
static char **runtime_argv = NULL;

static inline const char *get_contracts_dir()
{
    return runtime_argv[1];
}

int start_runtime(int argc, char **argv)
{
    if (runtime_argv != NULL) {
        err_printf("start_runtime: cannot be called more than once\n");
        return EXIT_FAILURE;
    }

    runtime_argc = argc;
    runtime_argv = argv;

    if (argc < 3) {
        err_printf("usage: ourcontract-rt [CONTRACTS DIR] [CONTRACT] [ARG 1] [ARG 2] ...\n");
        return EXIT_FAILURE;
    }

    return call_contract(argv[2], argc - 2, argv + 2);
}

int call_contract(const char *contract, int argc, char **argv)
{
    char filename[PATH_MAX];
    if (snprintf(filename, PATH_MAX, "%s/%s/code.so", get_contracts_dir(), contract) >= PATH_MAX) {
        err_printf("call_contract: path too long\n");
        return EXIT_FAILURE;
    }

    void *handle = dlopen(filename, RTLD_LAZY);
    if (handle == NULL) {
        err_printf("call_contract: dlopen failed\n");
        return EXIT_FAILURE;
    }

    int (*contract_main)(int, char **) = dlsym(handle, "contract_main");
    if (contract_main == NULL) {
        err_printf("call_contract: %s\n", dlerror());
        return EXIT_FAILURE;
    }

    push(contract);
    int ret = contract_main(argc, argv);
    pop();

    dlclose(handle);
    return ret;
}

int err_printf(const char *format, ...)
{
    va_list args;
    int ret;

    va_start(args, format);
    ret = vfprintf(stderr, format, args);

    va_end(args);
    return ret;
}

int str_printf(char *str, unsigned size, const char *format, ...)
{
    va_list args;
    int ret;

    va_start(args, format);
    ret = vsnprintf(str, size, format, args);

    va_end(args);
    return ret;
}

int str_cmp(const char *s1, const char *s2, int n)
{
    return strncmp(s1, s2, n);
}

static int out_open(const char *mode)
{
    char filename[PATH_MAX];
    if (snprintf(filename, PATH_MAX, "%s/%s/out",
                 get_contracts_dir(), curr_frame->name) >= PATH_MAX) {
        err_printf("out_open: path too long\n");
        return -1;
    }

    curr_frame->out_fp = fopen(filename, mode);
    if (curr_frame->out_fp == NULL) {
        err_printf("out_open: fopen failed\n");
        return -1;
    }

    return 0;
}

static int out_close()
{
    if (fclose(curr_frame->out_fp) == EOF) {
        err_printf("out_close: fclose failed\n");
        return -1;
    }
    return 0;
}

int out_printf(const char *format, ...)
{
    if (curr_frame->out_fp == NULL) {
        if (out_open("a") == -1) return -1;
    }

    va_list args;
    int ret;

    va_start(args, format);
    ret = vfprintf(curr_frame->out_fp, format, args);

    va_end(args);
    return ret;
}

int out_clear()
{
    if (curr_frame->out_fp != NULL) {
        if (out_close() == -1) return -1;
    }

    if (out_open("w") == -1) return -1;
    return 0;
}

static int state_open(int flags)
{
    char filename[PATH_MAX];
    if (snprintf(filename, PATH_MAX, "%s/%s/state",
                 get_contracts_dir(), curr_frame->name) >= PATH_MAX) {
        err_printf("state_open: path too long\n");
        return -1;
    }

    curr_frame->state_fd = open(filename, flags, 0664);
    if (curr_frame->state_fd == -1) {
        err_printf("state_open: open failed\n");
        return -1;
    }

    return 0;
}

static int state_close()
{
    if (close(curr_frame->state_fd) == -1) {
        err_printf("state_close: close failed\n");
        return -1;
    }
    return 0;
}

int state_read(void *buf, int count)
{
    if (curr_frame->state_fd == -1) {
        if (state_open(O_RDONLY) == -1) return -1;
    } else if ((fcntl(curr_frame->state_fd, F_GETFL) & O_ACCMODE) != O_RDONLY) {
        if (state_close() == -1) return -1;
        if (state_open(O_RDONLY) == -1) return -1;
    }

    return read(curr_frame->state_fd, buf, count);
}

int state_write(const void *buf, int count)
{
    if (curr_frame->state_fd == -1) {
        if (state_open(O_WRONLY | O_CREAT) == -1) return -1;
    } else if ((fcntl(curr_frame->state_fd, F_GETFL) & O_ACCMODE) != O_WRONLY) {
        if (state_close() == -1) return -1;
        if (state_open(O_WRONLY | O_CREAT) == -1) return -1;
    }

    return write(curr_frame->state_fd, buf, count);
}

int test_libsnark(int input_x) {
    char *libPath;
    libPath = getenv("OURZKLIB");

    void *handle = dlopen(libPath, RTLD_LAZY);
    if (handle == NULL) {
        err_printf("test_libsnark: dlopen failed\n");
        return EXIT_FAILURE;
    }

    int (*call_function)(int) = dlsym(handle, "test_libsnark");
    if (call_function == NULL) {
        err_printf("test_libsnark: %s\n", dlerror());
        return EXIT_FAILURE;
    }

    push("test_libsnark");
    int ret = call_function(input_x);
    pop();

    dlclose(handle);
    return ret;
}

int vote_zk_init(void) {
	char *libPath;
    libPath = getenv("OURZKLIB");

    void *handle = dlopen(libPath, RTLD_LAZY);
    if (handle == NULL) {
        err_printf("vote_zk_init: dlopen failed\n");
        return EXIT_FAILURE;
    }

    void (*call_function)(char*, char*) = dlsym(handle, "vote_zk_init");
    if (call_function == NULL) {
        err_printf("vote_zk_init: %s\n", dlerror());
        return EXIT_FAILURE;
    }

    char proving_key_filename[PATH_MAX];
    if (snprintf(proving_key_filename, PATH_MAX, "%s/%s/proving_key",
                 get_contracts_dir(), curr_frame->name) >= PATH_MAX) {
        err_printf("state_open: path too long\n");
        return -1;
    }

    char verify_key_filename[PATH_MAX];
    if (snprintf(verify_key_filename, PATH_MAX, "%s/%s/verify_key",
                 get_contracts_dir(), curr_frame->name) >= PATH_MAX) {
        err_printf("state_open: path too long\n");
        return -1;
    }

    push("vote_zk_init");
    call_function(proving_key_filename, verify_key_filename);
    pop();

    dlclose(handle);
    return 0;
}

int vote_zk_verify(void) {
	char *libPath;
    libPath = getenv("OURZKLIB");

    void *handle = dlopen(libPath, RTLD_LAZY);
    if (handle == NULL) {
        err_printf("vote_zk_verify: dlopen failed\n");
        return EXIT_FAILURE;
    }

    int (*call_function)(char*, char*) = dlsym(handle, "vote_zk_verify");
    if (call_function == NULL) {
        err_printf("vote_zk_verify: %s\n", dlerror());
        return EXIT_FAILURE;
    }

    char proof_filename[PATH_MAX];
    if (snprintf(proof_filename, PATH_MAX, "%s/%s/proof",
                 get_contracts_dir(), curr_frame->name) >= PATH_MAX) {
        err_printf("state_open: path too long\n");
        return -1;
    }

    char verify_key_filename[PATH_MAX];
    if (snprintf(verify_key_filename, PATH_MAX, "%s/%s/verify_key",
                 get_contracts_dir(), curr_frame->name) >= PATH_MAX) {
        err_printf("state_open: path too long\n");
        return -1;
    }

    push("vote_zk_verify");
    int ret = call_function(verify_key_filename, proof_filename);
    pop();

    dlclose(handle);
    return ret;
}
