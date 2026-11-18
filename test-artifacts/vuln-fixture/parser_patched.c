/*
 * PATCHED counterpart of parser.c (ground truth for patch-diff validation).
 * Every vulnerable construct from parser.c is replaced by a bounded/safe variant.
 *
 * Expected patch-diff signals vs parser.c:
 *   strcpy -> snprintf(buf, sizeof buf, ...)   (CWE-121 fixed)
 *   system  -> removed                         (CWE-78 fixed)
 *   printf(user_buf) -> printf("%s", user_buf) (CWE-134 fixed)
 *   memcpy(dst, src, len) -> if (len <= sizeof dst) memcpy(...) (CWE-787 fixed)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>

static char *g_last;

void copy_payload(const char *src) {
    char dst[64];
    snprintf(dst, sizeof(dst), "%s", src);
    printf("payload=%s\n", dst);
}

void run_diag(const char *host) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "ping -c 1 -- %s", host);
    (void)cmd; /* execution removed in the patched build */
}

void log_message(const char *user_buf) {
    printf("%s", user_buf);
}

void fill_buffer(const char *src, size_t len) {
    char dst[128];
    if (len > sizeof(dst)) {
        len = sizeof(dst);
    }
    memcpy(dst, src, len);
    g_last = dst;
}

void handle_request(int sock) {
    char buf[4096];
    ssize_t n = recv(sock, buf, sizeof(buf) - 1, 0);
    if (n > 0) {
        buf[n] = '\0';
        copy_payload(buf);
    }
}

int main(int argc, char **argv) {
    if (argc > 1) {
        copy_payload(argv[1]);
        run_diag(argv[1]);
        log_message(argv[1]);
        fill_buffer(argv[1], (size_t)atoi(argv[2] ? argv[2] : "0"));
    }
    return 0;
}