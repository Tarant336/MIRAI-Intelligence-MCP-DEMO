/*
 * Intentionally vulnerable fixture for MIRAI deep validation (§4, §5).
 * Built with documented ground truth; never executed.
 *
 * GROUND TRUTH (expected detections):
 *   V1 CWE-121 stack buffer overflow  -> copy_payload()  : strcpy(dst, src), dst[64], src attacker-controlled
 *   V2 CWE-78  OS command injection   -> run_diag()     : system(cmd) where cmd embeds user input
 *   V3 CWE-134 format string          -> log_message()  : printf(user_buf)
 *   V4 CWE-787 out-of-bounds write    -> fill_buffer()  : memcpy(dst, src, len) with unchecked len
 *   F1 fuzz target (input boundary)   -> handle_request(): recv() into fixed buffer then copy_payload()
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>

static char *g_last;

/* V1: stack buffer overflow */
void copy_payload(const char *src) {
    char dst[64];
    strcpy(dst, src);
    printf("payload=%s\n", dst);
}

/* V2: OS command injection */
void run_diag(const char *host) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "ping -c 1 %s", host);
    system(cmd);
}

/* V3: format string */
void log_message(const char *user_buf) {
    printf(user_buf);
}

/* V4: unchecked memcpy length */
void fill_buffer(const char *src, size_t len) {
    char dst[128];
    memcpy(dst, src, len);
    g_last = dst;
}

/* F1: network input boundary feeding V1 */
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