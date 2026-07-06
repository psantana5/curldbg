#include "route.h"

#include <arpa/inet.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static volatile sig_atomic_t running = 1;

static void on_signal(int sig) {
    (void)sig;
    running = 0;
}

int main(void) {
    struct sigaction sa = { .sa_handler = on_signal, .sa_flags = 0 };
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return 1; }

    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_port = 0; /* ephemeral */

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind"); return 1;
    }
    if (listen(fd, 4) < 0) { perror("listen"); return 1; }

    struct sockaddr_in bound;
    socklen_t bound_len = sizeof(bound);
    getsockname(fd, (struct sockaddr *)&bound, &bound_len);
    printf("%d\n", ntohs(bound.sin_port));
    fflush(stdout);

    while (running) {
        struct sockaddr_in client;
        socklen_t client_len = sizeof(client);
        int conn = accept(fd, (struct sockaddr *)&client, &client_len);
        if (conn < 0) {
            if (!running) break;
            continue;
        }
        struct request req;
        if (route_parse(conn, &req) == 0)
            route_dispatch(conn, &req);
        close(conn);
    }

    close(fd);
    return 0;
}
