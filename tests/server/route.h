#ifndef TESTD_ROUTE_H
#define TESTD_ROUTE_H

#include <stddef.h>

#define REQ_BUF_MAX  65536
#define REQ_PATH_MAX 2048

struct request {
    char  method[8];
    char  path[REQ_PATH_MAX];
    int   minor_version;
};

struct route {
    const char *method;
    const char *path;
    void (*handler)(int fd, const struct request *req);
};

int  route_parse(int fd, struct request *req);
void route_dispatch(int fd, const struct request *req);

#endif
