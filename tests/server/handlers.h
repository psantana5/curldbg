#ifndef TESTD_HANDLERS_H
#define TESTD_HANDLERS_H

#include "route.h"

void handle_root(int fd, const struct request *req);
void handle_404(int fd, const struct request *req);
void handle_500(int fd, const struct request *req);
void handle_redirect_prefixed(int fd, const struct request *req);
void handle_redirect_loop(int fd, const struct request *req);
void handle_chunked(int fd, const struct request *req);
void handle_bad_chunk(int fd, const struct request *req);
void handle_gzip(int fd, const struct request *req);
void handle_cookies(int fd, const struct request *req);
void handle_lf_only(int fd, const struct request *req);
void handle_double_cl(int fd, const struct request *req);
void handle_negative_cl(int fd, const struct request *req);
void handle_slow_header(int fd, const struct request *req);
void handle_slow_body(int fd, const struct request *req);
void handle_partial_body(int fd, const struct request *req);
void handle_close_after_headers(int fd, const struct request *req);
void handle_large_header(int fd, const struct request *req);
void handle_empty_response(int fd, const struct request *req);
void handle_premature_close(int fd, const struct request *req);
void handle_infinite_redirect(int fd, const struct request *req);
void handle_echo(int fd, const struct request *req);

#endif
