#ifndef FLAGS_H
#define FLAGS_H

enum flag_id {
    FLAG_NONE,
    FLAG_REQUEST,
    FLAG_HEADER,
    FLAG_DATA,
    FLAG_DATA_BINARY,
    FLAG_DATA_URLENCODE,
    FLAG_UPLOAD_FILE,
    FLAG_USER,
    FLAG_USER_AGENT,
    FLAG_REFERER,
    FLAG_COOKIE,
    FLAG_COOKIE_JAR,
    FLAG_OUTPUT,
    FLAG_REMOTE_NAME,
    FLAG_WRITE_OUT,
    FLAG_SILENT,
    FLAG_SHOW_ERROR,
    FLAG_VERBOSE,
    FLAG_HEAD,
    FLAG_LOCATION,
    FLAG_MAX_REDIRS,
    FLAG_FAIL,
    FLAG_IPV4,
    FLAG_IPV6,
    FLAG_CONNECT_TIMEOUT,
    FLAG_READ_TIMEOUT,
    FLAG_MAX_TIME,
    FLAG_RETRY,
    FLAG_RETRY_DELAY,
    FLAG_NO_HAPPY_EYEBALLS,
    FLAG_RESOLVE,
    FLAG_INTERFACE,
    FLAG_PROXY,
    FLAG_UNIX_SOCKET,
    FLAG_INSECURE,
    FLAG_CACERT,
    FLAG_CAPATH,
    FLAG_TLSV1_2,
    FLAG_TLSV1_3,
    FLAG_COMPRESSED,
    FLAG_COMPARE,
    FLAG_COMPARE_URLS,
    FLAG_HELP,
    FLAG_VERSION,
    FLAG_HTTP1_1,
    FLAG_HTTP2,
    FLAG_PROGRESS_BAR,
    FLAG_DISABLE,
    FLAG_PROTO,
};

struct flag_info {
    const char *short_name;
    const char *long_name;
    const char *arg;
    const char *desc;
    const char *category;
    enum flag_id id;
};

#define FLG(s, l, a, d, c, id) { (s), (l), (a), (d), (c), (id) }

static const struct flag_info g_flags[] = {
    FLG("-X",  "--request",       "<method>", "HTTP method (GET, POST, PUT, DELETE, PATCH, OPTIONS)", "Request", FLAG_REQUEST),
    FLG("-H",  "--header",        "<header>", "Add custom header", "Request", FLAG_HEADER),
    FLG("-d",  "--data",          "<data>",   "Send POST/PUT data (@file, @-)", "Request", FLAG_DATA),
    FLG(NULL,  "--data-binary",   "<data>",   "Send binary POST data (@file)", "Request", FLAG_DATA_BINARY),
    FLG(NULL,  "--data-urlencode","<data>",   "URL-encode and send data (name=content, @file)", "Request", FLAG_DATA_URLENCODE),
    FLG("-T",  "--upload-file",   "<file>",   "Upload file via PUT (- for stdin)", "Request", FLAG_UPLOAD_FILE),
    FLG("-u",  "--user",          "<user:pass>", "Basic authentication", "Request", FLAG_USER),
    FLG("-A",  "--user-agent",    "<str>",    "Set User-Agent header", "Request", FLAG_USER_AGENT),
    FLG("-e",  "--referer",       "<url>",    "Set Referer header", "Request", FLAG_REFERER),
    FLG("-b",  "--cookie",        "<data>",   "Send cookie data (@file to load)", "Request", FLAG_COOKIE),
    FLG("-c",  "--cookie-jar",    "<file>",   "Save cookies to Netscape-format file", "Request", FLAG_COOKIE_JAR),

    FLG("-o",  "--output",        "<file>",   "Write response body to file", "Output", FLAG_OUTPUT),
    FLG("-O",  "--remote-name",   NULL,       "Save body to remote filename", "Output", FLAG_REMOTE_NAME),
    FLG("-w",  "--write-out",     "<fmt>",    "Print format variables (%{http_code}, etc.)", "Output", FLAG_WRITE_OUT),
    FLG("-s",  "--silent",        NULL,       "Silent mode", "Output", FLAG_SILENT),
    FLG("-S",  "--show-error",    NULL,       "Show error even with -s", "Output", FLAG_SHOW_ERROR),
    FLG("-v",  "--verbose",       NULL,       "Verbose request/response headers", "Output", FLAG_VERBOSE),
    FLG("-I",  "--head",          NULL,       "Fetch headers only (HEAD request)", "Output", FLAG_HEAD),

    FLG("-L",  "--location",      NULL,       "Follow redirects", "Redirect", FLAG_LOCATION),
    FLG(NULL,  "--max-redirs",    "<n>",      "Maximum redirects (default 10)", "Redirect", FLAG_MAX_REDIRS),
    FLG("-f",  "--fail",          NULL,       "Fail on HTTP errors (4xx, 5xx)", "Redirect", FLAG_FAIL),

    FLG("-4",  NULL,              NULL,       "Force IPv4", "Network", FLAG_IPV4),
    FLG("-6",  NULL,              NULL,       "Force IPv6", "Network", FLAG_IPV6),
    FLG(NULL,  "--connect-timeout","<s>",     "Connection timeout in seconds", "Network", FLAG_CONNECT_TIMEOUT),
    FLG(NULL,  "--read-timeout",  "<ms>",     "Read timeout in milliseconds", "Network", FLAG_READ_TIMEOUT),
    FLG(NULL,  "--max-time",      "<s>",      "Maximum total time in seconds", "Network", FLAG_MAX_TIME),
    FLG(NULL,  "--retry",         "<n>",      "Retry on failure", "Network", FLAG_RETRY),
    FLG(NULL,  "--retry-delay",   "<s>",      "Delay between retries in seconds", "Network", FLAG_RETRY_DELAY),
    FLG(NULL,  "--no-happy-eyeballs", NULL,   "Disable Happy Eyeballs (RFC 8305)", "Network", FLAG_NO_HAPPY_EYEBALLS),
    FLG(NULL,  "--resolve",       "<host:port:ip>", "Custom DNS resolution", "Network", FLAG_RESOLVE),
    FLG(NULL,  "--interface",     "<addr>",   "Bind to specific interface or IP", "Network", FLAG_INTERFACE),
    FLG(NULL,  "--proxy",         "<url>",    "HTTP CONNECT proxy (http:// only)", "Network", FLAG_PROXY),
    FLG(NULL,  "--unix-socket",   "<path>",   "Connect via Unix domain socket", "Network", FLAG_UNIX_SOCKET),
    FLG(NULL,  "--http1.1",       NULL,       "Force HTTP/1.1", "Network", FLAG_HTTP1_1),
    FLG(NULL,  "--http2",         NULL,       "Force HTTP/2", "Network", FLAG_HTTP2),

    FLG("-k",  "--insecure",      NULL,       "Skip TLS certificate verification", "TLS", FLAG_INSECURE),
    FLG(NULL,  "--cacert",        "<file>",   "Custom CA certificate file", "TLS", FLAG_CACERT),
    FLG(NULL,  "--capath",        "<dir>",    "Custom CA certificate directory", "TLS", FLAG_CAPATH),
    FLG(NULL,  "--tlsv1.2",       NULL,       "Force TLS v1.2", "TLS", FLAG_TLSV1_2),
    FLG(NULL,  "--tlsv1.3",       NULL,       "Force TLS v1.3", "TLS", FLAG_TLSV1_3),

    FLG(NULL,  "--compressed",    NULL,       "Request compressed response (gzip/deflate)", "Compression", FLAG_COMPRESSED),

    FLG(NULL,  "--compare",       NULL,       "Compare IPv4 vs IPv6 for the same URL", "Comparison", FLAG_COMPARE),
    FLG(NULL,  "--compare-urls",  NULL,       "Compare two different URLs (A vs B)", "Comparison", FLAG_COMPARE_URLS),

    FLG("-h",  "--help",          NULL,       "Show this help", "Other", FLAG_HELP),
    FLG(NULL,  "--version",       NULL,       "Print version", "Other", FLAG_VERSION),
    FLG(NULL,  "--progress-bar",  NULL,       "Progress bar (no-op, for curl compat)", "Other", FLAG_PROGRESS_BAR),
    FLG("-q",  "--disable",       NULL,       "Disable .curlrc (no-op, for curl compat)", "Other", FLAG_DISABLE),
    FLG(NULL,  "--proto",         "<protocols>", "Protocols to use (no-op, for curl compat)", "Other", FLAG_PROTO),

    { NULL, NULL, NULL, NULL, NULL, FLAG_NONE }
};

#undef FLG

#endif
