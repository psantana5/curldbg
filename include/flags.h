#ifndef FLAGS_H
#define FLAGS_H

struct flag_info {
    const char *short_name;
    const char *long_name;
    const char *arg;
    const char *desc;
    const char *category;
};

#define FLG(s, l, a, d, c) { (s), (l), (a), (d), (c) }

static const struct flag_info g_flags[] = {
    /* --- Request --- */
    FLG("-X",  "--request",       "<method>", "HTTP method (GET, POST, PUT, DELETE, PATCH, OPTIONS)", "Request"),
    FLG("-H",  "--header",        "<header>", "Add custom header", "Request"),
    FLG("-d",  "--data",          "<data>",   "Send POST/PUT data (@file, @-)", "Request"),
    FLG(NULL,  "--data-binary",   "<data>",   "Send binary POST data (@file)", "Request"),
    FLG(NULL,  "--data-urlencode","<data>",   "URL-encode and send data (name=content, @file)", "Request"),
    FLG("-T",  "--upload-file",   "<file>",   "Upload file via PUT (- for stdin)", "Request"),
    FLG("-u",  "--user",          "<user:pass>", "Basic authentication", "Request"),
    FLG("-A",  "--user-agent",    "<str>",    "Set User-Agent header", "Request"),
    FLG("-e",  "--referer",       "<url>",    "Set Referer header", "Request"),
    FLG("-b",  "--cookie",        "<data>",   "Send cookie data (@file to load)", "Request"),
    FLG("-c",  "--cookie-jar",    "<file>",   "Save cookies to Netscape-format file", "Request"),

    /* --- Output --- */
    FLG("-o",  "--output",        "<file>",   "Write response body to file", "Output"),
    FLG("-O",  "--remote-name",   NULL,       "Save body to remote filename", "Output"),
    FLG("-w",  "--write-out",     "<fmt>",    "Print format variables (%{http_code}, etc.)", "Output"),
    FLG("-s",  "--silent",        NULL,       "Silent mode", "Output"),
    FLG("-S",  "--show-error",    NULL,       "Show error even with -s", "Output"),
    FLG("-v",  "--verbose",       NULL,       "Verbose request/response headers", "Output"),
    FLG("-I",  "--head",          NULL,       "Fetch headers only (HEAD request)", "Output"),

    /* --- Redirect --- */
    FLG("-L",  "--location",      NULL,       "Follow redirects", "Redirect"),
    FLG(NULL,  "--max-redirs",    "<n>",      "Maximum redirects (default 10)", "Redirect"),
    FLG("-f",  "--fail",          NULL,       "Fail on HTTP errors (4xx, 5xx)", "Redirect"),

    /* --- Network --- */
    FLG("-4",  NULL,              NULL,       "Force IPv4", "Network"),
    FLG("-6",  NULL,              NULL,       "Force IPv6", "Network"),
    FLG(NULL,  "--connect-timeout","<ms>",    "Connection timeout in milliseconds", "Network"),
    FLG(NULL,  "--read-timeout",  "<ms>",     "Read timeout in milliseconds", "Network"),
    FLG(NULL,  "--max-time",      "<ms>",     "Maximum total time in milliseconds", "Network"),
    FLG(NULL,  "--retry",         "<n>",      "Retry on failure", "Network"),
    FLG(NULL,  "--retry-delay",   "<s>",      "Delay between retries in seconds", "Network"),
    FLG(NULL,  "--no-happy-eyeballs", NULL,   "Disable Happy Eyeballs (RFC 8305)", "Network"),
    FLG(NULL,  "--resolve",       "<host:port:ip>", "Custom DNS resolution", "Network"),
    FLG(NULL,  "--interface",     "<addr>",   "Bind to specific interface or IP", "Network"),
    FLG(NULL,  "--proxy",         "<url>",    "HTTP CONNECT proxy (http:// only)", "Network"),
    FLG(NULL,  "--unix-socket",   "<path>",   "Connect via Unix domain socket", "Network"),

    /* --- TLS --- */
    FLG("-k",  "--insecure",      NULL,       "Skip TLS certificate verification", "TLS"),
    FLG(NULL,  "--cacert",        "<file>",   "Custom CA certificate file", "TLS"),
    FLG(NULL,  "--capath",        "<dir>",    "Custom CA certificate directory", "TLS"),
    FLG(NULL,  "--tlsv1.2",       NULL,       "Force TLS v1.2", "TLS"),
    FLG(NULL,  "--tlsv1.3",       NULL,       "Force TLS v1.3", "TLS"),

    /* --- Compression --- */
    FLG(NULL,  "--compressed",    NULL,       "Request compressed response (gzip/deflate)", "Compression"),

    /* --- Comparison --- */
    FLG(NULL,  "--compare",       NULL,       "Compare IPv4 vs IPv6 for the same URL", "Comparison"),
    FLG(NULL,  "--compare-urls",  NULL,       "Compare two different URLs (A vs B)", "Comparison"),

    /* --- Other --- */
    FLG("-h",  "--help",          NULL,       "Show this help", "Other"),
    FLG(NULL,  "--version",       NULL,       "Print version", "Other"),
    FLG(NULL,  "--progress-bar",  NULL,       "Progress bar (no-op, for curl compat)", "Other"),

    { NULL, NULL, NULL, NULL, NULL }
};

#undef FLG

#endif
