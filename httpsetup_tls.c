// httpsetup_tls.c
// HTTP/1.1 keep-alive server with per-connection login (isSigned) over TLS (OpenSSL).
//
// Build: cc -O2 -pthread -Wall -Wextra -o httpsetup_tls httpsetup_tls.c -lssl -lcrypto
// Run:   ./httpsetup_tls 8443 server.crt server.key
// Test:  https://localhost:8443/login
//
// Notes:
// - This is a TLS wrapper of the previous keep-alive server.
// - Replaces send()/recv() with SSL_write()/SSL_read().
// - Disables sendfile() (TLS can't use it). Uses read() + SSL_write() streaming.
// - Timeout via SO_RCVTIMEO still applies to the underlying socket; we map SSL errors to failure.
// - isSigned remains per-connection (per TCP/TLS session).
// - For multi-connection sign-in, add cookie sessions later.

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#ifndef BUFFER_SIZE
#define BUFFER_SIZE (128 * 1024)
#define CERT_FILE "server.crt"
#define KEY_FILE  "server.key"
#endif

// ---------- small utils ----------
static void die(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    exit(1);
}

static char *strcasestr_local(const char *haystack, const char *needle) {
    if (!*needle) return (char*)haystack;
    for (; *haystack; ++haystack) {
        if (tolower((unsigned char)*haystack) == tolower((unsigned char)*needle)) {
            const char *h = haystack, *n = needle;
            while (*h && *n && tolower((unsigned char)*h) == tolower((unsigned char)*n)) { ++h; ++n; }
            if (!*n) return (char*)haystack;
        }
    }
    return NULL;
}

static char hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}

static char *url_decode(const char *s) {
    size_t len = strlen(s);
    char *out = malloc(len + 1);
    if (!out) return NULL;
    char *o = out;
    for (size_t i = 0; i < len; ++i) {
        if (s[i] == '+') { *o++ = ' '; }
        else if (s[i] == '%' && i + 2 < len) {
            char h1 = hexval(s[i+1]), h2 = hexval(s[i+2]);
            if (h1 >= 0 && h2 >= 0) { *o++ = (char)((h1 << 4) | h2); i += 2; }
            else { *o++ = s[i]; }
        } else { *o++ = s[i]; }
    }
    *o = '\0';
    return out;
}

static const char *get_file_extension(const char *path) {
    const char *dot = strrchr(path, '.');
    if (!dot || dot == path) return "";
    return dot + 1;
}

static const char *get_mime_type(const char *ext) {
    if (!ext) return "application/octet-stream";
    if (!strcasecmp(ext, "html") || !strcasecmp(ext, "htm")) return "text/html; charset=utf-8";
    if (!strcasecmp(ext, "css")) return "text/css; charset=utf-8";
    if (!strcasecmp(ext, "js")) return "application/javascript; charset=utf-8";
    if (!strcasecmp(ext, "json")) return "application/json; charset=utf-8";
    if (!strcasecmp(ext, "png")) return "image/png";
    if (!strcasecmp(ext, "jpg") || !strcasecmp(ext, "jpeg")) return "image/jpeg";
    if (!strcasecmp(ext, "gif")) return "image/gif";
    if (!strcasecmp(ext, "svg")) return "image/svg+xml";
    if (!strcasecmp(ext, "ico")) return "image/x-icon";
    if (!strcasecmp(ext, "txt")) return "text/plain; charset=utf-8";
    if (!strcasecmp(ext, "pdf")) return "application/pdf";
    return "application/octet-stream";
}

// ---------- TLS IO helpers ----------
static int ssl_write_all(SSL *ssl, const void *buf, size_t len) {
    const unsigned char *p = (const unsigned char*)buf;
    while (len > 0) {
        int n = SSL_write(ssl, p, (int)len);
        if (n <= 0) {
            int err = SSL_get_error(ssl, n);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) continue;
            return -1;
        }
        p += n; len -= (size_t)n;
    }
    return 0;
}

static int ssl_read_some(SSL *ssl, void *buf, size_t cap) {
    int n = SSL_read(ssl, buf, (int)cap);
    if (n <= 0) {
        int err = SSL_get_error(ssl, n);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) return 0; // try again
        return -1; // closed/error
    }
    return n;
}

// ---------- HTTP helpers ----------
static ssize_t read_http_request_tls(SSL *ssl, char *buf, size_t cap, int timeout_sec, long *out_content_len) {
    (void)timeout_sec; // underlying socket timeout still applies
    if (out_content_len) *out_content_len = 0;

    size_t used = 0;
    while (used + 1 < cap) {
        int n = ssl_read_some(ssl, buf + used, cap - used - 1);
        if (n < 0) return -1;
        if (n == 0) continue; // WANT_READ/WRITE
        used += (size_t)n;
        buf[used] = '\0';
        char *hdr_end = strstr(buf, "\r\n\r\n");
        if (hdr_end) {
            size_t header_len = (size_t)(hdr_end + 4 - buf);
            long content_len = 0;
            const char *cl = strcasestr_local(buf, "\r\nContent-Length:");
            if (cl) content_len = strtol(cl + 17, NULL, 10);
            if (out_content_len) *out_content_len = content_len;

            size_t need = header_len + (size_t)((content_len > 0) ? content_len : 0);
            while (used < need && used + 1 < cap) {
                n = ssl_read_some(ssl, buf + used, cap - used - 1);
                if (n < 0) return -1;
                if (n == 0) continue;
                used += (size_t)n;
                buf[used] = '\0';
            }
            return (ssize_t)used;
        }
    }
    return -1; // too large
}

static int should_keep_alive(const char *req) {
    const char *ver = strstr(req, "HTTP/");
    int http11 = (ver && !strncmp(ver, "HTTP/1.1", 8));
    int conn_close = 0, conn_keep = 0;
    const char *p = req;
    while ((p = strcasestr_local(p, "\r\nConnection:")) != NULL) {
        p += 2;
        const char *line_end = strstr(p, "\r\n");
        if (!line_end) break;
        if (strcasestr_local(p, "close")) conn_close = 1;
        if (strcasestr_local(p, "keep-alive")) conn_keep = 1;
    }
    if (http11) return !conn_close;
    return conn_keep && !conn_close;
}

static int send_header_tls(SSL *ssl, int status, const char *status_text,
                       const char *content_type, long content_length,
                       int keep_alive, const char *extra_headers) {
    char header[4096];
    int n = snprintf(header, sizeof(header),
        "HTTP/1.1 %d %s\r\n"
        "Server: tinyka/1.3-tls\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %ld\r\n"
        "Connection: %s\r\n"
        "%s"
        "%s"
        "\r\n",
        status, status_text,
        content_type ? content_type : "text/plain; charset=utf-8",
        content_length,
        keep_alive ? "keep-alive" : "close",
        keep_alive ? "Keep-Alive: timeout=10, max=100\r\n" : "",
        extra_headers ? extra_headers : "");
    return ssl_write_all(ssl, header, (size_t)n);
}

static int send_simple_body_tls(SSL *ssl, const char *body) {
    return ssl_write_all(ssl, body, strlen(body));
}

static int send_simple_response_tls(SSL *ssl, int status, const char *status_text,
                                const char *content_type, const char *body,
                                int keep_alive, const char *extra_headers) {
    int body_len = (int)strlen(body);
    if (send_header_tls(ssl, status, status_text, content_type, body_len, keep_alive, extra_headers) < 0) return -1;
    return ssl_write_all(ssl, body, (size_t)body_len);
}

static int send_file_response_tls(SSL *ssl, const char *path, int keep_alive) {
    int f = open(path, O_RDONLY);
    if (f < 0) {
        return send_simple_response_tls(ssl, 404, "Not Found",
                                    "text/plain; charset=utf-8", "404 Not Found", keep_alive, NULL);
    }
    struct stat st;
    if (fstat(f, &st) < 0 || !S_ISREG(st.st_mode)) {
        close(f);
        return send_simple_response_tls(ssl, 404, "Not Found",
                                    "text/plain; charset=utf-8", "404 Not Found", keep_alive, NULL);
    }
    const char *ext  = get_file_extension(path);
    const char *mime = get_mime_type(ext);
    if (send_header_tls(ssl, 200, "OK", mime, (long)st.st_size, keep_alive, NULL) < 0) { close(f); return -1; }

    char buf[8192];
    ssize_t r;
    while ((r = read(f, buf, sizeof(buf))) > 0) {
        if (ssl_write_all(ssl, buf, (size_t)r) < 0) { close(f); return -1; }
    }
    close(f);
    return 0;
}

static int redirect_to_tls(SSL *ssl, const char *location, int keep) {
    char hdr[1024];
    snprintf(hdr, sizeof(hdr), "Location: %s\r\n", location);
    return send_simple_response_tls(ssl, 302, "Found",
                                "text/plain; charset=utf-8", "Redirecting...", keep, hdr);
}

// ---------- client handler ----------
struct client_arg {
    int fd;
    SSL_CTX *ctx;
};

static void *handle_client(void *argp) {
    struct client_arg *arg = (struct client_arg*)argp;
    int client_fd = arg->fd;
    SSL_CTX *ctx = arg->ctx;
    free(arg);

    int one = 1;
    setsockopt(client_fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

    SSL *ssl = SSL_new(ctx);
    if (!ssl) { close(client_fd); return NULL; }
    SSL_set_fd(ssl, client_fd);
    if (SSL_accept(ssl) <= 0) { SSL_free(ssl); close(client_fd); return NULL; }

    bool isSigned = false;
    char *reqbuf = malloc(BUFFER_SIZE);
    if (!reqbuf) { SSL_shutdown(ssl); SSL_free(ssl); close(client_fd); return NULL; }

    const char *expect_password = getenv("APP_PASSWORD");
    if (!expect_password) expect_password = "password";

    for (;;) {
        long content_len = 0;
        ssize_t req_len = read_http_request_tls(ssl, reqbuf, BUFFER_SIZE - 1, 30, &content_len);
        if (req_len <= 0) break;
        reqbuf[req_len] = '\0';

        int keep = should_keep_alive(reqbuf);

        char method[8] = {0}, uri[2048] = {0}, version[16] = {0};
        if (sscanf(reqbuf, "%7s %2047s %15s", method, uri, version) != 3) {
            if (send_simple_response_tls(ssl, 400, "Bad Request",
                                 "text/plain; charset=utf-8",
                                 "400 Bad Request", keep, NULL) < 0) break;
            if (!keep) break; else continue;
        }

        char *hdr_end = strstr(reqbuf, "\r\n\r\n");
        const char *body = hdr_end ? (hdr_end + 4) : "";

        if (!strcmp(uri, "/favicon.ico")) {
            send_file_response_tls(ssl, "favicon.ico", keep);
            if (!keep) break; else continue;
        }

        if (!strcmp(uri, "/login") && !strcasecmp(method, "GET")) {
            if (send_file_response_tls(ssl, "getpass.html", keep) < 0) {
                send_simple_response_tls(ssl, 500, "Internal Server Error",
                    "text/plain; charset=utf-8", "Missing getpass.html in working directory.\n", keep, NULL);
            }
            if (!keep) break; else continue;
        }

        if (!strcmp(uri, "/login") && !strcasecmp(method, "POST")) {
            int is_form = 0;
            const char *ctype = strcasestr_local(reqbuf, "\r\nContent-Type:");
            if (ctype) {
                const char *line_end = strstr(ctype + 2, "\r\n");
                size_t len = line_end ? (size_t)(line_end - (ctype + 15)) : strlen(ctype + 15);
                char *val = strndup(ctype + 15, len);
                if (val) {
                    for (char *q=val; *q; ++q) *q = tolower((unsigned char)*q);
                    if (strstr(val, "application/x-www-form-urlencoded")) is_form = 1;
                    free(val);
                }
            }
            if (!is_form) {
                send_simple_response_tls(ssl, 415, "Unsupported Media Type",
                    "text/plain; charset=utf-8", "Use application/x-www-form-urlencoded for /login", keep, NULL);
                if (!keep) break; else continue;
            }
            // Parse only pass= from x-www-form-urlencoded body
            char *pass = NULL;
            const char *p = body;
            while (*p) {
                const char *eq = strchr(p, '=');
                if (!eq) break;
                const char *amp = strchr(eq+1, '&');
                size_t key_len = (size_t)(eq - p);
                size_t val_len = amp ? (size_t)(amp - (eq+1)) : strlen(eq+1);
                char *key = strndup(p, key_len);
                char *val = strndup(eq+1, val_len);
                char *key_d = url_decode(key);
                char *val_d = url_decode(val);
                free(key); free(val);
                if (!strcasecmp(key_d, "pass")) { free(pass); pass = val_d; } else free(val_d);
                free(key_d);
                if (!amp) break;
                p = amp + 1;
            }

            int ok = (pass && strcmp(pass, expect_password) == 0);
            free(pass);
            if (ok) {
                isSigned = true;
                redirect_to_tls(ssl, "/", keep);
            } else {
                redirect_to_tls(ssl, "/login?error=1", keep);
            }
            if (!keep) break; else continue;
        }

        if (!isSigned) {
            if (send_file_response_tls(ssl, "getpass.html", keep) < 0) {
                send_simple_response_tls(ssl, 401, "Unauthorized",
                    "text/plain; charset=utf-8", "Unauthorized. Put getpass.html in this folder.\n", keep, NULL);
            }
            if (!keep) break; else continue;
        }

        int is_head = !strcasecmp(method, "HEAD");
        if (strcasecmp(method, "GET") && !is_head) {
            send_simple_response_tls(ssl, 405, "Method Not Allowed",
                                 "text/plain; charset=utf-8",
                                 "405 Method Not Allowed", keep, NULL);
            if (!keep) break; else continue;
        }

        const char *raw = (uri[0] == '/') ? uri + 1 : uri;
        if (strstr(raw, "..")) {
            send_simple_response_tls(ssl, 403, "Forbidden",
                                 "text/plain; charset=utf-8",
                                 "403 Forbidden", keep, NULL);
            if (!keep) break; else continue;
        }
        char *decoded = url_decode(raw);
        if (!decoded) {
            send_simple_response_tls(ssl, 500, "Internal Server Error",
                                 "text/plain; charset=utf-8",
                                 "500 Internal Server Error", keep, NULL);
            if (!keep) break; else continue;
        }

        char path[4096];
        if (decoded[0] == '\0') snprintf(path, sizeof(path), "index.html");
        else snprintf(path, sizeof(path), "%s", decoded);
        free(decoded);

        if (is_head) {
            struct stat st;
            if (stat(path, &st) == 0 && S_ISREG(st.st_mode)) {
                const char *ext = get_file_extension(path);
                const char *mime = get_mime_type(ext);
                send_header_tls(ssl, 200, "OK", mime, (long)st.st_size, keep, NULL);
            } else {
                send_simple_response_tls(ssl, 404, "Not Found",
                                     "text/plain; charset=utf-8",
                                     "404 Not Found", keep, NULL);
            }
        } else {
            if (send_file_response_tls(ssl, path, keep) < 0) {
                send_simple_response_tls(ssl, 404, "Not Found",
                                     "text/plain; charset=utf-8",
                                     "404 Not Found", keep, NULL);
            }
        }
        if (!keep) break;
    }

    free(reqbuf);
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(client_fd);
    return NULL;
}

void configure_context(SSL_CTX *context){
	if (SSL_CTX_use_certificate_file(context, CERT_FILE, SSL_FILETYPE_PEM) <= 0)
        die("Failed to load certificate %s", CERT_FILE);
    if (SSL_CTX_use_PrivateKey_file(context, KEY_FILE, SSL_FILETYPE_PEM) <= 0)
        die("Failed to load private key %s", KEY_FILE);
    if (!SSL_CTX_check_private_key(context))
        die("Certificate and key do not match");
}

// ---------- server bootstrap ----------
int main() {
    signal(SIGPIPE, SIG_IGN);
    /*if (argc < 4) {
        fprintf(stderr, "Usage: %s <port> <server.crt> <server.key>\n", argv[0]);
        return 1;
    }*/
    int port = 8080;
    

    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) die("SSL_CTX_new failed");

	configure_context(ctx);
    // Reasonable defaults
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION);

    

    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) die("socket: %s", strerror(errno));

    int yes = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons((uint16_t)port);

    if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0)
        die("bind: %s", strerror(errno));
    if (listen(s, 128) < 0)
        die("listen: %s", strerror(errno));

    printf("Serving HTTPS (login-gated) on 0.0.0.0:%d\n", port);
    printf("Use certificate: %s\n", CERT_FILE);
    printf("Password defaults to 'password' (override with APP_PASSWORD)\n");

    while (1) {
        struct sockaddr_in cli; socklen_t clilen = sizeof(cli);
        int c = accept(s, (struct sockaddr*)&cli, &clilen);
        if (c < 0) {
            if (errno == EINTR) continue;
            perror("accept"); continue;
        }
        struct client_arg *arg = malloc(sizeof(*arg));
        if (!arg) { close(c); continue; }
        arg->fd = c;
        arg->ctx = ctx;

        pthread_t th;
        if (pthread_create(&th, NULL, handle_client, arg) != 0) {
            perror("pthread_create"); close(c); free(arg); continue;
        }
        pthread_detach(th);
    }

    SSL_CTX_free(ctx);
    EVP_cleanup();
    return 0;
}
