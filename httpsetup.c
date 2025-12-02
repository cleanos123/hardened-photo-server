// httpsetup_tls_raw.c
// Minimal HTTPS server with login, static files, and RAW upload endpoint.
// - RAW upload: POST /upload-raw
//   * Content-Type: application/octet-stream
//   * X-Filename: <desired name>
//   * Body: exactly Content-Length bytes of the file
//
// Build:  cc -O2 -pthread -Wall -Wextra -o httpsetup_tls httpsetup_tls_raw.c -lssl -lcrypto
// Run:    ./httpsetup_tls
/* Test:   curl -k -X POST https://localhost:8080/upload-raw \
//           -H "Content-Type: application/octet-stream" \
//           -H "X-Filename: test.jpg" \
//           --data-binary @test.jpg
*/
// Notes:
// - Self-signed cert/key files "server.crt" and "server.key" must exist in cwd.
// - Login is per-connection; default password is "password" (override with APP_PASSWORD).
// - Files are written to /photos/<sanitized-filename> (directory must exist and be writable).

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <ctype.h>
#include <setjmp.h>
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
#include <dirent.h>
#include <jpeglib.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#ifndef PORT
#define PORT 443
#endif

#define PHOTOS_DIR "/mnt/newdisk/photos"
#ifndef BUFFER_SIZE
#define BUFFER_SIZE (128 * 1024)
#endif

#ifndef CERT_FILE
#define CERT_FILE "server.crt"
#endif

#ifndef KEY_FILE
#define KEY_FILE "server.key"
#endif

#ifndef MAX_UPLOAD
#define MAX_UPLOAD (200 * 1024 * 1024)
#endif

// ---------- small utils ----------
static void die(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    exit(1);
}

struct my_jpeg_error {
    struct jpeg_error_mgr pub;   // "public" fields (must be first)
    jmp_buf setjmp_buffer;
};

static void my_jpeg_error_exit(j_common_ptr cinfo)
{
    struct my_jpeg_error *myerr = (struct my_jpeg_error *) cinfo->err;
	
    // Optional: still print the libjpeg error message
    (*cinfo->err->output_message)(cinfo);

    // Jump back to the setjmp point in sanitize_jpeg()
    longjmp(myerr->setjmp_buffer, 1);
}

static void my_emit_message(j_common_ptr cinfo, int msg_level)
{
    struct my_jpeg_error *myerr = (struct my_jpeg_error *) cinfo->err;

    // Print the warning/error message
    (*cinfo->err->output_message)(cinfo);

    if (msg_level < 0) {
        // libjpeg uses msg_level < 0 for warnings
        longjmp(myerr->setjmp_buffer, 1);
    }
    // msg_level >= 0 are trace/debug, ignore if you like
}

// ---------- async logger ----------

struct log_item {
    char *msg;
    struct log_item *next;
};

static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  log_cond  = PTHREAD_COND_INITIALIZER;
static struct log_item *log_head = NULL;
static struct log_item *log_tail = NULL;
static int log_done = 0; // set to 1 if you ever want to cleanly stop the logger

static void enqueue_log(const char *s) {
    struct log_item *item = malloc(sizeof(*item));
    if (!item) return;
    item->msg = strdup(s);
    if (!item->msg) { free(item); return; }
    item->next = NULL;

    pthread_mutex_lock(&log_mutex);
    if (log_tail) log_tail->next = item;
    else          log_head = item;
    log_tail = item;
    pthread_cond_signal(&log_cond);
    pthread_mutex_unlock(&log_mutex);
}

// Public logging function: call this from any thread.
void log_msg(const char *fmt, ...) {
    char buf[1024];

    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    // Optionally add timestamp here if you like:
    time_t now = time(NULL);
    struct tm tm;
    localtime_r(&now, &tm);
    char tbuf[64];
    strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S", &tm);
    char line[1152];
    snprintf(line, sizeof(line), "[%s] %s", tbuf, buf);
    enqueue_log(line);
    enqueue_log(buf);
}

static void *logger_thread(void *arg) {
    (void)arg;

    FILE *f = fopen("server.log", "a");
    if (!f) f = stderr;

    pthread_mutex_lock(&log_mutex);
    for (;;) {
        while (!log_head && !log_done)
            pthread_cond_wait(&log_cond, &log_mutex);

        if (log_done && !log_head)
            break;

        struct log_item *item = log_head;
        log_head = item->next;
        if (!log_head) log_tail = NULL;

        pthread_mutex_unlock(&log_mutex);

        fprintf(f, "%s\n", item->msg);
        fflush(f);

        free(item->msg);
        free(item);

        pthread_mutex_lock(&log_mutex);
    }
    pthread_mutex_unlock(&log_mutex);

    if (f != stderr)
        fclose(f);
    return NULL;
}

// --- image helpers ---

// Return 0 = unknown/unsupported, 1 = JPEG
static int sniff_image_type(const char *path) {
    unsigned char buf[16];
    int fd = open(path, O_RDONLY);
    if (fd < 0) return 0;
    ssize_t n = read(fd, buf, sizeof(buf));
    close(fd);
    if (n < 3) return 0;

    // JPEG magic: FF D8 FF
    if (buf[0] == 0xFF && buf[1] == 0xD8 && buf[2] == 0xFF)
        return 1;

    // later you can add PNG/WebP/etc
    return 0;
}

/* Re-encode a JPEG with libjpeg, dropping all metadata.
 * Returns 0 on success, -1 on error.
 */
static int sanitize_jpeg(const char *inpath, const char *outpath) {
    FILE *in = NULL;
    FILE *out = NULL;
    struct jpeg_decompress_struct dinfo;
    struct jpeg_compress_struct   cinfo;
    struct my_jpeg_error jerr;
    int got_decompress = 0;
    int got_compress   = 0;
    int rc = -1;  // assume failure

    in = fopen(inpath, "rb");
    if (!in) return -1;

    // Set up error handler *before* any other libjpeg calls
    dinfo.err = jpeg_std_error(&jerr.pub);
	jerr.pub.error_exit  = my_jpeg_error_exit;
	jerr.pub.emit_message = my_emit_message;


    if (setjmp(jerr.setjmp_buffer)) {
        // Any libjpeg fatal error jumps here
        if (got_compress)   jpeg_destroy_compress(&cinfo);
        if (got_decompress) jpeg_destroy_decompress(&dinfo);
        if (in)  fclose(in);
        if (out) { fclose(out); unlink(outpath); }
        return -1;
    }

    // ---- Decompress side ----
    jpeg_create_decompress(&dinfo);
    got_decompress = 1;

    jpeg_stdio_src(&dinfo, in);

    if (jpeg_read_header(&dinfo, TRUE) != JPEG_HEADER_OK) {
        // will hit setjmp cleanup via longjmp if libjpeg dies inside
        goto done;
    }

    // Decode to RGB
    dinfo.out_color_space = JCS_RGB;
    jpeg_start_decompress(&dinfo);

    int w  = (int)dinfo.output_width;
    int h  = (int)dinfo.output_height;
    int ch = (int)dinfo.output_components;   // should be 3

    JSAMPARRAY buffer = (*dinfo.mem->alloc_sarray)
        ((j_common_ptr)&dinfo, JPOOL_IMAGE, (JDIMENSION)(w * ch), 1);

    out = fopen(outpath, "wb");
    if (!out) {
        goto done;
    }

    // ---- Compress side ----
    cinfo.err = jpeg_std_error(&jerr.pub);
	jerr.pub.error_exit  = my_jpeg_error_exit;
	jerr.pub.emit_message = my_emit_message;


    jpeg_create_compress(&cinfo);
    got_compress = 1;

    jpeg_stdio_dest(&cinfo, out);

    cinfo.image_width      = w;
    cinfo.image_height     = h;
    cinfo.input_components = ch;
    cinfo.in_color_space   = JCS_RGB;

    jpeg_set_defaults(&cinfo);
    jpeg_set_quality(&cinfo, 85, TRUE); // adjust as you like

    jpeg_start_compress(&cinfo, TRUE);

    while (dinfo.output_scanline < dinfo.output_height) {
        jpeg_read_scanlines(&dinfo, buffer, 1);
        jpeg_write_scanlines(&cinfo, buffer, 1);
    }

    jpeg_finish_compress(&cinfo);
    jpeg_finish_decompress(&dinfo);

    rc = 0;  // success

done:
    if (got_compress)   jpeg_destroy_compress(&cinfo);
    if (got_decompress) jpeg_destroy_decompress(&dinfo);

    if (in)  fclose(in);
    if (out) fclose(out);

    if (rc != 0) {
        // delete partial output on failure
        unlink(outpath);
    }

    return rc;
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

// keep only [A-Za-z0-9._-], strip directories
static void sanitize_filename(char *s) {
    char *p = s, *w = s;
    const char *ls = strrchr(s, '/'), *lb = strrchr(s, '\\');
    if (ls && (!lb || ls > lb)) p = (char*)ls + 1;
    else if (lb) p = (char*)lb + 1;
    if (p != s) memmove(s, p, strlen(p) + 1);
    for (p = s; *p; ++p) {
        unsigned char c = (unsigned char)*p;
        *w++ = ((c>='A'&&c<='Z')||(c>='a'&&c<='z')||(c>='0'&&c<='9')||c=='.'||c=='_'||c=='-') ? c : '_';
    }
    *w = '\0';
    if (!*s) strcpy(s, "upload.bin");
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
	if (!strcasecmp(ext, "mp4")) return "video/mp4";
    if (!strcasecmp(ext, "webp")) return "image/webp";
	if (!strcasecmp(ext, "bmp"))  return "image/bmp";
	if (!strcasecmp(ext, "jfif")) return "image/jpeg";
	if (!strcasecmp(ext, "tif") || !strcasecmp(ext, "tiff")) return "image/tiff";
	if (!strcasecmp(ext, "webm")) return "video/webm";
	if (!strcasecmp(ext, "mov"))  return "video/quicktime";
	if (!strcasecmp(ext, "mkv"))  return "video/x-matroska";
    return "application/octet-stream";
}


// simple case-insensitive header fetch; returns malloc'd string (caller frees)
static char *header_value_dup(const char *reqbuf, const char *name) {
    char needle[128];
    snprintf(needle, sizeof(needle), "\r\n%s:", name);
    const char *p = strcasestr_local(reqbuf, needle);
    if (!p) return NULL;
    p += 2 + strlen(name); // skip CRLF + name
    if (*p != ':') return NULL;
    p++;
    while (*p==' ' || *p=='\t') p++;
    const char *end = strstr(p, "\r\n");
    if (!end) return NULL;
    size_t n = (size_t)(end - p);
    while (n>0 && (p[n-1]==' ' || p[n-1]=='\t')) n--;
    char *out = (char*)malloc(n+1);
    if (!out) return NULL;
    memcpy(out, p, n); out[n] = '\0';
    return out;
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

static void ensure_photos_dir(void) {
    struct stat st;
    if (stat(PHOTOS_DIR, &st) == -1) {
        mkdir(PHOTOS_DIR, 0755);
    }
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

static int write_all_fd(int fd, const void *buf, size_t len) {
    const unsigned char *p = (const unsigned char*)buf;
    while (len) {
        ssize_t n = write(fd, p, len);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        p   += (size_t)n;
        len -= (size_t)n;
    }
    return 0;
}

static int write_index_json(const char *dir) {
    char tmppath[512], outpath[512];
    snprintf(outpath, sizeof(outpath), "%s/index.json", dir);
    snprintf(tmppath, sizeof(tmppath),  "%s/.index.json.tmp", dir);

    FILE *out = fopen(tmppath, "w");
    if (!out) return -1;

    DIR *d = opendir(dir);
    if (!d) { fclose(out); remove(tmppath); return -1; }

    fputs("[", out);
    int first = 1;

    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        const char *name = ent->d_name;
        if (!name || name[0] == '.') continue;                  // skip dotfiles/. and ..
        if (strcmp(name, "index.json") == 0) continue;          // skip manifest

        char path[1024];
        snprintf(path, sizeof(path), "%s/%s", dir, name);

        struct stat st;
        if (stat(path, &st) == 0 && S_ISREG(st.st_mode)) {
            if (!first) fputc(',', out);
            first = 0;
            // Names are sanitized to safe chars already when saving uploads.
            fprintf(out, "\n  \"%s\"", name);
        }
    }
    closedir(d);
    fputs(first ? "]\n" : "\n]\n", out);
    fclose(out);

    // Atomic replace so readers never see a partial file.
    if (rename(tmppath, outpath) != 0) {
        remove(tmppath);
        return -1;
    }
    return 0;
}

// ---------- client handler ----------
struct client_arg {
    int fd;
    SSL_CTX *ctx;
	char ip[64];
};

static void *handle_client(void *argp) {
    struct client_arg *arg = (struct client_arg*)argp;
    int client_fd = arg->fd;
    SSL_CTX *ctx = arg->ctx;
	char ip[64];
	strncpy(ip, arg->ip, sizeof(ip));
	ip[sizeof(ip) - 1] = '\0';
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
		char *cookie = header_value_dup(reqbuf, "Cookie");
		if (cookie) {
			if (strcasestr_local(cookie, "auth=1")) {
				isSigned = true;
			}
			free(cookie);
		}

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

			int ok = (pass && strcmp(pass, expect_password)== 0);
            if (ok) {
				isSigned = true;

				// Send redirect with a cookie for cross-connection auth
				char hdr[256];
				snprintf(hdr, sizeof(hdr),"Location: /\r\n""Set-Cookie: auth=1; Path=/; HttpOnly; Secure\r\n");

				send_simple_response_tls(ssl,302, "Found","text/plain; charset=utf-8","Redirecting...",keep,hdr);
			} 
			else {
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
        int is_get  = !strcasecmp(method, "GET");
        int is_post = !strcasecmp(method, "POST");

        // --- RAW UPLOAD: POST /upload-raw ---
        if (is_post && !strcmp(uri, "/upload-raw")) {
            if (content_len <= 0 || content_len > MAX_UPLOAD) {
                send_simple_response_tls(ssl, 413, "Payload Too Large",
                    "text/plain; charset=utf-8", "Bad or missing Content-Length", keep, NULL);
                if (!keep) break; else continue;
            }

            char *ctype = header_value_dup(reqbuf, "Content-Type");
            int ok_type = 0;
			
			if (ctype) {
				if (!strncasecmp(ctype, "application/octet-stream", 24)) ok_type = 1;
				else if (!strncasecmp(ctype, "image/", 6)) ok_type = 1;
				else if (!strncasecmp(ctype, "video/", 6)) ok_type = 1;
				}
            free(ctype);
            if (!ok_type) {
                send_simple_response_tls(ssl, 415, "Unsupported Media Type",
                    "text/plain; charset=utf-8", "Use application/octet-stream", keep, NULL);
                if (!keep) break; else continue;
            }

            char fname[256] = {0};
            char *xfn = header_value_dup(reqbuf, "X-Filename");
            if (xfn && *xfn) {
                size_t n = strlen(xfn);
                if (n >= sizeof(fname)) n = sizeof(fname)-1;
                memcpy(fname, xfn, n); fname[n] = '\0';
            } else strcpy(fname, "upload.bin");
            free(xfn);
            sanitize_filename(fname);

            char outpath[512];
            char tmppath[512];

            snprintf(outpath, sizeof(outpath), "%s/%s", PHOTOS_DIR, fname);
            // temp file in same dir so rename() (if used later) would be atomic
            snprintf(tmppath, sizeof(tmppath), "%s/.upload-%ld.tmp",
                     PHOTOS_DIR, (long)getpid());

            int fd = open(tmppath, O_CREAT | O_WRONLY | O_TRUNC, 0644);
            if (fd < 0) {
                send_simple_response_tls(ssl, 500, "Internal Server Error",
                    "text/plain; charset=utf-8", "Cannot open temp file", keep, NULL);
                if (!keep) break; else continue;
            }






            // bytes of body already present in reqbuf
			size_t preloaded = 0;
			if (hdr_end && content_len > 0) {
				size_t inbuf = (size_t)(req_len - (hdr_end + 4 - reqbuf));
				if (inbuf > (size_t)content_len) inbuf = (size_t)content_len;
				if (inbuf) {
					if (write_all_fd(fd, body, inbuf) < 0) {
						close(fd);
						send_simple_response_tls(ssl, 500, "Internal Server Error",
							"text/plain; charset=utf-8", "Write failed", keep, NULL);
						if (!keep) break; else continue;
						continue;
					}
					preloaded = inbuf;
				}
			}

			// stream the rest from TLS
			size_t wrote = preloaded;
			size_t remaining = (size_t)content_len - preloaded;
			char ibuf[8192];
			while (remaining > 0) {
				size_t want = remaining < sizeof(ibuf) ? remaining : sizeof(ibuf);
				int rn = SSL_read(ssl, ibuf, (int)want);
				if (rn <= 0) {
					int err = SSL_get_error(ssl, rn);
					if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) continue;
					close(fd);
					send_simple_response_tls(ssl, 500, "Internal Server Error","text/plain; charset=utf-8", "Client disconnected while uploading", keep, NULL);
					if (!keep) break; else continue; 
				}
				if (write_all_fd(fd, ibuf, (size_t)rn) < 0) {
					close(fd);
					send_simple_response_tls(ssl, 500, "Internal Server Error",
				"text/plain; charset=utf-8", "Write failed", keep, NULL);
					if (!keep) break; else continue;
				}
				wrote += (size_t)rn;
				remaining -= (size_t)rn;
			}
			            if (wrote != (size_t)content_len) {
                // didn’t write the full file → treat as failure
                unlink(tmppath);  // avoid leaving partial files
                send_simple_response_tls(ssl, 500, "Internal Server Error",
                    "text/plain; charset=utf-8", "Short write (upload incomplete)", keep, NULL);
                if (!keep) break; else continue;
            }

            fsync(fd);
            close(fd);

            // --- Sniff & sanitize ---

            int img_type = sniff_image_type(tmppath);
            if (img_type != 1) {  // for now: only accept JPEG
                unlink(tmppath);
                send_simple_response_tls(ssl, 415, "Unsupported Media Type",
                    "text/plain; charset=utf-8",
                    "Only JPEG images are supported", keep, NULL);
                if (!keep) break; else continue;
            }

            if (sanitize_jpeg(tmppath, outpath) != 0) {
                unlink(tmppath);
				log_msg("%s sanitize FAILED for %s", ip, fname);
                send_simple_response_tls(ssl, 500, "Internal Server Error",
                    "text/plain; charset=utf-8",
                    "Failed to sanitize uploaded image", keep, NULL);
                if (!keep) break; else continue;
            }

            unlink(tmppath);  // temp file no longer needed
			log_msg("%s triggered sanitize on %s (%ld bytes)", ip, fname, content_len);

            write_index_json(PHOTOS_DIR);
            char json[320];
            int n = snprintf(json, sizeof(json),
                             "{ \"ok\": true, \"path\": \"%s\" }\n", outpath);
            if (send_header_tls(ssl, 201, "Created",
                                "application/json; charset=utf-8",
                                n, keep, NULL) >= 0) {
                ssl_write_all(ssl, json, (size_t)n);
            }
            if (!keep) break; else continue;
        }

        // Everything else: only GET/HEAD as before
        if (!is_get && !is_head) {
            send_simple_response_tls(ssl, 405, "Method Not Allowed",
                "text/plain; charset=utf-8", "405 Method Not Allowed", keep, NULL);
            if (!keep) break; else continue;
        }

        const char *raw = (uri[0] == '/') ? uri + 1 : uri;
        if (strstr(raw, "..")) {
            send_simple_response_tls(ssl, 403, "Forbidden",
                "text/plain; charset=utf-8", "403 Forbidden", keep, NULL);
            if (!keep) break; else continue;
        }
        char *decoded = url_decode(raw);
        if (!decoded) {
            send_simple_response_tls(ssl, 500, "Internal Server Error",
                "text/plain; charset=utf-8", "500 Internal Server Error", keep, NULL);
            if (!keep) break; else continue;
        }

        char path[4096];
        if (decoded[0] == '\0') snprintf(path, sizeof(path), "index.html");
        else snprintf(path, sizeof(path), "%s", decoded);
        free(decoded);
		
		        if (!strncmp(path, "photos/", 7)) {
            char mapped[4096];

            size_t dir_len = strlen(PHOTOS_DIR);
            /* room left for '/', the filename, and '\0' */
            size_t max_file_len;
            if (dir_len + 2 >= sizeof(mapped)) {
                /* PHOTOS_DIR is too long, fallback or error */
                mapped[0] = '\0';
            } else {
                max_file_len = sizeof(mapped) - dir_len - 2; // '/' + '\0'

                int n = snprintf(
                    mapped,
                    sizeof(mapped),
                    "%s/%.*s",
                    PHOTOS_DIR,
                    (int)max_file_len,
                    path + 7
                );

                if (n < 0 || (size_t)n >= sizeof(mapped)) {
                    mapped[sizeof(mapped) - 1] = '\0';  // force terminate
                }
            }

            strncpy(path, mapped, sizeof(path) - 1);
            path[sizeof(path) - 1] = '\0';
        }

        if (is_head) {
            struct stat st;
            if (stat(path, &st) == 0 && S_ISREG(st.st_mode)) {
                const char *ext = get_file_extension(path);
                const char *mime = get_mime_type(ext);
                send_header_tls(ssl, 200, "OK", mime, (long)st.st_size, keep, NULL);
            } else {
                send_simple_response_tls(ssl, 404, "Not Found",
                    "text/plain; charset=utf-8", "404 Not Found", keep, NULL);
            }
        } else {
            if (send_file_response_tls(ssl, path, keep) < 0) {
                send_simple_response_tls(ssl, 404, "Not Found",
                    "text/plain; charset=utf-8", "404 Not Found", keep, NULL);
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
	#ifdef __OpenBSD__
    /* Whitelist filesystem access */
	printf("RUNNING OpenBSD\n");
    if (unveil("/mnt/newdisk/photos", "rwc") == -1) die("unveil photos");  /* uploads dir */
    if (unveil(".", "r") == -1)                    die("unveil cwd");      /* certs, html in cwd */
    if (unveil(NULL, NULL) == -1)                  die("unveil lock");

    /* Restrict syscalls for runtime */
    if (pledge("stdio rpath wpath cpath inet", NULL) == -1)
        die("pledge");
	#endif

    int port = PORT;
	
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) die("SSL_CTX_new failed");

    configure_context(ctx);
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
	ensure_photos_dir();
	
	// start logger thread
    pthread_t log_th;
	if (pthread_create(&log_th, NULL, logger_thread, NULL) != 0) {
        perror("pthread_create logger");
        exit(1);
    }
    pthread_detach(log_th);
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

		// Get dotted-quad IP
		if (!inet_ntop(AF_INET, &cli.sin_addr, arg->ip, sizeof(arg->ip))) {
			strncpy(arg->ip, "unknown", sizeof(arg->ip));
			arg->ip[sizeof(arg->ip) - 1] = '\0';
		}

		// Log new connection
		log_msg("%s connected", arg->ip);

		pthread_t th;
		if (pthread_create(&th, NULL, handle_client, arg) != 0) {
			perror("pthread_create");
			close(c);
			free(arg);
			continue;
		}
		pthread_detach(th);
	}

    SSL_CTX_free(ctx);
    EVP_cleanup();
    return 0;
}
