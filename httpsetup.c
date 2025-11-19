#include <arpa/inet.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <regex.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <limits.h>
#include <sys/sendfile.h>

#define PORT 8080
#define BACKLOG 10
#define BUFFER_SIZE 104857600
#define MAX_UPLOAD (25 * 1024 * 1024)   // 25 MB per request
#define UPLOAD_DIR "photos/2025"      


////////////////////////////////////////////////////////////
char *url_decode(const char *src);
const char *get_file_extension(const char *file_name);
void* handle_client(void *arg);
void build_http_response(const char *file_name, const char *file_ext, char *response, size_t *response_len);
const char *get_mime_type(const char *file_ext);
static void sanitize_filename(char *s);
static int send_all(int fd, const void *buf, size_t len);
static int mkdir_if_needed(const char *path, mode_t mode);
static char *strncasestr(const char *hay, size_t haylen, const char *needle);
static long parse_content_length(const char *hdrs);
static ssize_t find_header_end(const char *buf, size_t len);
static int extract_boundary(const char *hdrs, char *out, size_t outcap);
static int current_year(void);
static int ensure_year_dir(int year, char out_path[PATH_MAX]);
static void uniquify_path(char path[PATH_MAX]);
static int save_multipart_photos(const char *body, size_t blen, const char *boundary);
////////////////////////////////////////////////////////////

int main(){
	
	int server_fd;
	struct sockaddr_in server_addr;
	
	if((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0 ){
		perror("SOCKET FAILED");
		exit(EXIT_FAILURE);
	}
	
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(PORT);
	server_addr.sin_addr.s_addr = INADDR_ANY;
	
	if (bind(server_fd,(struct sockaddr *)&server_addr, sizeof(server_addr)) < 0){
		perror("BIND FAILED");
		exit(EXIT_FAILURE);
	}
	
	if(listen(server_fd, BACKLOG) < 0){
		perror("LISTEN FAILED");
		exit(EXIT_FAILURE);
	}
	
	while(1){
		//Client connections
		struct sockaddr_in client_addr;
		socklen_t client_addr_len = sizeof(client_addr);
		int *client_fd = malloc(sizeof(int));
		
		if((*client_fd = accept(server_fd,(struct sockaddr *)&client_addr,&client_addr_len)) < 0){
			perror("ACCEPT FAILED");
			continue;
		}
		
		pthread_t thread_id;
		pthread_create(&thread_id, NULL, handle_client, (void *)client_fd);
		pthread_detach;
		
	}
	
	return 0;
}

void* handle_client(void *arg){
	int client_fd = *((int*)arg);
	char *buffer = (char *)malloc(BUFFER_SIZE * sizeof(char));
	
	ssize_t bytes_received =  recv(client_fd, buffer, BUFFER_SIZE, 0 );
	if (bytes_received > 0) {
		regex_t regex;
		regcomp( &regex,"GET /([^ ]*) HTTP/1.1", REG_EXTENDED);
		regmatch_t matches[2]; // uses regular expressions and will compare to check if /index.html is grabbed
		
		if (regexec(&regex, buffer, 2, matches, 0) == 0){
			// extract filename from request and decode URL
			buffer[matches[1].rm_eo] = '\0';
			const char *url_encoded_file_name = buffer + matches[1].rm_so; //buffer is a pointer + 5 so that it can point to /index.html\0 and we use that for resolving
			char *file_name = url_decode(url_encoded_file_name);
			
			//get file extension
			char file_ext[32];
			strcpy(file_ext, get_file_extension(file_name));
			
			//build http response
			char *response = (char *)malloc(BUFFER_SIZE * 2 * sizeof(char));
			size_t response_len;
			build_http_response(file_name, file_ext, response, &response_len);
			
			//send http response
			send(client_fd, response, response_len, 0);
			
			//client sent html, we wait for response
			while(1){
				free(response);
				free(file_name);
				regfree(&regex);
				bytes_received =  recv(client_fd, buffer, BUFFER_SIZE, 0 );
				regcomp(&regex,"GET /([^ ]*) HTTP/1.1", REG_EXTENDED);
				memset(matches, 0, sizeof(matches));
				if (regexec(&regex, buffer, 2, matches, 0) == 0) {
					// extract filename from request and decode URL
					buffer[matches[1].rm_eo] = '\0';
					url_encoded_file_name = buffer + matches[1].rm_so; //buffer is a pointer + 5 so that it can point to /index.html\0 and we use that for resolving
					file_name = url_decode(url_encoded_file_name);
			
					//get file extension
					strcpy(file_ext, get_file_extension(file_name));
			
					//build http response
					response = (char *)malloc(BUFFER_SIZE * 2 * sizeof(char));
					response_len = 0;
					build_http_response(file_name, file_ext, response, &response_len);
			
					//send http response
					send(client_fd, response, response_len, 0);
				}
			
			
			
			}
			
			free(response);
			free(file_name);
		}
		else{
			
		}
		regfree(&regex);
	}
	close(client_fd);
	free(arg);
	free(buffer);
	return NULL;
}

void build_http_response(const char *file_name, const char *file_ext, char *response, size_t *response_len){
	//build https header
	const char *mime_type = get_mime_type(file_ext);
	char *header = (char *)malloc(BUFFER_SIZE * sizeof(char));
	snprintf(header, BUFFER_SIZE, "HTTP/1.1 200 OK\r\n""Content-Type: %s\r\n""\r\n", mime_type);
	
	//if file not exists, repsonse 404 not Found
	int file_fd = open(file_name, O_RDONLY);
	if (file_fd == -1){
		snprintf(response, BUFFER_SIZE, "HTTP/1.1 404 Not Found\r\n""Content-Type: text/plain\r\n""\r\n""404 Not Found");
		*response_len = (strlen(response));
		return;
	}
	//get file size for content length
	struct stat file_stat;
	fstat(file_fd, &file_stat);
	off_t file_size = file_stat.st_size;
	
	//copy header to response buffer
	*response_len = 0;
	memcpy(response, header, strlen(header));
	*response_len += strlen(header);
	
	//copy file to response buffer
	ssize_t bytes_read;
	while ((bytes_read = read(file_fd, response + *response_len, BUFFER_SIZE - *response_len)) > 0){
		*response_len += bytes_read;
	}
	free(header);
	close(file_fd);
}
	
const char *get_mime_type(const char *file_ext){
    if (strcasecmp(file_ext, "html") == 0 || strcasecmp(file_ext, "htm") == 0) {
        return "text/html";
    } else if (strcasecmp(file_ext, "txt") == 0) {
        return "text/plain";
    } else if (strcasecmp(file_ext, "jpg") == 0 || strcasecmp(file_ext, "jpeg") == 0) {
        return "image/jpeg";
    } else if (strcasecmp(file_ext, "png") == 0) {
        return "image/png";
    } else {
        return "application/octet-stream";
    }
}

char *url_decode(const char *src){
    size_t src_len = strlen(src);
    char *decoded = malloc(src_len + 1);
    size_t decoded_len = 0;

    // decode %2x to hex
    for (size_t i = 0; i < src_len; i++) {
        if (src[i] == '%' && i + 2 < src_len) {
            int hex_val;
            sscanf(src + i + 1, "%2x", &hex_val);
            decoded[decoded_len++] = hex_val; // moves hex values (spaces etc) to decoded
            i += 2;
        } else {
            decoded[decoded_len++] = src[i]; //moves regular characters to decoded
        } 
    }

    // add null terminator
    decoded[decoded_len] = '\0';
    return decoded;
}

const char *get_file_extension(const char *file_name){
    const char *dot = strrchr(file_name, '.');
    if (!dot || dot == file_name) {
        return "";
    }
    return dot + 1;
}

// sanitize filenames: keep [A-Za-z0-9._-], drop everything else
static void sanitize_filename(char *s) {
    // drop any provided path segments first
    const char *base = s;
    const char *slash;
    if ((slash = strrchr(base, '/'))) base = slash + 1;
    if ((slash = strrchr(base, '\\'))) base = slash + 1;

    if (base != s) memmove(s, base, strlen(base) + 1);

    size_t w = 0;
    for (size_t r = 0; s[r]; r++) {
        unsigned char c = (unsigned char)s[r];
        if ((c>='A'&&c<='Z') || (c>='a'&&c<='z') || (c>='0'&&c<='9') || c=='.' || c=='_' || c=='-')
            s[w++] = (char)c;
    }
    s[w] = '\0';
    if (w == 0) strcpy(s, "file");
}

// send-all helper (reliable send)
static int send_all(int fd, const void *buf, size_t len) {
    const char *p = (const char *)buf;
    while (len) {
        ssize_t n = send(fd, p, len, 0);
        if (n <= 0) return -1;
        p += n;
        len -= (size_t)n;
    }
    return 0;
}

// make directory if it doesn't exist (like mkdir -p for one level)
static int mkdir_if_needed(const char *path, mode_t mode) {
    if (mkdir(path, mode) == 0) return 0;
    if (errno == EEXIST) {
        struct stat st;
        if (stat(path, &st) == 0 && S_ISDIR(st.st_mode)) return 0;
    }
    return -1;
}

// naive case-insensitive substring over fixed length
static char *strncasestr(const char *hay, size_t haylen, const char *needle) {
    size_t nlen = strlen(needle);
    if (nlen == 0 || nlen > haylen) return NULL;
    for (size_t i = 0; i + nlen <= haylen; i++) {
        if (strncasecmp(hay + i, needle, nlen) == 0) return (char *)(hay + i);
    }
    return NULL;
}

static long parse_content_length(const char *hdrs) {
    const char *p = strcasestr(hdrs, "Content-Length:");
    if (!p) return -1;
    p += strlen("Content-Length:");
    while (*p==' '||*p=='\t') p++;
    return strtol(p, NULL, 10);
}

// naive case-insensitive substring over fixed length
static char *strncasestr(const char *hay, size_t haylen, const char *needle) {
    size_t nlen = strlen(needle);
    if (nlen == 0 || nlen > haylen) return NULL;
    for (size_t i = 0; i + nlen <= haylen; i++) {
        if (strncasecmp(hay + i, needle, nlen) == 0) return (char *)(hay + i);
    }
    return NULL;
}

// find CRLF CRLF (end of headers)
static ssize_t find_header_end(const char *buf, size_t len) {
    for (size_t i = 0; i + 3 < len; i++)
        if (buf[i]=='\r' && buf[i+1]=='\n' && buf[i+2]=='\r' && buf[i+3]=='\n')
            return (ssize_t)(i + 4);
    return -1;
}

static int extract_boundary(const char *hdrs, char *out, size_t outcap) {
    const char *p = strcasestr(hdrs, "Content-Type:");
    if (!p) return -1;
    const char *eol = strstr(p, "\r\n"); if (!eol) return -1;
    const char *b = strcasestr(p, "boundary=");
    if (!b || b > eol) return -1;
    b += 9;
    if (*b=='"') {
        b++;
        const char *q = strchr(b, '"'); if (!q) return -1;
        size_t n = (size_t)(q - b);
        if (n >= outcap) return -1;
        memcpy(out, b, n); out[n] = '\0';
        return 0;
    } else {
        const char *q = b;
        while (q<eol && *q!=';' && *q!=' ' && *q!='\r' && *q!='\n') q++;
        size_t n = (size_t)(q - b);
        if (n >= outcap) return -1;
        memcpy(out, b, n); out[n] = '\0';
        return 0;
    }
}

// get current year as int (local time)
static int current_year(void) {
    time_t t = time(NULL);
    struct tm tmv;
    localtime_r(&t, &tmv);
    return 1900 + tmv.tm_year;
}

// ensure photos/<YEAR> exists; returns 0 on success
static int ensure_year_dir(int year, char out_path[PATH_MAX]) {
    if (mkdir_if_needed(PHOTOS_ROOT, 0755) != 0) return -1;
    snprintf(out_path, PATH_MAX, "%s/%d", PHOTOS_ROOT, year);
    if (mkdir_if_needed(out_path, 0755) != 0) return -1;
    return 0;
}

// if file exists, append "-1", "-2", ... before extension
static void uniquify_path(char path[PATH_MAX]) {
    struct stat st;
    if (stat(path, &st) != 0) return; // doesn't exist, good

    char dir[PATH_MAX], base[PATH_MAX], name[PATH_MAX], ext[64];
    // split dir/base
    strncpy(dir, path, sizeof(dir)); dir[sizeof(dir)-1] = 0;
    char *slash = strrchr(dir, '/');
    if (!slash) { dir[0] = 0; strncpy(base, path, sizeof(base)); }
    else { *slash = 0; strncpy(base, slash+1, sizeof(base)); }

    // split name/ext
    char *dot = strrchr(base, '.');
    if (dot) {
        *dot = 0;
        strncpy(name, base, sizeof(name)); name[sizeof(name)-1]=0;
        strncpy(ext, dot+1, sizeof(ext)); ext[sizeof(ext)-1]=0;
    } else {
        strncpy(name, base, sizeof(name)); name[sizeof(name)-1]=0;
        ext[0] = 0;
    }

    for (int i = 1; i < 10000; i++) {
        if (ext[0])
            snprintf(path, PATH_MAX, "%s/%s-%d.%s", dir, name, i, ext);
        else
            snprintf(path, PATH_MAX, "%s/%s-%d", dir, name, i);
        if (stat(path, &st) != 0) return; // found free name
    }
}

static int save_multipart_photos(const char *body, size_t blen, const char *boundary) {
    // markers
    char bstart[256], bend[256];
    snprintf(bstart, sizeof(bstart), "--%s", boundary);
    snprintf(bend,   sizeof(bend),   "--%s--", boundary);

    size_t bstart_len = strlen(bstart);

    // first boundary
    const char *p = strncasestr(body, blen, bstart);
    if (!p) return 0;
    p += bstart_len;

    // ensure destination year directory
    int year = current_year();
    char year_dir[PATH_MAX];
    if (ensure_year_dir(year, year_dir) != 0) return 0;

    int saved = 0;
    while ((size_t)(p - body) < blen) {
        if (p[0]=='\r' && p[1]=='\n') p += 2;

        const char *part_hdrs = p;
        const char *ph_end = strstr(part_hdrs, "\r\n\r\n");
        if (!ph_end) break;
        size_t part_hdrs_len = (size_t)(ph_end - part_hdrs);

        // parse filename=...
        char filename[256] = {0};
        const char *cd = strncasestr(part_hdrs, part_hdrs_len, "Content-Disposition:");
        if (cd) {
            const char *fn = strncasestr(cd, (size_t)(part_hdrs + part_hdrs_len - cd), "filename=");
            if (fn) {
                fn += 9;
                if (*fn=='"') {
                    fn++;
                    const char *q = strchr(fn, '"');
                    if (q) {
                        size_t n = (size_t)(q - fn);
                        if (n >= sizeof(filename)) n = sizeof(filename)-1;
                        memcpy(filename, fn, n); filename[n] = '\0';
                    }
                } else {
                    const char *q = fn;
                    while (*q && *q!=';' && *q!='\r' && *q!='\n') q++;
                    size_t n = (size_t)(q - fn);
                    if (n >= sizeof(filename)) n = sizeof(filename)-1;
                    memcpy(filename, fn, n); filename[n] = '\0';
                }
            }
        }

        const char *data = ph_end + 4;

        // find next boundary occurrence from data
        const char *next = strncasestr(data, (size_t)(blen - (data - body)), "\r\n--");
        const char *soft = strncasestr(data, (size_t)(blen - (data - body)), bstart);
        const char *hard = strncasestr(data, (size_t)(blen - (data - body)), bend);

        const char *marker = NULL;
        if (hard) marker = hard;
        if (soft && (!marker || soft < marker)) marker = soft;
        if (!marker && next) marker = next + 2;
        if (!marker) break;

        size_t datalen = (size_t)(marker - data);
        if (datalen >= 2 && data[datalen-2]=='\r' && data[datalen-1]=='\n') datalen -= 2;

        // save only if a file field
        if (filename[0] && datalen > 0) {
            sanitize_filename(filename);
            // photos/<YEAR>/<filename>
            char path[PATH_MAX];
            snprintf(path, sizeof(path), "%s/%s", year_dir, filename);
            uniquify_path(path);

            int fd = open(path, O_WRONLY|O_CREAT|O_TRUNC, 0644);
            if (fd >= 0) {
                ssize_t w = write(fd, data, datalen);
                (void)w;
                close(fd);
                saved++;
            }
        }

        // advance to after boundary
        const char *after = strncasestr(marker, (size_t)(blen - (marker - body)), bstart);
        const char *after_end = strncasestr(marker, (size_t)(blen - (marker - body)), bend);
        if (after_end && (!after || after_end < after)) break; // final boundary reached
        if (after) p = after + bstart_len; else break;
    }

    return saved;
}
