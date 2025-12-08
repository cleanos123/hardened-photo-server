// tests/unit_helpers.c
// Unit tests for helper functions in httpsetup.c

#include <stdio.h>
#include <string.h>
#include <assert.h>

#define UNIT_TEST
#include "../httpsetup.c"   // pulls in sanitize_filename, get_mime_type, etc.

static void test_sanitize_filename(void) {
    char name1[256] = "../etc/passwd";
    sanitize_filename(name1);
    // should strip directories and keep only safe chars
    assert(strcmp(name1, "passwd") == 0);

    char name2[256] = "my bad*name?.jpg";
    sanitize_filename(name2);
    // spaces and weird chars become '_'
    assert(strcmp(name2, "my_bad_name_.jpg") == 0);

    char name3[256] = "";
    sanitize_filename(name3);
    assert(strcmp(name3, "upload.bin") == 0);
}

static void test_get_mime_type(void) {
    const char *m1 = get_mime_type("jpg");
    const char *m2 = get_mime_type("jpeg");
    const char *m3 = get_mime_type("png");
    const char *m4 = get_mime_type("weird");

    assert(strstr(m1, "image/jpeg") != NULL);
    assert(strstr(m2, "image/jpeg") != NULL);
    assert(strcmp(m3, "image/png") == 0);
    assert(strcmp(m4, "application/octet-stream") == 0);
}

int main(void) {
    printf("[unit] test_sanitize_filename...\n");
    test_sanitize_filename();
    printf("[unit] test_get_mime_type...\n");
    test_get_mime_type();
    printf("[unit] all unit tests passed.\n");
    return 0;
}
