#include <string.h>
#include <stdio.h>

#include "myalloc.h"

char *alloc_str(const char *from) {
    size_t sz = strlen(from);
    char *to = (char *)my_malloc(sizeof(char) * (sz + 1));
    strcpy(to, from);
    return to;
}

int main(void)
{
    char *x = (char *)my_malloc(sizeof(char) * 20);

    char *s2 = alloc_str("did");
    char *s3 = alloc_str("nothing");
    char *s4 = alloc_str("wrong");

    char *x2 = (char *)my_malloc(sizeof(char) * 10);
    char *x3 = (char *)my_malloc(sizeof(char) * 10);
    my_free(x);
    my_free(x2);

    char *s1 = alloc_str("Stalin");

    my_memdump(stdout, 0, 2048);

    my_free(s1);
    my_free(s2);
    my_free(s3);
    my_free(s4);

    return 0;
}
