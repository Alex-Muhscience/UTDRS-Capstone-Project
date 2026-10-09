#include <bson/bson.h>
#include <stdio.h>

int main() {
    bson_t *doc = BCON_NEW("key", BCON_UTF8("value"));
    char *json = bson_as_json(doc, NULL);
    printf("BSON JSON: %s\n", json);
    bson_free(json);
    bson_destroy(doc);
    return 0;
}