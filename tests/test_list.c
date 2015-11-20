#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include "utils/list.h"

struct ts_test_list {
    int val;
    struct list_head list;
};

int main(int argc, char **argv) {
    LIST_HEAD(head);
    int i;
    for (i = 0; i < 5; i++) {
        struct ts_test_list *tmp = malloc(sizeof(struct ts_test_list));
        tmp->val = i;
        list_add(&tmp->list, &head);
    }

    struct list_head *pos;
    list_for_each(pos, &head) {
        struct ts_test_list * tmp = list_entry(pos, struct ts_test_list, list);
        printf("%d\n", tmp->val);
    }
    return 0;
}
