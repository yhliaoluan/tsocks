#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include "utils/list.h"

struct ts_test_list {
    int val;
    struct list_head list;
};

int main(int argc, char **argv) {
    struct ts_test_list my_list, *tmp;
    my_list.val = 0;
    INIT_LIST_HEAD(&my_list.list);
    int i;
    for (i = 1; i < 5; i++) {
        tmp = malloc(sizeof(struct ts_test_list));
        tmp->val = i;
        list_add(&tmp->list, &my_list.list);
    }

    struct list_head *pos;
    list_for_each(pos, &my_list.list) {
        tmp = list_entry(pos, struct ts_test_list, list);
        printf("%d\n", tmp->val);
    }
    return 0;
}
