#ifndef HTTP_PROXY_DOMAIN_DIC_H_
#define HTTP_PROXY_DOMAIN_DIC_H_

#include <stdarg.h>
#include <stdlib.h>
#include "../rbtree/rbtree.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct rbtree_t domain_dic_t;

typedef struct domain_t {
	struct rbnode_t node;
	char *domain;
	int proxy_index;
} domain_t;

domain_t *domain_create(const char *domain);
void domain_destroy(domain_t *item);
int domain_dic_init(domain_dic_t *dic);
void domain_dic_free(domain_dic_t *dic);
domain_t *domain_dic_add(domain_dic_t *dic, const char *domain);
domain_t *domain_dic_remove(domain_dic_t *dic, const char *domain);
#define domain_dic_remove_ex(dic, item) rbtree_remove((dic), &(item)->node)
domain_t *domain_dic_lookup(domain_dic_t *dic, const char *domain);
int domain_dic_load_file(domain_dic_t *dic, const char *filename);
int domain_dic_load_files(domain_dic_t *dic, const char *filenames);

#ifdef __cplusplus
}
#endif

#endif
