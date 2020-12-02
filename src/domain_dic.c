#include "domain_dic.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../rbtree/rbtree.h"
#include "log.h"

#ifndef WINDOWS
#define strnicmp strncasecmp
#endif

domain_t *domain_create(const char *domain)
{
	domain_t *item;

	if (!domain || !(*domain)) {
		loge("domain_create() error: empty domain\n");
		return NULL;
	}

	item = (domain_t*)malloc(sizeof(domain_t));
	if (!item) {
		loge("domain_create() error: alloc\n");
		return NULL;
	}

	memset(item, 0, sizeof(domain_t));

	item->domain = strdup(domain);
	if (!item->domain) {
		loge("domain_create() error: alloc\n");
		free(item);
		return NULL;
	}

	item->node.key = item->domain;

	return item;
}

void domain_destroy(domain_t *item)
{
	free(item->domain);
	item->domain = NULL;
	free(item);
}

static int rbnkeycmp(void *a, void *b)
{
	const char *x = (const char*)a;
	const char *y = (const char*)b;
	return strnicmp(x, y, HTTP_PROXY_MAX_DOMAIN_NAME_LEN);
}

void rbnfree(rbnode_t *node, void *state)
{
	domain_t *domain = rbtree_container_of(node, domain_t, node);
	domain_destroy(domain);
}

int domain_dic_init(domain_dic_t *dic)
{
	rbtree_init(dic, rbnkeycmp);
	return 0;
}

void domain_dic_free(domain_dic_t *dic)
{
	rbtree_clear(dic, rbnfree, NULL);
	rbtree_init(dic, rbnkeycmp);
}

domain_t *domain_dic_add(domain_dic_t *dic, const char *domain)
{
	domain_t *item;

	item = domain_create(domain);

	if (!item) return NULL;

	if (rbtree_insert(dic, &item->node)) {
		logd("domain_dic_add() error: domain exists - %s\n", domain);
		domain_destroy(item);
		return NULL;
	}

	return item;
}

domain_t *domain_dic_remove(domain_dic_t *dic, const char *domain)
{
	struct rbnode_t *n;
	domain_t *item;

	n = rbtree_lookup(dic, (void*)domain);

	if (!n) {
		logd("domain_dic_remove() error: not exists - %s\n", domain);
		return NULL;
	}

	item = rbtree_container_of(n, domain_t, node);
	
	rbtree_remove(dic, &item->node);

	return item;
}

domain_t *domain_dic_lookup(domain_dic_t *dic, const char *domain)
{
	struct rbnode_t *n;
	domain_t *item;

	n = rbtree_lookup(dic, (void*)domain);

	if (!n) return NULL;

	item = rbtree_container_of(n, domain_t, node);

	return item;
}

int domain_dic_load_file(domain_dic_t *dic, const char *filename)
{
	char buf[512];
	char *line;
	FILE *fp;
	int rownum = 0;
	domain_t *item;

	fp = fopen(filename, "rb");
	if (fp == NULL) {
		loge("Can't open file: %s\n", filename);
		return -1;
	}

	if (fseek(fp, 0, SEEK_SET) != 0) {
		loge("fseek\n");
		fclose(fp);
		return -1;
	}

	buf[sizeof(buf) - 1] = '\0';

	while ((line = fgets(buf, sizeof(buf) - 1, fp)) != NULL) {
		char *sp_pos;

		rownum++;

		if ((*line) == '#') continue;

		sp_pos = strchr(line, '\r');
		if (sp_pos) *sp_pos = 0;

		sp_pos = strchr(line, '\n');
		if (sp_pos) *sp_pos = 0;

		if (!(*line)) continue;

		sp_pos = strchr(line, '/');
		if (sp_pos) *sp_pos = 0;

		item = domain_dic_add(dic, line);
		if (item) {
			if (sp_pos) {
				item->proxy_index = atoi(sp_pos + 1);
			}
		}
		else {
			/*
			loge("calloc\n");
			fclose(fp);
			return -1;
			*/
		}
	}

	fclose(fp);

	return 0;
}

int domain_dic_load_files(domain_dic_t *dic, const char *filenames)
{
	char *s, *p;
	int r = 0;

	s = strdup(filenames);

	for (p = strtok(s, ",");
		p && *p;
		p = strtok(NULL, ",")) {

		if (domain_dic_load_file(dic, p)) {
			free(s);
			return -1;
		}
	}

	free(s);

	return r;
}

