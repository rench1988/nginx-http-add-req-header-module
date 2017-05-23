#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef struct ngx_http_req_header_val_s  ngx_http_req_header_val_t;

struct ngx_http_req_header_val_s {
    ngx_http_complex_value_t     value;
    ngx_uint_t                   hash;
    ngx_str_t                    key;
    u_char                      *lowcase_key;
};

typedef struct {
    ngx_array_t               *headers;
} ngx_http_add_req_header_loc_conf_t;


static ngx_int_t ngx_http_add_req_header_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_add_req_header_init(ngx_conf_t *cf);
static char *ngx_http_req_header_add(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void *ngx_http_add_req_header_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_add_req_header_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

static ngx_command_t  ngx_http_add_req_header_commands[] = {

    { ngx_string("add_req_header"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF
                        |NGX_CONF_TAKE2,
      ngx_http_req_header_add,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};

static ngx_http_module_t  ngx_http_add_req_header_module_ctx = {
    NULL,                                          /* preconfiguration */
    ngx_http_add_req_header_init,                  /* postconfiguration */

    NULL,                                          /* create main configuration */
    NULL,                                          /* init main configuration */

    NULL,                                          /* create server configuration */
    NULL,                                          /* merge server configuration */

    ngx_http_add_req_header_create_loc_conf,       /* create location configuration */
    ngx_http_add_req_header_merge_loc_conf         /* merge location configuration */
};

ngx_module_t  ngx_http_add_req_header_module = {
    NGX_MODULE_V1,
    &ngx_http_add_req_header_module_ctx,           /* module context */
    ngx_http_add_req_header_commands,              /* module directives */
    NGX_HTTP_MODULE,                               /* module type */
    NULL,                                          /* init master */
    NULL,                                          /* init module */
    NULL,                                          /* init process */
    NULL,                                          /* init thread */
    NULL,                                          /* exit thread */
    NULL,                                          /* exit process */
    NULL,                                          /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_int_t
ngx_http_add_req_header_handler(ngx_http_request_t *r)
{
    static u_char  lowcase[] =
        "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
        "\0\0\0\0\0\0\0\0\0\0\0\0\0-\0\0" "0123456789\0\0\0\0\0\0"
        "\0abcdefghijklmnopqrstuvwxyz\0\0\0\0\0"
        "\0abcdefghijklmnopqrstuvwxyz\0\0\0\0\0"
        "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
        "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
        "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
        "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

    u_char                               c, ch;
    ngx_uint_t                           i, j;
    ngx_str_t                            value;
    ngx_table_elt_t                     *h;
    ngx_http_header_t                   *hh;
    ngx_http_req_header_val_t           *hv;
    ngx_http_add_req_header_loc_conf_t  *conf;

    ngx_http_core_srv_conf_t   *cscf;
    ngx_http_core_main_conf_t  *cmcf;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_add_req_header_module);
    
    if (conf->headers == NULL || r != r->main) {
        return NGX_DECLINED;
    }

    hv = conf->headers->elts;

    cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);

    for (i = 0; i < conf->headers->nelts; i++) {
        /* the host header could change the server configuration context */
        cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);
 
        for (j = 0; j < hv[i].key.len; j++) {
            ch = hv[i].key.data[j];
            c  = lowcase[ch];

            if (c) {
                hv[i].hash = ngx_hash(hv[i].hash, c);
            }

            if (ch == '_') {
                if (cscf->underscores_in_headers) {
                    hv[i].hash = ngx_hash(hv[i].hash, c);
                } else {
                    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                                  "add_req_header module add invalid header name: \"%*s\"",
                                  hv[i].key.len, hv[i].key.data);
                    continue;
                }
            }
        }

        h = ngx_list_push(&r->headers_in.headers);
        if (h == NULL) {
            return NGX_ERROR;
        }

        h->hash    = hv[i].hash;
        h->key.len = hv[i].key.len;

        h->key.data = ngx_pnalloc(r->pool, h->key.len + 1);
        if (h->key.data == NULL) {
            return NGX_ERROR;
        }
        ngx_memcpy(h->key.data, hv[i].key.data, h->key.len);
        h->key.data[h->key.len] = '\0';

        h->lowcase_key = ngx_pnalloc(r->pool, h->key.len);
        if (h->lowcase_key == NULL) {
            return NGX_ERROR;
        }
        ngx_strlow(h->lowcase_key, h->key.data, h->key.len);

        if (ngx_http_complex_value(r, &hv[i].value, &value) != NGX_OK) {
            return NGX_ERROR;
        }

        h->value.len = value.len;
        h->value.data = ngx_pnalloc(r->pool, h->value.len + 1);
        if (h->value.data == NULL) {
            return NGX_ERROR;
        }
        ngx_memcpy(h->value.data, value.data, value.len);
        h->value.data[h->value.len] = '\0';

        hh = ngx_hash_find(&cmcf->headers_in_hash, h->hash, h->lowcase_key, h->key.len);
        if (hh && hh->handler(r, h, hh->offset) != NGX_OK) {
            return NGX_AGAIN; //这里必须是NGX_DONE或者NGX_AGAIN
        }
    }

    return NGX_DECLINED;
}

static ngx_int_t
ngx_http_add_req_header_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_POST_READ_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_add_req_header_handler;

    return NGX_OK;
}

static char *
ngx_http_req_header_add(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_add_req_header_loc_conf_t *hcf = conf;

    ngx_str_t                         *value;
    ngx_http_req_header_val_t         *hv;
    ngx_http_compile_complex_value_t   ccv;

    value = cf->args->elts;

    if (hcf->headers == NULL) {
        hcf->headers = ngx_array_create(cf->pool, 1,
                                        sizeof(ngx_http_req_header_val_t));
        if (hcf->headers == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    hv = ngx_array_push(hcf->headers);
    if (hv == NULL) {
        return NGX_CONF_ERROR;
    }

    hv->key = value[1];

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[2];
    ccv.complex_value = &hv->value;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    hv->lowcase_key = ngx_pnalloc(cf->pool, hv->key.len);
    if (hv->lowcase_key == NULL) {
        return NGX_CONF_ERROR;
    }        

    ngx_strlow(hv->lowcase_key, hv->key.data, hv->key.len);

    hv->hash = 0;

    return NGX_CONF_OK;
}


static void *
ngx_http_add_req_header_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_add_req_header_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_add_req_header_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    return conf;
}

static char *
ngx_http_add_req_header_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_add_req_header_loc_conf_t  *prev = parent;
    ngx_http_add_req_header_loc_conf_t  *conf = child;

    if (conf->headers == NULL) {
        conf->headers = prev->headers;
    }

    return NGX_CONF_OK;
}



