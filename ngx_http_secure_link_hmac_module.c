
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/crypto.h>


#define NGX_HTTP_SECURE_LINK_HMAC_TIMESTAMP    1
#define NGX_HTTP_SECURE_LINK_HMAC_MSTIMESTAMP  2
#define NGX_HTTP_SECURE_LINK_HMAC_HEXTIMESTAMP 3
#define NGX_HTTP_SECURE_LINK_HMAC_DATE         4

#define NGX_HTTP_SECURE_LINK_HMAC_BASE64URL    1
#define NGX_HTTP_SECURE_LINK_HMAC_HEXDIGEST    2


typedef struct {
    ngx_flag_t                 enable;
    ngx_http_complex_value_t  *token;
    ngx_http_complex_value_t  *time;
    ngx_http_complex_value_t  *start;
    ngx_http_complex_value_t  *end;
    ngx_http_complex_value_t  *message;
    ngx_http_complex_value_t  *secret;
    ngx_uint_t                 time_mode;
    ngx_str_t                  time_format;
    time_t                     time_offset;
    ngx_uint_t                 token_format;
    ngx_str_t                  algorithm;
} ngx_http_secure_link_hmac_conf_t;


static ngx_int_t ngx_http_secure_link_hmac_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static void *ngx_http_secure_link_hmac_create_conf(ngx_conf_t *cf);
static char *ngx_http_secure_link_hmac_merge_conf(ngx_conf_t *cf, void *parent,
    void *child);

static ngx_int_t ngx_http_secure_link_hmac_hex_decode(ngx_str_t *dst,
    ngx_str_t *src);
static ngx_int_t ngx_http_secure_link_hmac_is_valid_num(ngx_str_t *s);
static char *ngx_http_secure_link_hmac_check_time(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_http_secure_link_hmac_check_token(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_secure_link_hmac_add_variables(ngx_conf_t *cf);


static ngx_command_t  ngx_http_secure_link_hmac_commands[] = {

    { ngx_string("secure_link_hmac"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_secure_link_hmac_conf_t, enable),
      NULL },

    { ngx_string("secure_link_hmac_check_time"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_secure_link_hmac_check_time,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("secure_link_hmac_check_token"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE12,
      ngx_http_secure_link_hmac_check_token,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("secure_link_hmac_message"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_set_complex_value_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_secure_link_hmac_conf_t, message),
      NULL },

    { ngx_string("secure_link_hmac_secret"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_set_complex_value_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_secure_link_hmac_conf_t, secret),
      NULL },

    { ngx_string("secure_link_hmac_algorithm"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_secure_link_hmac_conf_t, algorithm),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_secure_link_hmac_module_ctx = {
    ngx_http_secure_link_hmac_add_variables,    /* preconfiguration */
    NULL,                                       /* postconfiguration */

    NULL,                                       /* create main configuration */
    NULL,                                       /* init main configuration */

    NULL,                                       /* create server configuration */
    NULL,                                       /* merge server configuration */

    ngx_http_secure_link_hmac_create_conf,      /* create location configuration */
    ngx_http_secure_link_hmac_merge_conf        /* merge location configuration */
};


ngx_module_t  ngx_http_secure_link_hmac_module = {
    NGX_MODULE_V1,
    &ngx_http_secure_link_hmac_module_ctx,      /* module context */
    ngx_http_secure_link_hmac_commands,         /* module directives */
    NGX_HTTP_MODULE,                            /* module type */
    NULL,                                       /* init master */
    NULL,                                       /* init module */
    NULL,                                       /* init process */
    NULL,                                       /* init thread */
    NULL,                                       /* exit thread */
    NULL,                                       /* exit process */
    NULL,                                       /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_http_variable_t ngx_http_secure_link_hmac_vars[] = {

    { ngx_string("secure_link_hmac"), NULL,
      ngx_http_secure_link_hmac_variable,
      0, NGX_HTTP_VAR_CHANGEABLE, 0 },

      ngx_http_null_variable
};


static ngx_int_t
ngx_http_secure_link_hmac_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_secure_link_hmac_conf_t  *conf;
    const EVP_MD                 *evp_md;
    u_char                       *p, *last;
    ngx_str_t                     value;
    ngx_int_t                     is_negative;
    time_t                        timestamp, now, start, end;
    ngx_int_t                     start_is_valid, end_is_valid;
    ngx_tm_t                      tm;
    ngx_uint_t                    i;
    ngx_str_t                     hash, key;
    u_char                        hash_buf[EVP_MAX_MD_SIZE], hmac_buf[EVP_MAX_MD_SIZE];
    u_int                         hmac_len;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_secure_link_hmac_module);

    if (!conf->enable
        || conf->token == NULL
        || conf->message == NULL
        || conf->secret == NULL)
    {
        goto not_found;
    }

    /* no time range is set, no check for expiration */
    if (conf->time == NULL
        || (conf->start == NULL && conf->end == NULL))
    {
        goto token;
    }

    if (conf->start == NULL) {
        start_is_valid = 0;

    } else {
        if (ngx_http_complex_value(r, conf->start, &value) != NGX_OK) {
            return NGX_ERROR;
        }

        if (value.len > 0) {
            is_negative = 0;

            if (value.data[0] == '-') {
                is_negative = 1;
                value.data++;
                value.len--;
            }

            if (value.len >= 2 && value.data[0] == '0' && value.data[1] == 'x') {
                start = ngx_hextoi(value.data + 2, value.len - 2);

            } else {
                start = ngx_atoi(value.data, value.len);
            }

            if (start == NGX_ERROR) {
                start_is_valid = 0;
            }

            if (is_negative) {
                start = -start;
            }

            start_is_valid = 1;
        } else {
            start_is_valid = 0;
        }
    }

    if (conf->end == NULL) {
        end_is_valid = 0;

    } else {
        if (ngx_http_complex_value(r, conf->end, &value) != NGX_OK) {
            return NGX_ERROR;
        }

        if (value.len > 0) {
            is_negative = 0;

            if (value.data[0] == '-') {
                is_negative = 1;
                value.data++;
                value.len--;
            }

            if (value.len >= 2 && value.data[0] == '0' && value.data[1] == 'x') {
                end = ngx_hextoi(value.data + 2, value.len - 2);

            } else {
                end = ngx_atoi(value.data, value.len);
            }

            if (end == NGX_ERROR) {
                end_is_valid = 0;
            }

            if (is_negative) {
                end = -end;
            }

            end_is_valid = 1;
        } else {
            end_is_valid = 0;
        }
    }

    /* Invalid time range */
    if ((start_is_valid == 0 && end_is_valid == 0)
        || (start_is_valid == 1 && end_is_valid == 1 && start > end))
    {
        goto not_found;
    }

    if (ngx_http_complex_value(r, conf->time, &value) != NGX_OK) {
        return NGX_ERROR;
    }

    if (value.len == 0) {
        goto not_found;
    }

    if (conf->time_mode == NGX_HTTP_SECURE_LINK_HMAC_TIMESTAMP) {
        timestamp = (time_t) ngx_atoi(value.data, value.len);

    } else if (conf->time_mode == NGX_HTTP_SECURE_LINK_HMAC_MSTIMESTAMP) {
        timestamp = (time_t) ngx_atoi(value.data , value.len - 3);

    } else if (conf->time_mode == NGX_HTTP_SECURE_LINK_HMAC_HEXTIMESTAMP) {
        timestamp = (time_t) ngx_hextoi(value.data, value.len);

    } else { /* NGX_HTTP_SECURE_LINK_HMAC_DATE */
        ngx_memzero(&tm, sizeof(ngx_tm_t));

        if (strptime((char *) value.data,
            (char *) conf->time_format.data, &tm) == NULL) {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                            "failed to parse date string");
            return NGX_ERROR;
        }

        /* Convert to unix_time */
        timestamp = timegm(&tm);
        
        if (timestamp == (time_t) NGX_ERROR) {
            goto not_found;
        }

        timestamp -= conf->time_offset;
    }

    if (timestamp <= 0) {
        goto not_found;
    }

    now = ngx_time();
    if (start_is_valid && now + start < timestamp
        || end_is_valid && now + end > timestamp)
    {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                        "secure link expiresd");
        goto not_found;
    }

token:

    evp_md = EVP_get_digestbyname((const char*) conf->algorithm.data);
    if (evp_md == NULL) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "Unknown cryptographic hash function \"%s\"", conf->algorithm.data);

        return NGX_ERROR;
    }

    hash.len  = (u_int) EVP_MD_size(evp_md);
    hash.data = hash_buf;

    if (ngx_http_complex_value(r, conf->token, &value) != NGX_OK) {
        return NGX_ERROR;
    }

    if (conf->token_format == NGX_HTTP_SECURE_LINK_HMAC_BASE64URL) {

        if (value.len > ngx_base64_encoded_length(hash.len)+2) {
            goto not_found;
        }

        if (ngx_decode_base64url(&hash, &value) != NGX_OK) {
            goto not_found;
        }

    } else {
        if (ngx_http_secure_link_hmac_hex_decode(&hash, &value) != NGX_OK) {
            goto not_found;
        }
    }

    if (hash.len != (u_int) EVP_MD_size(evp_md)) {
        goto not_found;
    }

    if (ngx_http_complex_value(r, conf->message, &value) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "secure link message: \"%V\"", &value);

    if (ngx_http_complex_value(r, conf->secret, &key) != NGX_OK) {
        return NGX_ERROR;
    }

    HMAC(evp_md, key.data, key.len, value.data, value.len, hmac_buf, &hmac_len);

    if (CRYPTO_memcmp(hash_buf, hmac_buf, EVP_MD_size(evp_md)) != 0) {
        goto not_found;
    }

    v->data = (u_char *) "1";
    v->len = 1;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;

not_found:

    v->not_found = 1;

    return NGX_OK;
}


static void *
ngx_http_secure_link_hmac_create_conf(ngx_conf_t *cf)
{
    ngx_http_secure_link_hmac_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_secure_link_hmac_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->token = NULL;
     *     conf->time = NULL;
     *     conf->start = NULL;
     *     conf->end = NULL;
     *     conf->message = NULL;
     *     conf->secret = NULL;
     *     conf->time_format = { 0, NULL };
     *     conf->token_format = { 0, NULL };
     *     conf->algorithm = { 0, NULL };
     */

    conf->enable = NGX_CONF_UNSET;
    conf->time_mode= NGX_CONF_UNSET_UINT;
    conf->token_format = NGX_CONF_UNSET_UINT;
    conf->time_offset = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_http_secure_link_hmac_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_secure_link_hmac_conf_t *prev = parent;
    ngx_http_secure_link_hmac_conf_t *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);

    if (conf->time == NULL) {
        conf->time = prev->time;
        conf->start = prev->start;
        conf->end = prev->end;
        ngx_conf_merge_value(conf->time_mode, prev->time_mode, NGX_HTTP_SECURE_LINK_HMAC_TIMESTAMP);
        ngx_conf_merge_str_value(conf->time_format, prev->time_format, "%s");
        ngx_conf_merge_value(conf->time_offset, prev->time_offset, 0);
    }

    if (conf->token == NULL) {
        conf->token = prev->token;
        ngx_conf_merge_value(conf->token_format, prev->token_format, NGX_HTTP_SECURE_LINK_HMAC_HEXDIGEST);
    }

    if (conf->message == NULL) {
        conf->message = prev->message;
    }

    if (conf->secret == NULL) {
        conf->secret = prev->secret;
    }

    ngx_conf_merge_str_value(conf->algorithm, prev->algorithm, "sha256");

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_secure_link_hmac_is_valid_num(ngx_str_t *s)
{
    u_char      *p;
    size_t       len;

    if (s == NULL || s->len == 0) {
        return 0;
    }

    p = s->data;
    len = s->len;

    if (*p == '-') {
        p++;
        len--;

        if (len == 0) {
            return 0;
        }
    }

    if (len > 2 && p[0] == '0' && (p[1] == 'x')) {
        p += 2;
        len -= 2;

        if (len == 0) {
            return 0;
        }

        while (len--) {
            if (!((*p >= '0' && *p <= '9') ||
                  || (*p >= 'a' && *p <= 'f') ||
                  || (*p >= 'A' && *p <= 'F')))
            {
                return 0;
            }
            p++;
        }

        return 1;
    }

    while (len--) {
        if (!(*p >= '0' && *p <= '9')) {
            return 0;
        }
        p++;
    }

    return 1;
}


static char *
ngx_http_secure_link_hmac_check_time(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf)
{
    ngx_http_secure_link_hmac_conf_t *slcf = conf;

    ngx_uint_t                          i, j;
    ngx_str_t                          *value;
    ngx_http_compile_complex_value_t    ccv;
    ngx_str_t                           s;
    time_t                              time_offset;

    if (slcf->time != NGX_CONF_UNSET_PTR && slcf->time != NULL) {
        return "is duplicate";
    }

    value = cf->args->elts;

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = ngx_palloc(cf->pool,
                                sizeof(ngx_http_complex_value_t));
    if (ccv.complex_value == NULL) {
        return NGX_CONF_ERROR;
    }

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    slcf->time = ccv.complex_value;

    for (i = 2; i < cf->args->nelts; i++) {

        if (value[i].len > 7 && ngx_strncmp(value[i].data, "format=", 7) == 0) {
            s.len = value[i].len - 7;
            s.data = value[i].data + 7;

            if (s.len == 2 && s.data[0] == '%' && s.data[1] == 's') {
                slcf->time_mode = NGX_HTTP_SECURE_LINK_HMAC_TIMESTAMP;
                continue;
            }

            if (s.len == 3 && s.data[0] == '%'
                && s.data[1] == 'm' && s.data[1] == 's') {
                slcf->time_mode = NGX_HTTP_SECURE_LINK_HMAC_MSTIMESTAMP;
                continue;
            }

            if (s.len == 2 && s.data[0] == '%' && s.data[1] == 'x') {
                slcf->time_mode = NGX_HTTP_SECURE_LINK_HMAC_HEXTIMESTAMP;
                continue;
            }

            slcf->time_mode = NGX_HTTP_SECURE_LINK_HMAC_DATE;
            slcf->time_format = s;

            continue;
        }

        if (value[i].len > 9 && ngx_strncmp(value[i].data, "timezone=", 9) == 0) {
            s.len = value[i].len - 9;
            s.data = value[i].data + 9;

            if (ngx_strncmp(s.data, "gmt", 3) != 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                "invalid timezone format");
                return NGX_CONF_ERROR;
            }

            if (s.len == 3) {
                slcf->time_offset = 0;
                continue;
            }

            if (s.len != 8
                || (s.data[3] != '+' && s.data[3] != '-'))
            {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                "invalid timezone format");
                return NGX_CONF_ERROR;
            }

            for (j = 4; j < 8; j++) {
                if (s.data[j] < '0' || s.data[j] > '9') {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                        "invalid timezone value");
                    return NGX_CONF_ERROR;
                }
            }

            /* Parse timezone offset, e.g., +0800 or -0200 */
            time_offset = ((s.data[4] - '0') * 10
                            + (s.data[5] - '0')) * 3600;
            time_offset += ((s.data[6] - '0') * 10
                            + (s.data[7] - '0')) * 60;

            if (s.data[3] == '-') {
                time_offset = -time_offset;
            }

            slcf->time_offset = time_offset;

            continue;
        }

        if (value[i].len > 12 && ngx_strncmp(value[i].data, "range_start=", 12) == 0) {
            s.len = value[i].len - 12;
            s.data = value[i].data + 12;

            if (ngx_strlchr(s.data, s.data + s.len, '$') == NULL) {
                if (!ngx_http_secure_link_hmac_is_valid_number(&s)) {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                        "invalid numeric value in start value[i]eter \"%V\"", &s);
                    return NGX_CONF_ERROR;
                }
            }

            ccv.cf = cf;
            ccv.value = &s;
            ccv.complex_value = ngx_palloc(cf->pool,
                                        sizeof(ngx_http_complex_value_t));
            if (ccv.complex_value == NULL) {
                return NGX_CONF_ERROR;
            }

            if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
                return NGX_CONF_ERROR;
            }

            slcf->start = ccv.complex_value;

            continue;
        }

        if (value[i].len >= 10 && ngx_strncmp(value[i].data, "range_end=", 10) == 0) {
            s.len = value[i].len - 10;
            s.data = value[i].data + 10;

            if (ngx_strlchr(s.data, s.data + s.len, '$') == NULL) {
                if (!ngx_http_secure_link_hmac_is_valid_number(&s)) {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                        "invalid numeric value in end value[i]eter \"%V\"", &s);
                    return NGX_CONF_ERROR;
                }
            }

            ccv.cf = cf;
            ccv.value = &s;
            ccv.complex_value = ngx_palloc(cf->pool,
                                        sizeof(ngx_http_complex_value_t));
            if (ccv.complex_value == NULL) {
                return NGX_CONF_ERROR;
            }

            if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
                return NGX_CONF_ERROR;
            }

            slcf->end = ccv.complex_value;
        }
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_secure_link_hmac_check_token(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf)
{
    ngx_http_secure_link_hmac_conf_t *slcf = conf;

    ngx_uint_t                          i, j;
    ngx_str_t                          *value;
    ngx_http_compile_complex_value_t    ccv;
    ngx_str_t                           s;
    time_t                              time_offset;

    if (slcf->token != NGX_CONF_UNSET_PTR && slcf->token != NULL) {
        return "is duplicate";
    }

    value = cf->args->elts;

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = ngx_palloc(cf->pool,
                                sizeof(ngx_http_complex_value_t));
    if (ccv.complex_value == NULL) {
        return NGX_CONF_ERROR;
    }

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    slcf->token = ccv.complex_value;

    if (cf->args->nelts == 3) {

        if (ngx_strncmp(value[2].data, "format=hexdigest", 17) == 0) {
            slcf->token_format = NGX_HTTP_SECURE_LINK_HMAC_HEXDIGEST;

        } else if (ngx_strncmp(value[2].data, "format=base64url", 17) == 0) {
            slcf->token_format = NGX_HTTP_SECURE_LINK_HMAC_BASE64URL;

        } else {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid token format,\"%V\"", &value[2])
            return NGX_CONF_ERROR;
        }

    } else {
        slcf->token_format = NGX_HTTP_SECURE_LINK_HMAC_HEXDIGEST;
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_secure_link_hmac_hex_decode(ngx_str_t *dst, ngx_str_t *src)
{
    size_t      i, half_len;
    u_char     *p;
    ngx_int_t   n;

    if (hex_str.len % 2 != 0) {
        return NGX_ERROR;
    }

    half_len = src->len / 2;

    if (dst->len < half_len) {
        return NGX_ERROR;
    }

    p = src->data;
    for (i = 0; i < half_len; i++) {

        n = ngx_hextoi(p, 2);
        if (n == NGX_ERROR || n > 255) {
            return NGX_ERROR;
        }

        dst->data[i] = (u_char) n;
        p += 2;
    }

    dst->len = half_len;

    return NGX_OK;
}


static ngx_int_t
ngx_http_secure_link_hmac_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var, *v;

    for (v = ngx_http_secure_link_hmac_vars; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}
