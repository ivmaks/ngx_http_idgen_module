/*
 * Copyright (C) 2025
 * Модуль для генерации ULID, UUIDv4 и UUIDv7 на основе request_id
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#define NGX_HTTP_IDGEN_ULID_LEN    26
#define NGX_HTTP_IDGEN_UUID_LEN    36
#define NGX_HTTP_IDGEN_TIMESTAMP_LEN 8

typedef enum {
    NGX_HTTP_IDGEN_TIMESTAMP_CONNECTION = 0,
    NGX_HTTP_IDGEN_TIMESTAMP_MSEC
} ngx_http_idgen_timestamp_e;

typedef struct {
    ngx_http_idgen_timestamp_e  timestamp_source;
} ngx_http_idgen_conf_t;

typedef struct {
    u_char                     *ulid;
    u_char                     *uuidv4;
    u_char                     *uuidv7;
    ngx_str_t                   request_id;
    unsigned                    request_id_set:1;
} ngx_http_idgen_ctx_t;

/* Объявления функций */
static ngx_int_t ngx_http_idgen_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_idgen_add_variables(ngx_conf_t *cf);
static void *ngx_http_idgen_create_conf(ngx_conf_t *cf);
static char *ngx_http_idgen_merge_conf(ngx_conf_t *cf, void *parent, void *child);

static ngx_int_t ngx_http_idgen_get_request_id(ngx_http_request_t *r,
    ngx_http_idgen_ctx_t *ctx);
static ngx_int_t ngx_http_idgen_generate_ulid(ngx_http_request_t *r,
    ngx_http_idgen_ctx_t *ctx);
static ngx_int_t ngx_http_idgen_generate_uuidv4(ngx_http_request_t *r,
    ngx_http_idgen_ctx_t *ctx);
static ngx_int_t ngx_http_idgen_generate_uuidv7(ngx_http_request_t *r,
    ngx_http_idgen_ctx_t *ctx);

static ngx_int_t ngx_http_idgen_encode_ulid(u_char *ulid, uint64_t timestamp,
    u_char *random_data);
static void ngx_http_idgen_format_uuid(u_char *dst, u_char *src);

/* Имена переменных */
static ngx_str_t  ngx_http_idgen_ulid_name = ngx_string("request_ulid");
static ngx_str_t  ngx_http_idgen_uuidv4_name = ngx_string("request_uuidv4");
static ngx_str_t  ngx_http_idgen_uuidv7_name = ngx_string("request_uuidv7");

/* Перечисление для настройки источника времени */
static ngx_conf_enum_t ngx_http_idgen_timestamp_source_enum[] = {
    { ngx_string("connection_time"), NGX_HTTP_IDGEN_TIMESTAMP_CONNECTION },
    { ngx_string("msec"), NGX_HTTP_IDGEN_TIMESTAMP_MSEC },
    { ngx_null_string, 0 }
};

static ngx_command_t ngx_http_idgen_commands[] = {

    { ngx_string("idgen_timestamp_source"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_idgen_conf_t, timestamp_source),
      (void *) ngx_http_idgen_timestamp_source_enum },

      ngx_null_command
};

/* Контекст модуля */
static ngx_http_module_t ngx_http_idgen_module_ctx = {
    ngx_http_idgen_add_variables,          /* предварительная конфигурация */
    NULL,                                  /* постконфигурация */

    NULL,                                  /* создание основной конфигурации */
    NULL,                                  /* инициализация основной конфигурации */

    NULL,                                  /* создание конфигурации сервера */
    NULL,                                  /* объединение конфигурации сервера */

    ngx_http_idgen_create_conf,            /* создание конфигурации локации */
    ngx_http_idgen_merge_conf              /* объединение конфигурации локации */
};

/* Определение модуля */
ngx_module_t ngx_http_idgen_module = {
    NGX_MODULE_V1,
    &ngx_http_idgen_module_ctx,            /* контекст модуля */
    ngx_http_idgen_commands,               /* директивы модуля */
    NGX_HTTP_MODULE,                       /* тип модуля */
    NULL,                                  /* инициализация master */
    NULL,                                  /* инициализация модуля */
    NULL,                                  /* инициализация процесса */
    NULL,                                  /* инициализация потока */
    NULL,                                  /* завершение потока */
    NULL,                                  /* завершение процесса */
    NULL,                                  /* завершение master */
    NGX_MODULE_V1_PADDING
};

static ngx_int_t
ngx_http_idgen_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var;

    /* Переменная ULID */
    var = ngx_http_add_variable(cf, &ngx_http_idgen_ulid_name, NGX_HTTP_VAR_CHANGEABLE);
    if (var == NULL) {
        return NGX_ERROR;
    }

    var->get_handler = ngx_http_idgen_variable;
    var->data = 0; /* 0 для ULID */

    /* Переменная UUIDv4 */
    var = ngx_http_add_variable(cf, &ngx_http_idgen_uuidv4_name, NGX_HTTP_VAR_CHANGEABLE);
    if (var == NULL) {
        return NGX_ERROR;
    }

    var->get_handler = ngx_http_idgen_variable;
    var->data = 1; /* 1 для UUIDv4 */

    /* Переменная UUIDv7 */
    var = ngx_http_add_variable(cf, &ngx_http_idgen_uuidv7_name, NGX_HTTP_VAR_CHANGEABLE);
    if (var == NULL) {
        return NGX_ERROR;
    }

    var->get_handler = ngx_http_idgen_variable;
    var->data = 2; /* 2 для UUIDv7 */

    return NGX_OK;
}

/* Создание конфигурации */
static void *
ngx_http_idgen_create_conf(ngx_conf_t *cf)
{
    ngx_http_idgen_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_idgen_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * Источник времени по умолчанию - connection_time
     */
    conf->timestamp_source = NGX_HTTP_IDGEN_TIMESTAMP_CONNECTION;

    return conf;
}

/* Объединение конфигурации */
static char *
ngx_http_idgen_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_idgen_conf_t  *prev = parent;
    ngx_http_idgen_conf_t  *conf = child;

    ngx_conf_merge_uint_value(conf->timestamp_source, prev->timestamp_source,
                              NGX_HTTP_IDGEN_TIMESTAMP_CONNECTION);

    return NGX_CONF_OK;
}

/* Обработчик переменных */
static ngx_int_t
ngx_http_idgen_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    ngx_http_idgen_ctx_t   *ctx;
    ngx_int_t               rc;

    ctx = ngx_http_get_module_ctx(r, ngx_http_idgen_module);

    if (ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_idgen_ctx_t));
        if (ctx == NULL) {
            return NGX_ERROR;
        }

        ngx_http_set_ctx(r, ctx, ngx_http_idgen_module);
    }

    switch (data) {
    case 0: /* ULID */
        if (ctx->ulid == NULL) {
            rc = ngx_http_idgen_generate_ulid(r, ctx);
            if (rc != NGX_OK) {
                return NGX_ERROR;
            }
        }
        v->data = ctx->ulid;
        v->len = NGX_HTTP_IDGEN_ULID_LEN;
        break;

    case 1: /* UUIDv4 */
        if (ctx->uuidv4 == NULL) {
            rc = ngx_http_idgen_generate_uuidv4(r, ctx);
            if (rc != NGX_OK) {
                return NGX_ERROR;
            }
        }
        v->data = ctx->uuidv4;
        v->len = NGX_HTTP_IDGEN_UUID_LEN;
        break;

    case 2: /* UUIDv7 */
        if (ctx->uuidv7 == NULL) {
            rc = ngx_http_idgen_generate_uuidv7(r, ctx);
            if (rc != NGX_OK) {
                return NGX_ERROR;
            }
        }
        v->data = ctx->uuidv7;
        v->len = NGX_HTTP_IDGEN_UUID_LEN;
        break;

    default:
        return NGX_ERROR;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}

/* получение request_id из основного модуля nginx */
static ngx_int_t
ngx_http_idgen_get_request_id(ngx_http_request_t *r, ngx_http_idgen_ctx_t *ctx)
{
    ngx_http_variable_value_t  *vv;
    ngx_uint_t                  i;
    u_char                     *p;

    if (ctx->request_id_set) {
        return NGX_OK;
    }

 
    /* Поиск переменной request_id по имени */
    ngx_str_t request_id_name = ngx_string("request_id");
    ngx_uint_t key = ngx_hash_key(request_id_name.data, request_id_name.len);
    
    vv = ngx_http_get_variable(r, &request_id_name, key);
    if (vv == NULL || vv->not_found || vv->len != 32) {
        /* 
         * Если request_id недоступен или имеет неправильную длину,
         * используем буфер, заполненный нулями,
         * используется для наглядности корректности использования request_id
         */
        ctx->request_id.data = ngx_pcalloc(r->pool, 16);
        if (ctx->request_id.data == NULL) {
            return NGX_ERROR;
        }
        ctx->request_id.len = 16;
        ngx_memzero(ctx->request_id.data, 16);
    } else {
        /* Преобразуем шестнадцатеричную строку в бинарные данные */
        ctx->request_id.data = ngx_pcalloc(r->pool, 16);
        if (ctx->request_id.data == NULL) {
            return NGX_ERROR;
        }
        
        ctx->request_id.len = 16;
        p = ctx->request_id.data;
        
        for (i = 0; i < 32; i += 2) {
            *p++ = (ngx_hextoi(&vv->data[i], 2) & 0xff);
        }
    }

    ctx->request_id_set = 1;
    return NGX_OK;
}

/* Генерация ULID */
static ngx_int_t
ngx_http_idgen_generate_ulid(ngx_http_request_t *r, ngx_http_idgen_ctx_t *ctx)
{
    ngx_http_idgen_conf_t  *conf;
    uint64_t                timestamp;
    ngx_time_t             *tp;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_idgen_module);

    /* Получаем временную метку в зависимости от настроек */
    if (conf->timestamp_source == NGX_HTTP_IDGEN_TIMESTAMP_MSEC) {
        tp = ngx_timeofday();
        timestamp = (uint64_t) tp->sec * 1000 + tp->msec;
    } else {
        /* По умолчанию: время соединения на основе времени начала запроса */
        timestamp = (uint64_t) r->start_sec * 1000 + r->start_msec;
    }

    /* Получаем случайные данные из request_id */
    if (ngx_http_idgen_get_request_id(r, ctx) != NGX_OK) {
        return NGX_ERROR;
    }

    ctx->ulid = ngx_pnalloc(r->pool, NGX_HTTP_IDGEN_ULID_LEN + 1);
    if (ctx->ulid == NULL) {
        return NGX_ERROR;
    }

    if (ngx_http_idgen_encode_ulid(ctx->ulid, timestamp, ctx->request_id.data)
        != NGX_OK) {
        return NGX_ERROR;
    }

    ctx->ulid[NGX_HTTP_IDGEN_ULID_LEN] = '\0';
    return NGX_OK;
}

/* Генерация UUIDv4 */
static ngx_int_t
ngx_http_idgen_generate_uuidv4(ngx_http_request_t *r, ngx_http_idgen_ctx_t *ctx)
{
    u_char  *uuid_data;

    /* Получаем случайные данные из request_id */
    if (ngx_http_idgen_get_request_id(r, ctx) != NGX_OK) {
        return NGX_ERROR;
    }

    ctx->uuidv4 = ngx_pnalloc(r->pool, NGX_HTTP_IDGEN_UUID_LEN + 1);
    if (ctx->uuidv4 == NULL) {
        return NGX_ERROR;
    }

    uuid_data = ngx_pnalloc(r->pool, 16);
    if (uuid_data == NULL) {
        return NGX_ERROR;
    }

    /* Копируем данные request_id */
    ngx_memcpy(uuid_data, ctx->request_id.data, 
               ctx->request_id.len > 16 ? 16 : ctx->request_id.len);
    
    /* Устанавливаем версию UUIDv4 (4) и вариант */
    uuid_data[6] = (uuid_data[6] & 0x0f) | 0x40;  /* Версия 4 */
    uuid_data[8] = (uuid_data[8] & 0x3f) | 0x80;  /* Вариант 10xx */

    ngx_http_idgen_format_uuid(ctx->uuidv4, uuid_data);
    ctx->uuidv4[NGX_HTTP_IDGEN_UUID_LEN] = '\0';

    return NGX_OK;
}

/* Генерация UUIDv7 */
static ngx_int_t
ngx_http_idgen_generate_uuidv7(ngx_http_request_t *r, ngx_http_idgen_ctx_t *ctx)
{
    ngx_http_idgen_conf_t  *conf;
    u_char                 *uuid_data;
    uint64_t                timestamp;
    ngx_time_t             *tp;
    uint64_t                timestamp_ms;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_idgen_module);

    /* Получаем временную метку в миллисекундах */
    if (conf->timestamp_source == NGX_HTTP_IDGEN_TIMESTAMP_MSEC) {
        tp = ngx_timeofday();
        timestamp = (uint64_t) tp->sec * 1000 + tp->msec;
    } else {
        /* По умолчанию: время соединения на основе времени начала запроса */
        timestamp = (uint64_t) r->start_sec * 1000 + r->start_msec;
    }
    
    timestamp_ms = timestamp;

    /* Получаем случайные данные из request_id */
    if (ngx_http_idgen_get_request_id(r, ctx) != NGX_OK) {
        return NGX_ERROR;
    }

    ctx->uuidv7 = ngx_pnalloc(r->pool, NGX_HTTP_IDGEN_UUID_LEN + 1);
    if (ctx->uuidv7 == NULL) {
        return NGX_ERROR;
    }

    uuid_data = ngx_pnalloc(r->pool, 16);
    if (uuid_data == NULL) {
        return NGX_ERROR;
    }

    /* Копируем данные request_id для случайной части */
    ngx_memcpy(uuid_data, ctx->request_id.data, 
               ctx->request_id.len > 16 ? 16 : ctx->request_id.len);

    /* 
     * Устанавливаем временную метку в первых 6 байтах (48 бит)
     * Согласно RFC 9562 для UUIDv7:
     * - Байты 0-5: 48-битная временная метка в миллисекундах (big-endian)
     */
    uuid_data[0] = (timestamp_ms >> 40) & 0xff;
    uuid_data[1] = (timestamp_ms >> 32) & 0xff;
    uuid_data[2] = (timestamp_ms >> 24) & 0xff;
    uuid_data[3] = (timestamp_ms >> 16) & 0xff;
    uuid_data[4] = (timestamp_ms >> 8) & 0xff;
    uuid_data[5] = timestamp_ms & 0xff;

    /* Устанавливаем версию UUIDv7 (7) и вариант */
    uuid_data[6] = (uuid_data[6] & 0x0f) | 0x70;  /* Версия 7 */
    uuid_data[8] = (uuid_data[8] & 0x3f) | 0x80;  /* Вариант 10xx */

    ngx_http_idgen_format_uuid(ctx->uuidv7, uuid_data);
    ctx->uuidv7[NGX_HTTP_IDGEN_UUID_LEN] = '\0';

    return NGX_OK;
}

/*
 * Кодирование ULID:
 * - Первые 10 символов: base32 закодированная временная метка (48 бит)
 * - Последние 16 символов: base32 закодированные случайные данные (80 бит)
 */
static ngx_int_t
ngx_http_idgen_encode_ulid(u_char *ulid, uint64_t timestamp, u_char *random_data_16bytes)
{
    static const char base32_chars[] = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    uint64_t ts = timestamp;
    int i;

    // Кодируем временную метку (48 бит) → 10 символов
    for (i = 9; i >= 0; i--) {
        ulid[i] = base32_chars[ts & 0x1f];
        ts >>= 5;
    }

    // Кодируем 10 байт случайности (80 бит) в 16 символов base32
    // random_data_16bytes используется как источник, берем первые 10 байт
    const u_char *r = random_data_16bytes;
    ulid[10 + 0] = base32_chars[(r[0] >> 3) & 0x1f];
    ulid[10 + 1] = base32_chars[((r[0] & 0x07) << 2) | ((r[1] >> 6) & 0x03)];
    ulid[10 + 2] = base32_chars[(r[1] >> 1) & 0x1f];
    ulid[10 + 3] = base32_chars[((r[1] & 0x01) << 4) | ((r[2] >> 4) & 0x0f)];
    ulid[10 + 4] = base32_chars[((r[2] & 0x0f) << 1) | ((r[3] >> 7) & 0x01)];
    ulid[10 + 5] = base32_chars[(r[3] >> 2) & 0x1f];
    ulid[10 + 6] = base32_chars[((r[3] & 0x03) << 3) | ((r[4] >> 5) & 0x07)];
    ulid[10 + 7] = base32_chars[r[4] & 0x1f];
    ulid[10 + 8] = base32_chars[(r[5] >> 3) & 0x1f];
    ulid[10 + 9] = base32_chars[((r[5] & 0x07) << 2) | ((r[6] >> 6) & 0x03)];
    ulid[10 +10] = base32_chars[(r[6] >> 1) & 0x1f];
    ulid[10 +11] = base32_chars[((r[6] & 0x01) << 4) | ((r[7] >> 4) & 0x0f)];
    ulid[10 +12] = base32_chars[((r[7] & 0x0f) << 1) | ((r[8] >> 7) & 0x01)];
    ulid[10 +13] = base32_chars[(r[8] >> 2) & 0x1f];
    ulid[10 +14] = base32_chars[((r[8] & 0x03) << 3) | ((r[9] >> 5) & 0x07)];
    ulid[10 +15] = base32_chars[r[9] & 0x1f];

    return NGX_OK;
}

/*
 * Форматирование бинарных данных UUID в строковое представление
 * xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
 */
static void
ngx_http_idgen_format_uuid(u_char *dst, u_char *src)
{
    static const u_char hex[] = "0123456789abcdef";
    int i, j;

    j = 0;
    for (i = 0; i < 4; i++) {
        dst[j++] = hex[src[i] >> 4];
        dst[j++] = hex[src[i] & 0x0f];
    }
    dst[j++] = '-';

    for (i = 4; i < 6; i++) {
        dst[j++] = hex[src[i] >> 4];
        dst[j++] = hex[src[i] & 0x0f];
    }
    dst[j++] = '-';

    for (i = 6; i < 8; i++) {
        dst[j++] = hex[src[i] >> 4];
        dst[j++] = hex[src[i] & 0x0f];
    }
    dst[j++] = '-';

    for (i = 8; i < 10; i++) {
        dst[j++] = hex[src[i] >> 4];
        dst[j++] = hex[src[i] & 0x0f];
    }
    dst[j++] = '-';

    for (i = 10; i < 16; i++) {
        dst[j++] = hex[src[i] >> 4];
        dst[j++] = hex[src[i] & 0x0f];
    }
    
    dst[j] = '\0';
}
