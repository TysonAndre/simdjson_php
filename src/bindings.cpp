/*
  +----------------------------------------------------------------------+
  | simdjson_php                                                         |
  +----------------------------------------------------------------------+
  | This source file is subject to version 2.0 of the Apache license,    |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.apache.org/licenses/LICENSE-2.0.html                      |
  +----------------------------------------------------------------------+
  | Author: Jinxi Wang  <1054636713@qq.com>                              |
  +----------------------------------------------------------------------+
*/


extern "C" {
#include <ext/spl/spl_exceptions.h>
#include <Zend/zend_exceptions.h>
#include "php.h"
#include "php_simdjson.h"
}

#include "simdjson.h"
#include "bindings.h"

#if PHP_VERSION_ID < 70300
#define zend_string_release_ex(s, persistent) zend_string_release((s))
#endif

#define SIMDJSON_DEPTH_CHECK_THRESHOLD 100000

#define SIMDJSON_PHP_SET_VAR_OR_RETURN_ERROR(varname, expr) \
    do { \
        simdjson::error_code _error = (expr).get(varname); \
        if (UNEXPECTED(_error)) { return _error; } \
    } while (0)

void cplus_simdjson_throw_jsonexception(simdjson::error_code error)
{
    zend_throw_exception(simdjson_exception_ce, simdjson::error_message(error), (zend_long) error);
}

static inline simdjson::simdjson_result<simdjson::ondemand::value>
get_key_with_optional_prefix(simdjson::ondemand::document &doc, std::string_view json_pointer)
{
    auto std_pointer = (json_pointer.empty() ? "" : "/") + std::string(json_pointer.begin(), json_pointer.end());
    return doc.at_pointer(std_pointer);
}

static simdjson::error_code
build_parsed_json_cust(simdjson::ondemand::parser& parser, simdjson::ondemand::document &doc, const char *buf, size_t len, bool realloc_if_needed,
                       size_t depth = simdjson::DEFAULT_MAX_DEPTH) {
    if (UNEXPECTED(depth > SIMDJSON_DEPTH_CHECK_THRESHOLD) && depth > len && depth > parser.max_depth()) {
        /*
         * Choose the depth in a way that both avoids frequent reallocations
         * and avoids excessive amounts of wasted memory beyond multiples of the largest string ever decoded.
         *
         * If the depth is already sufficient to parse a string of length `len`,
         * then use the parser's previous depth.
         *
         * Precondition: depth > len
         * Postcondition: depth <= original_depth && depth > len
         */
        if (len < SIMDJSON_DEPTH_CHECK_THRESHOLD) {
            depth = SIMDJSON_DEPTH_CHECK_THRESHOLD;
        } else if (depth > len * 2) {
            // In callers, simdjson_validate_depth ensures depth <= SIMDJSON_MAX_DEPTH (which is <= SIZE_MAX/8),
            // so len * 2 is even smaller than the previous depth and won't overflow.
            depth = len * 2;
        }
    }
    auto error = parser.allocate(len, depth);

    if (error) {
        return error;
    }

    error = parser.iterate(buf, len, realloc_if_needed).get(doc);
    if (error) {
        return error;
    }

    return simdjson::SUCCESS;
}

static zend_always_inline void simdjson_set_zval_to_string(zval *v, std::string_view s) {
    const size_t len = s.size();
    /* In php 7.1, the ZSTR_CHAR macro doesn't exist, and CG(one_char_string)[chr] may or may not be null */
#if PHP_VERSION_ID >= 70200
    if (len <= 1) {
        /*
        A note on performance benefits of the use of interned strings here and elsewhere:

        - PHP doesn't need to allocate a temporary string and initialize it
        - PHP doesn't need to free the temporary string
        - PHP doesn't need to compute the hash of the temporary string
        - Memory usage is reduced because the string representation is reused
        - String comparisons are faster when the strings are the exact same pointer.
        - CPU caches may already have this interned string
        - If all array keys are interned strings, then php can skip the step of
          freeing array keys when garbage collecting the array.
         */
        zend_string *key = len == 1 ? ZSTR_CHAR(s[0]) : ZSTR_EMPTY_ALLOC();
        ZVAL_INTERNED_STR(v, key);
        return;
    }
#endif
    ZVAL_STRINGL(v, s.data(), len);
}

static zend_always_inline void simdjson_add_key_to_symtable(HashTable *ht, const char *buf, size_t len, zval *value) {
#if PHP_VERSION_ID >= 70200
    if (len <= 1) {
        /* Look up the interned string (i.e. not reference counted) */
        zend_string *key = len == 1 ? ZSTR_CHAR(buf[0]) : ZSTR_EMPTY_ALLOC();
        /* Add the key or update the existing value of the key. */
        zend_symtable_update(ht, key, value);
        /* zend_string_release_ex is a no-op for interned strings */
        return;
    }
#endif
    zend_string *key = zend_string_init(buf, len, 0);
    zend_symtable_update(ht, key, value);
    /* Release the reference counted key */
    zend_string_release_ex(key, 0);
}

static zend_always_inline void simdjson_set_zval_to_int64(zval *zv, const int64_t value) {
#if SIZEOF_ZEND_LONG < 8
    if (value != (zend_long)value) {
        ZVAL_DOUBLE(zv, value);
        return;
    }
#endif
    ZVAL_LONG(zv, value);
}

static simdjson::error_code parse_number_from_element(simdjson::ondemand::number v, zval *return_value) {
    switch (v.get_number_type()) {
        case simdjson::ondemand::number_type::signed_integer:
            ZVAL_LONG(return_value, v.get_int64());
            break;
        case simdjson::ondemand::number_type::unsigned_integer:
            ZVAL_DOUBLE(return_value, (double)v.get_uint64());
            break;
        case simdjson::ondemand::number_type::floating_point_number:
            ZVAL_DOUBLE(return_value, v.get_double());
            break;
        EMPTY_SWITCH_DEFAULT_CASE();
    }
    return simdjson::SUCCESS;
}

static simdjson::error_code create_array_from_element(simdjson::ondemand::value element, zval *return_value) /* {{{ */ {
    simdjson::ondemand::json_type type;
    SIMDJSON_PHP_SET_VAR_OR_RETURN_ERROR(type, element.type());

    switch (type) {
        //ASCII sort
        case simdjson::ondemand::json_type::string : {
            std::string_view str;
            SIMDJSON_PHP_SET_VAR_OR_RETURN_ERROR(str, element.get_string());

            simdjson_set_zval_to_string(return_value, str);
            break;
        }
            /*
        case simdjson::ondemand::json_type::INT64 :
            simdjson_set_zval_to_int64(return_value, element.get_int64().value_unsafe());
            break;
            // UINT64 is used for positive values exceeding INT64_MAX
        case simdjson::ondemand::json_type::UINT64 : ZVAL_DOUBLE(return_value, (double)element.get_uint64().value_unsafe());
            break;
            */
        case simdjson::ondemand::json_type::number : {
            simdjson::ondemand::number v;
            SIMDJSON_PHP_SET_VAR_OR_RETURN_ERROR(v, element.get_number());
            return parse_number_from_element(v, return_value);
        }
        case simdjson::ondemand::json_type::boolean : {
            bool b;
            SIMDJSON_PHP_SET_VAR_OR_RETURN_ERROR(b, element.get_bool());
            ZVAL_BOOL(return_value, b);
            break;
        }
        case simdjson::ondemand::json_type::null :
            ZVAL_NULL(return_value);
            break;
        case simdjson::ondemand::json_type::array : {
            auto json_array = element.get_array().value_unsafe();
#if PHP_VERSION_ID >= 70300
            bool is_empty;
            SIMDJSON_PHP_SET_VAR_OR_RETURN_ERROR(is_empty, json_array.is_empty());
            if (is_empty) {
                /* Reuse the immutable empty array to save memory */
                ZVAL_EMPTY_ARRAY(return_value);
                break;
            }
#endif
            zend_array *arr = zend_new_array(0);

            for (auto child : json_array) {
                simdjson::ondemand::value child_value;
                simdjson::error_code error = child.get(child_value);
                zval value;
                if (!error) {
                    error = create_array_from_element(child_value, &value);
                }
                if (error) {
                    zend_array_destroy(arr);
                    return error;
                }
                zend_hash_next_index_insert(arr, &value);
            }
            ZVAL_ARR(return_value, arr);

            break;
        }
        case simdjson::ondemand::json_type::object : {
            auto json_object = element.get_object().value_unsafe();
#if PHP_VERSION_ID >= 70300
            bool is_empty;
            SIMDJSON_PHP_SET_VAR_OR_RETURN_ERROR(is_empty, json_object.is_empty());
            if (is_empty) {
                /* Reuse the immutable empty array to save memory */
                ZVAL_EMPTY_ARRAY(return_value);
                break;
            }
#endif
            zend_array *arr = zend_new_array(0);

            for (auto field : json_object) {
                zval value;
                simdjson::ondemand::value field_value;
                simdjson::error_code error = field.value().get(field_value);
                if (!error) {
                    error = create_array_from_element(field_value, &value);
                }
                if (error) {
                    zend_array_destroy(arr);
                    return error;
                }
                /* TODO consider using zend_string_init_existing_interned in php 8.1+ to save memory and time freeing strings. */
                auto key = field.unescaped_key().value_unsafe();
                simdjson_add_key_to_symtable(arr, key.data(), key.size(), &value);
            }
            ZVAL_ARR(return_value, arr);
            break;
        }
        EMPTY_SWITCH_DEFAULT_CASE();
    }

    return simdjson::SUCCESS;
}

/* }}} */

static zend_always_inline simdjson::error_code create_scalar_from_document(simdjson::ondemand::document &doc, zval *return_value) /* {{{ */ {
    // we have a special case where the JSON document is a single document...
    simdjson::ondemand::json_type type;
    SIMDJSON_PHP_SET_VAR_OR_RETURN_ERROR(type, doc.type());
    switch (type) {
        case simdjson::ondemand::json_type::number: {
            simdjson::ondemand::number v;
            SIMDJSON_PHP_SET_VAR_OR_RETURN_ERROR(v, doc.get_number());
            return parse_number_from_element(v, return_value);
        }
        case simdjson::ondemand::json_type::string:
            simdjson_set_zval_to_string(return_value, doc.get_string().value_unsafe());
            break;
        case simdjson::ondemand::json_type::boolean:
            ZVAL_BOOL(return_value, doc.get_bool().value_unsafe());
            break;
        case simdjson::ondemand::json_type::null:
            ZVAL_NULL(return_value);
            break;
        EMPTY_SWITCH_DEFAULT_CASE();
    }
    return simdjson::SUCCESS;
}
/* }}} */

static inline simdjson::error_code create_array(simdjson::ondemand::document &doc, zval *return_value) /* {{{ */ {
    bool is_scalar;
    simdjson::error_code error = doc.is_scalar().get(is_scalar);
    if (error) {
        return error;
    }
    if (is_scalar) {
        return create_scalar_from_document(doc, return_value);
    }
    simdjson::ondemand::value val;
    SIMDJSON_PHP_SET_VAR_OR_RETURN_ERROR(val, doc);
    return create_array_from_element(val, return_value);
}
/* }}} */

static simdjson::error_code create_object_from_element(simdjson::ondemand::value element, zval *return_value) /* {{{ */ {
    simdjson::ondemand::json_type type;
    SIMDJSON_PHP_SET_VAR_OR_RETURN_ERROR(type, element.type());
    switch (type) {
        //ASCII sort
        case simdjson::ondemand::json_type::string :
            simdjson_set_zval_to_string(return_value, element.get_string().value_unsafe());
            break;
            /*
        case simdjson::ondemand::json_type::INT64 :
            simdjson_set_zval_to_int64(&v, element.get_int64().value_unsafe());
            break;
            // UINT64 is used for positive values exceeding INT64_MAX
        case simdjson::ondemand::json_type::UINT64 : ZVAL_DOUBLE(&v, (double)element.get_uint64().value_unsafe());
            break;
            */
            // TODO parse int type
        case simdjson::ondemand::json_type::number : {
            simdjson::ondemand::number v;
            SIMDJSON_PHP_SET_VAR_OR_RETURN_ERROR(v, element.get_number());
            return parse_number_from_element(v, return_value);
        }
        case simdjson::ondemand::json_type::boolean :
            ZVAL_BOOL(return_value, element.get_bool().value_unsafe());
            break;
        case simdjson::ondemand::json_type::null :
            ZVAL_NULL(return_value);
            break;
        case simdjson::ondemand::json_type::array : {
            simdjson::ondemand::array json_array;
            SIMDJSON_PHP_SET_VAR_OR_RETURN_ERROR(json_array, element.get_array());
#if PHP_VERSION_ID >= 70300
            bool is_empty;
            SIMDJSON_PHP_SET_VAR_OR_RETURN_ERROR(is_empty, json_array.is_empty());
            if (is_empty) {
                /* Reuse the immutable empty array to save memory */
                ZVAL_EMPTY_ARRAY(return_value);
                break;
            }
#endif
            zend_array *arr = zend_new_array(0);

            for (auto child_or_error : json_array) {
                simdjson::ondemand::value child;
                simdjson::error_code error = child_or_error.get(child);
                zval value;
                if (!error) {
                    error = create_object_from_element(child, &value);
                }
                if (error) {
                    zend_array_destroy(arr);
                    return error;
                }
                zend_hash_next_index_insert(arr, &value);
            }
            ZVAL_ARR(return_value, arr);
            break;
        }
        case simdjson::ondemand::json_type::object : {
            auto json_object = element.get_object().value_unsafe();
            object_init(return_value);
#if PHP_VERSION_ID >= 80000
            zend_object *obj = Z_OBJ_P(return_value);
#endif

            for (auto field : json_object) {
                auto json_key = field.unescaped_key().value_unsafe();
                const char *data = json_key.data();
                const size_t size = json_key.size();
				/* PHP 7.1 allowed using the empty string as a property of an object */
                if (UNEXPECTED(data[0] == '\0') && (PHP_VERSION_ID < 70100 || UNEXPECTED(size > 0))) {
                    if (!EG(exception)) {
                        zend_throw_exception(spl_ce_RuntimeException, "Invalid property name", 0);
                    }
                    zval_ptr_dtor(return_value);
                    return simdjson::NUM_ERROR_CODES;
                }
                simdjson::ondemand::value field_value;
                simdjson::error_code error = field.value().get(field_value);
                zval value;
                if (!error) {
                    error = create_object_from_element(field_value, &value);
                }
                if (error) {
                    zval_ptr_dtor(return_value);
                    return error;
                }

                /* Add the key to the object */
#if PHP_VERSION_ID >= 80000
                zend_string *key;
                if (size <= 1) {
                    key = size == 1 ? ZSTR_CHAR(data[0]) : ZSTR_EMPTY_ALLOC();
                } else {
                    key = zend_string_init(data, size, 0);
                }
                zend_std_write_property(obj, key, &value, NULL);
                zend_string_release_ex(key, 0);
#else

# if PHP_VERSION_ID >= 70200
                if (size <= 1) {
                    zval zkey;
                    zend_string *key = size == 1 ? ZSTR_CHAR(data[0]) : ZSTR_EMPTY_ALLOC();
                    ZVAL_INTERNED_STR(&zkey, key);
                    zend_std_write_property(&v, &zkey, &value, NULL);
                } else
# endif
                {
                    zval zkey;
                    ZVAL_STRINGL(&zkey, data, size);
                    zend_std_write_property(&v, &zkey, &value, NULL);
                    zval_ptr_dtor_nogc(&zkey);
                }
#endif
                /* After the key is added to the object (incrementing the reference count) ,
                 * decrement the reference count of the value by one */
                zval_ptr_dtor_nogc(&value);
            }
            break;
        }
        EMPTY_SWITCH_DEFAULT_CASE();
    }
    return simdjson::SUCCESS;
}
/* }}} */

static simdjson::error_code create_object(simdjson::ondemand::document &doc, zval *return_value) /* {{{ */ {
    bool is_scalar;
    simdjson::error_code error = doc.is_scalar().get(is_scalar);
    if (error) {
        return error;
    }
    if (is_scalar) {
        return create_scalar_from_document(doc, return_value);
    }
    simdjson::ondemand::value val;
    SIMDJSON_PHP_SET_VAR_OR_RETURN_ERROR(val, doc);
    return create_object_from_element(val, return_value);
}
/* }}} */

simdjson::ondemand::parser* cplus_simdjson_create_ondemand_parser(void) /* {{{ */ {
    return new simdjson::ondemand::parser();
}

void cplus_simdjson_free_ondemand_parser(simdjson::ondemand::parser* parser) /* {{{ */ {
    delete parser;
}

bool cplus_simdjson_is_valid(simdjson::ondemand::parser& parser, const char *json, size_t len, size_t depth) /* {{{ */ {
    simdjson::ondemand::document doc;
    /* The depth is passed in to ensure this behaves the same way for the same arguments */
    simdjson::error_code error = build_parsed_json_cust(parser, doc, json, len, true, depth);
    if (error) {
        return false;
    }
    return true;
}

/* }}} */

void cplus_simdjson_parse(simdjson::ondemand::parser& parser, const char *json, size_t len, zval *return_value, unsigned char assoc, size_t depth) /* {{{ */ {
    simdjson::ondemand::document doc;
    simdjson::error_code error = build_parsed_json_cust(parser, doc, json, len, true, depth);
    if (error) {
        cplus_simdjson_throw_jsonexception(error);
        return;
    }

    if (assoc) {
        error = create_array(doc, return_value);
    } else {
        error = create_object(doc, return_value);
    }

    if (error) {
        cplus_simdjson_throw_jsonexception(error);
        return;
    }
}
/* }}} */
simdjson::error_code cplus_simdjson_key_value(simdjson::ondemand::parser& parser, const char *json, size_t len, const char *key, zval *return_value, unsigned char assoc,
                              size_t depth) /* {{{ */ {
    simdjson::ondemand::document doc;
    auto error = build_parsed_json_cust(parser, doc, json, len, true, depth);
    if (error) {
        return error;
    }

    simdjson::ondemand::value element;
    error = get_key_with_optional_prefix(doc, key).get(element);

    if (error) {
        return error;
    }

    if (assoc) {
        return create_array_from_element(element, return_value);
    } else {
        return create_object_from_element(element, return_value);
    }
}

/* }}} */

u_short cplus_simdjson_key_exists(simdjson::ondemand::parser& parser, const char *json, size_t len, const char *key, size_t depth) /* {{{ */ {
    simdjson::ondemand::document doc;
    auto error = build_parsed_json_cust(parser, doc, json, len, true, depth);
    if (error) {
        return SIMDJSON_PARSE_KEY_NOEXISTS;
    }
    error = get_key_with_optional_prefix(doc, key).error();
    if (error) {
        return SIMDJSON_PARSE_KEY_NOEXISTS;
    }
    return SIMDJSON_PARSE_KEY_EXISTS;
}

/* }}} */


simdjson::error_code cplus_simdjson_key_count(simdjson::ondemand::parser& parser, const char *json, size_t len, const char *key, zval *return_value, size_t depth) /* {{{ */ {
    simdjson::ondemand::document doc;
    simdjson::ondemand::value element;

    auto error = build_parsed_json_cust(parser, doc, json, len, true, depth);
    if (error) {
        cplus_simdjson_throw_jsonexception(error);
        return error;
    }

    error = get_key_with_optional_prefix(doc, key).get(element);
    if (error) {
        cplus_simdjson_throw_jsonexception(error);
        return error;
    }

    size_t key_count;
    simdjson::ondemand::json_type type;
    SIMDJSON_PHP_SET_VAR_OR_RETURN_ERROR(type, element.type());
    switch (type) {
        //ASCII sort
        case simdjson::ondemand::json_type::array : {
            simdjson::ondemand::array json_array;
            SIMDJSON_PHP_SET_VAR_OR_RETURN_ERROR(json_array, element.get_array());
            SIMDJSON_PHP_SET_VAR_OR_RETURN_ERROR(key_count, json_array.count_elements());
            break;
        }
        case simdjson::ondemand::json_type::object : {
            simdjson::ondemand::object json_object;
            SIMDJSON_PHP_SET_VAR_OR_RETURN_ERROR(json_object, element.get_object());
            SIMDJSON_PHP_SET_VAR_OR_RETURN_ERROR(key_count, json_object.count_fields());
            break;
        }
        default:
            key_count = 0;
            break;
    }
    ZVAL_LONG(return_value, key_count);
    return simdjson::SUCCESS;
}

/* }}} */
