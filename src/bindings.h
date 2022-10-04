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

#include "simdjson.h"

extern zend_class_entry *simdjson_exception_ce;

simdjson::ondemand::parser* cplus_simdjson_create_ondemand_parser(void);
void cplus_simdjson_free_ondemand_parser(simdjson::ondemand::parser* parser);
bool cplus_simdjson_is_valid(simdjson::ondemand::parser& parser, const char *json, size_t len, size_t depth);
void cplus_simdjson_parse(simdjson::ondemand::parser& parser, const char *json, size_t len, zval *return_value, unsigned char assoc, size_t depth);
simdjson::error_code cplus_simdjson_key_value(simdjson::ondemand::parser& parser, const char *json, size_t len, const char *key, zval *return_value, unsigned char assoc, size_t depth);
u_short cplus_simdjson_key_exists(simdjson::ondemand::parser& parser, const char *json, size_t len, const char *key, size_t depth);
simdjson::error_code cplus_simdjson_key_count(simdjson::ondemand::parser& parser, const char *json, size_t len, const char *key, zval *return_value, size_t depth);
void cplus_simdjson_throw_jsonexception(simdjson::error_code error);
