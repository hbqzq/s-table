/*
Copyright(c) 2017 Qizhiqiang
All rights reserved.

Redistribution and use in source and binary forms are permitted
provided that the above copyright notice and this paragraph are
duplicated in all such forms and that any documentation,
advertising materials, and other materials related to such
distribution and use acknowledge that the software was developed
by Qizhiqiang.The name may not be used to endorse or promote 
products derived from this software without specific prior 
written permission. 
THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
*/

#ifndef stable_h
#define stable_h

#include <stdint.h>

#define STABLE_EXPORTS
#define STABLE_ENABLE_WRITER

#ifdef _WIN32
#ifdef __cplusplus
#ifdef STABLE_EXPORTS
#define STABLE_API extern "C" __declspec(dllexport)
#else
#define STABLE_API extern "C" __declspec(dllimport)
#endif
#else
#ifdef STABLE_EXPORTS
#define STABLE_API __declspec(dllexport)
#else
#define STABLE_API __declspec(dllimport)
#endif
#endif
#else
#ifdef __cplusplus
#define STABLE_API extern "C"
#else
#define STABLE_API extern
#endif
#endif

#define STABLE_VERSION 1

#define STABLE_STRING_MAX_LEN 0xffff //string max length: 65535
#define STABLE_NAME_MAX_LEN 0xff //field name max length: 255

#pragma pack(4)

enum {
	STABLE_NULL = 0,
	STABLE_BOOL,
	STABLE_INT8,
	STABLE_INT16,
	STABLE_INT32,
	STABLE_INT64,
	STABLE_FLOAT,	//Just provide an float-point number type definition, 
	STABLE_DOUBLE,	//different float-point calculation on different archs is not considered
	STABLE_STRING,
	STABLE_BEAN,
	STABLE_ARRAY,
};

enum {
	STABLE_ERR_OK = 0,

	STABLE_ERR_OUT_OF_MEM = -1000,
	STABLE_ERR_INVALID_VER,
	STABLE_ERR_READING,

#ifdef STABLE_ENABLE_WRITER
	STABLE_ERR_NULL_PTR = -2000,
	STABLE_ERR_TYPE_DISMATCH,
	STABLE_ERR_FIELD_NOT_FOUND,
	STABLE_ERR_INVALID_VALUE,
	STABLE_ERR_OOM,
	STABLE_ERR_INDEX_OVERFLOW,
	STABLE_ERR_STRING_TOO_LONG,
	STABLE_ERR_INVALID_PROTO,
	STABLE_ERR_FILE_CREATING,
#endif
};

typedef uint16_t stable_type_t;

typedef struct stable_field_s *stable_field_t;
typedef struct stable_proto_s *stable_proto_t;

typedef struct stable_bean_s *stable_bean_t;
typedef struct stable_array_s *stable_array_t;

typedef struct stable_s *stable_t;

typedef struct
{
	uint16_t stable_type;
	union {
		bool b;
		int8_t i8;
		int16_t i16;
		int32_t i32;
		int64_t i64;
		float f32;
		double f64;
		const char *pstr;
		stable_bean_t pbean;
		stable_array_t parray;
		uint32_t idx;
		uint8_t bytes[8];
	};
} stable_value;

#define STABLE_IS_NULL(v) (v.stable_type == STABLE_NULL)

#pragma pack()

STABLE_API stable_t stable_from_file(const char *path);
STABLE_API stable_t stable_from_string(const char *data, uint32_t data_size);
STABLE_API int stable_delete(stable_t stable);

STABLE_API const stable_bean_t stable_find(const stable_t stable, uint64_t id);

STABLE_API stable_value stable_index(const stable_array_t ary, uint32_t index);
STABLE_API stable_value stable_field(const stable_bean_t bean, const char* fieldname);

STABLE_API int stable_lasterror();

#ifdef STABLE_ENABLE_WRITER

typedef struct stable_writer_s *stable_writer_t;

STABLE_API stable_writer_t stable_writer_new();
STABLE_API int stable_writer_delete(stable_writer_t writer);
STABLE_API int stable_writer_save(stable_writer_t writer, const char *name);

STABLE_API stable_proto_t stable_proto_new(stable_writer_t writer);
STABLE_API int stable_proto_field(stable_writer_t writer, stable_proto_t proto, const char* fieldname, stable_type_t type);

STABLE_API stable_bean_t stable_bean_new(stable_writer_t writer, stable_proto_t proto);
STABLE_API int stable_bean_set(stable_writer_t writer, stable_bean_t bean, const char* fieldname, stable_value value);

STABLE_API stable_array_t stable_array_new(stable_writer_t writer, stable_type_t type, uint32_t len);
STABLE_API int stable_array_set(stable_writer_t writer, stable_array_t ary, uint32_t index, stable_value item);

STABLE_API int stable_set(stable_writer_t writer, uint64_t key, stable_bean_t bean);

#endif //STABLE_ENABLE_WRITER

#endif //stable_h