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

#include <stdio.h>
#include <stdlib.h>

#include <array>
#include <string>
#include <unordered_map>
#include <vector>
#include <functional>

#include "stable.h"

#define WRITER_BYTES_START_SIZE 10240

static int last_errorcode = STABLE_ERR_OK;

static inline int SET_ERRORCODE(int code) {
	last_errorcode = code;
	return code;
}

#pragma pack(4)

typedef struct stable_bytes_s *stable_bytes_t;
typedef std::unordered_map<uint64_t, uint32_t> stable_map_t;
typedef std::unordered_map<std::string, stable_field_s> proto_fieldmap_t;
typedef std::function<bool(void* dst, size_t size)> read_func_t;

static uint32_t stable_type_sz[] = {
	0,
	sizeof(int8_t),		// STABLE_BOOL
	sizeof(int8_t),		// STABLE_INT8
	sizeof(int16_t),	// STABLE_INT16
	sizeof(int32_t),	// STABLE_INT32
	sizeof(int64_t),	// STABLE_INT64
	sizeof(float),		// STABLE_FLOAT
	sizeof(double),		// STABLE_DOUBLE
	sizeof(uint32_t),	// STABLE_STRING?
	sizeof(uint32_t),	// STABLE_BEAN
	sizeof(uint32_t),	// STABLE_ARRAY
};

struct stable_bytes_s {
	uint32_t size;
	uint8_t *data;
};

struct stable_field_s {
	stable_type_t type;
	uint32_t offset;
};

struct stable_array_s {
	stable_type_t data_type;
	uint16_t stable_index;
	uint32_t length;
	uint32_t offset;
};

struct stable_proto_s {
	proto_fieldmap_t fields;
	uint32_t size;
};

struct stable_bean_s {
	uint16_t stable_index;
	uint32_t proto;
	uint32_t offset;
};

struct stable_s {
	uint16_t version;
	uint16_t index;

	std::vector<std::string> strings;
	stable_bytes_s body;

	stable_proto_t protos;
	stable_bean_t beans;
	stable_array_t arrays;

	stable_map_t map;
};

/**
 * functions for encoding & decoding
 */
#define ENCODING_BUFFER(T)         \
    union {                        \
        uint8_t *bytes[sizeof(T)]; \
        T v;                       \
    }

template <typename T>
static void decode(uint8_t *bytes, T *value) {
	ENCODING_BUFFER(T)
		buffer;
	memcpy(buffer.bytes, bytes, sizeof(T)); // little endian
	*value = buffer.v;
}

template <typename T>
static bool decode(read_func_t reader, T *value) {
	ENCODING_BUFFER(T)
		buffer;
	reader(buffer.bytes, sizeof(T)); // little endian
	*value = buffer.v;
	return true;
}

template <typename T>
static bool decode(FILE *f, T *value) {
	ENCODING_BUFFER(T)
		buffer;
	size_t readsz = fread(buffer.bytes, 1, sizeof(T), f);
	if (readsz < sizeof(T))
		return false;
	*value = buffer.v;
	return true;
}

template <typename T>
static void encode(uint8_t *bytes, T value) {
	ENCODING_BUFFER(T)
		buffer;
	buffer.v = value;
	memcpy(bytes, buffer.bytes, sizeof(T));
}

template <typename T>
static bool encode(FILE *f, T value) {
	ENCODING_BUFFER(T)
		buffer;
	buffer.v = value;
	size_t writesz = fwrite(buffer.bytes, 1, sizeof(T), f);
	if (writesz < sizeof(T))
		return false;
	return true;
}

#pragma pack()

struct AutoFILE final {
	FILE *file;
	AutoFILE(FILE *f) : file(f) {}
	AutoFILE(const AutoFILE &other) = delete;
	AutoFILE(AutoFILE &&other) : file(other.file) { other.file = NULL; }
	~AutoFILE() { close(); }

	AutoFILE &operator=(const AutoFILE &other) = delete;
	AutoFILE &operator=(AutoFILE &&other) {
		close();
		file = other.file;
		other.file = NULL;
		return *this;
	}

	void close() {
		if (file)
			fclose(file);
		file = NULL;
	}
};

/********************************
 * functions for common accessing
 ***/

static std::vector<stable_t> stable_list;

static inline void post_read_value(const stable_t stable, stable_value* result) {
	switch (result->stable_type) {
	case STABLE_STRING: {
		result->pstr = stable->strings[result->idx].c_str();
		break;
	}
	case STABLE_BEAN: {
		result->pbean = stable->beans + result->idx;
		break;
	}
	case STABLE_ARRAY: {
		result->parray = stable->arrays + result->idx;
		break;
	}
	}
}

STABLE_API stable_value stable_index(const stable_array_t ary, uint32_t index) {
	const stable_t stable = stable_list[ary->stable_index];

	stable_value ret;
	ret.stable_type = ary->data_type;

	uint32_t type_sz = stable_type_sz[ret.stable_type];
	memcpy(ret.bytes, stable->body.data + ary->offset + type_sz * index, type_sz);
	post_read_value(stable, &ret);

	return ret;
}

STABLE_API stable_value stable_field(const stable_bean_t bean, const char *fieldname) {
	const stable_t stable = stable_list[bean->stable_index];

	stable_value ret;
	ret.stable_type = STABLE_NULL;

	stable_proto_t proto = stable->protos + bean->proto;
	auto it = proto->fields.find(fieldname);
	if (it != proto->fields.end()) {
		ret.stable_type = it->second.type;
		uint32_t type_sz = stable_type_sz[it->second.type];
		memcpy(ret.bytes, stable->body.data + bean->offset + it->second.offset, type_sz);
		post_read_value(stable, &ret);
	}
	return ret;
}

STABLE_API const stable_bean_t stable_find(stable_t stable, uint64_t id) {
	auto it = stable->map.find(id);
	if (it != stable->map.end()) {
		return stable->beans + it->second;
	}
	return NULL;
}

/********************************
 * definitions for reading
 ***/

enum stable_opcode {
	OPNONE = 0,
	OPHEADER,
	OPBODY,
	OPSTRING,
	OPPROTO,
	OPBLOCK,
	OPMAP,
	OPEND,
};

static stable_t stable_create(read_func_t reader) {
	stable_t stable = NULL;

	uint8_t op = 0;
	bool ret = true;
	while ((ret = decode(reader, &op)) && op != OPEND) {
		switch (op) {
		case OPHEADER: {
			uint16_t version = 0;
			decode(reader, &version);
			if (version != STABLE_VERSION) {
				SET_ERRORCODE(STABLE_ERR_INVALID_VER);
				return NULL;
			}

			stable = new stable_s();
			stable->index = (uint16_t)stable_list.size();
			stable_list.push_back(stable);

			stable->protos = NULL;
			stable->beans = NULL;
			stable->arrays = NULL;
			stable->protos = NULL;
			stable->body.data = NULL;
			stable->body.size = 0;
			break;
		}
		case OPBODY: {
			stable_bytes_s body;
			decode(reader, &body.size);
			body.data = (uint8_t *)malloc(body.size);
			if (!body.data) {
				stable_delete(stable);
				SET_ERRORCODE(STABLE_ERR_OUT_OF_MEM);
				return NULL;
			}
			reader(body.data, body.size);
			stable->body = body;

			printf("body size: %d\n", body.size);

			break;
		}
		case OPSTRING: {
			size_t buffer_size = 512;
			char* buffer = (char*)malloc(buffer_size);
			if (!buffer) {
				stable_delete(stable);
				SET_ERRORCODE(STABLE_ERR_OUT_OF_MEM);
				return NULL;
			}

			uint32_t count = 0;
			decode(reader, &count);

			stable->strings.reserve(count);

			uint16_t strLength = 0;
			for (uint32_t i = 0; i < count; i++) {
				decode(reader, &strLength);
				if (buffer_size < (size_t)strLength) {
					do {
						buffer_size <<= 1;
					} while (buffer_size < (size_t)strLength);
					buffer = (char*)realloc(buffer, buffer_size);
					if (!buffer) {
						stable_delete(stable);
						SET_ERRORCODE(STABLE_ERR_OUT_OF_MEM);
						return NULL;
					}
				}
				if (!reader(buffer, strLength)) {
					stable_delete(stable);
					SET_ERRORCODE(STABLE_ERR_READING);
					return NULL;
				}
				stable->strings.push_back(std::string(buffer, strLength));
			}

			free(buffer);
			break;
		}
		case OPPROTO: {
			char name_buffer[256];

			uint32_t count = 0;
			decode(reader, &count);

			stable->protos = new stable_proto_s[count];
			if (!stable->protos) {
				stable_delete(stable);
				SET_ERRORCODE(STABLE_ERR_OUT_OF_MEM);
				return NULL;
			}

			uint32_t field_count = 0;
			uint8_t field_name_len;
			stable_field_s field;
			for (uint32_t i = 0; i < count; i++) {
				decode(reader, &field_count);
				stable_proto_t proto = stable->protos + i;
				proto->size = 0;
				for (uint32_t j = 0; j < field_count; j++) {
					decode(reader, &field_name_len);
					reader(name_buffer, field_name_len);
					decode(reader, &field.type);
					decode(reader, &field.offset);
					proto->fields.insert({ std::string(name_buffer, field_name_len), field });
					proto->size += stable_type_sz[field.type];
				}
			}
			break;
		}
		case OPBLOCK: {
			uint32_t count = 0;

			decode(reader, &count);
			stable->beans = new stable_bean_s[count];
			for (uint32_t i = 0; i < count; i++) {
				stable_bean_t bean = stable->beans + i;
				bean->stable_index = stable->index;

				decode(reader, &bean->proto);
				decode(reader, &bean->offset);
			}

			decode(reader, &count);
			stable->arrays = new stable_array_s[count];

			for (uint32_t i = 0; i < count; i++) {
				stable_array_t ary = stable->arrays + i;
				ary->stable_index = stable->index;

				decode(reader, &ary->data_type);
				decode(reader, &ary->length);
				decode(reader, &ary->offset);
			}
			break;
		}
		case OPMAP: {
			uint32_t count = 0;
			decode(reader, &count);

			uint64_t key = 0;
			uint32_t bean_index = 0;

			for (uint32_t i = 0; i < count; i++) {
				decode(reader, &key);
				decode(reader, &bean_index);

				stable->map.insert({ key, bean_index });
			}
			break;
		}
		}
	}

	if (!ret) {
		stable_delete(stable);
		return NULL;
	}

	return stable;
}

STABLE_API stable_t stable_from_file(const char *path) {
	AutoFILE f(fopen(path, "rb"));
	read_func_t reader = [&f](void* buffer, size_t size) {
		return fread(buffer, 1, size, f.file);
	};
	return stable_create(reader);
}

STABLE_API stable_t stable_from_string(const char *data, uint32_t data_size) {
	size_t position = 0;
	read_func_t reader = [data, data_size, &position](void* buffer, size_t size) {
		return 0;
	};
	return stable_create(reader);
}

STABLE_API int stable_delete(stable_t stable) {
	if (!stable) return 0;

	if (stable->protos) delete[] stable->protos;
	if (stable->beans) delete[] stable->beans;
	if (stable->arrays) delete[] stable->arrays;
	if (stable->body.data) free(stable->body.data);

	stable->map.clear();
	stable->protos = NULL;
	stable->beans = NULL;
	stable->arrays = NULL;
	stable->body.data = NULL;
	stable->body.size = 0;
	stable->strings.clear();

	stable_list[stable->index] = NULL;

	return 0;
}

STABLE_API int stable_lasterror() {
	return last_errorcode;
}

#ifdef STABLE_ENABLE_WRITER

/********************************
 * definitions for writing
 ***/

struct stable_body_output_s {
	uint32_t capacity;
	uint32_t size;
	uint8_t *data;
};

typedef std::unordered_map<std::string, uint32_t> stable_string_map_t;
typedef stable_body_output_s* stable_body_output_t;

struct stable_writer_s {
	stable_string_map_t string_map;
	std::vector<std::string> string_list;

	std::vector<stable_proto_t> proto_list;
	std::vector<stable_bean_t> bean_list;
	std::vector<stable_array_t> array_list;

	std::unordered_map<void*, uint32_t> ptr_map;

	stable_map_t map;

	stable_body_output_s body_output;
};

/********************************
 * functions for writing in memory
 ***/

static inline bool writer_allocate_bytes(stable_writer_t writer, size_t size, uint32_t *result) {
	stable_body_output_t output = &writer->body_output;

	if (output->size + size > output->capacity) {
		do {
			output->capacity <<= 1;
		} while (output->size + size > output->capacity);
		output->data = (uint8_t*)realloc(output->data, output->capacity * sizeof(uint8_t*));
	}

	if (!output->data)return false;

	*result = output->size;
	output->size += size;
	return true;
}

static inline bool writer_bytes_assign(stable_writer_t writer, uint32_t offset, stable_value value) {
	uint8_t* dst = writer->body_output.data + offset;

	switch (value.stable_type) {
	case STABLE_NULL: {
		return false;
	}
	case STABLE_STRING: {
		std::string s = value.pstr;
		size_t slen = s.size();
		if (slen > STABLE_STRING_MAX_LEN)
			return false;
		auto its = writer->string_map.find(s);
		uint32_t index = 0;
		if (its != writer->string_map.end()) {
			index = its->second;
		}
		else {
			index = writer->string_list.size();
			writer->string_list.push_back(s);
			writer->string_map.insert(stable_string_map_t::value_type(s, index));
		}
		encode(dst, index);
		break;
	}
	case STABLE_BEAN:
	case STABLE_ARRAY: {
		auto it = writer->ptr_map.find(value.pbean);
		if (it == writer->ptr_map.end())return false;
		encode(dst, it->second);
		break;
	}
	default: {
		uint32_t type_sz = stable_type_sz[value.stable_type];
		memcpy(dst, value.bytes, type_sz);
		break;
	}
	};

	return true;
}

STABLE_API stable_writer_t stable_writer_new() {
	stable_writer_t writer = new stable_writer_s();
	if (!writer) {
		SET_ERRORCODE(STABLE_ERR_OUT_OF_MEM);
		return NULL;
	}

	writer->body_output.data = (uint8_t *)malloc(WRITER_BYTES_START_SIZE * sizeof(uint8_t*));
	if (!writer->body_output.data) {
		SET_ERRORCODE(STABLE_ERR_OUT_OF_MEM);
		return NULL;
	}

	writer->body_output.capacity = WRITER_BYTES_START_SIZE;
	writer->body_output.size = 0;

	SET_ERRORCODE(STABLE_ERR_OK);
	return writer;
}

STABLE_API int stable_writer_delete(stable_writer_t writer) {
	if (writer == NULL)
		return SET_ERRORCODE(STABLE_ERR_NULL_PTR);

	for (auto it = writer->proto_list.begin(); it != writer->proto_list.end(); it++) {
		stable_proto_t proto = *it;
		delete proto;
	}

	for (auto it = writer->bean_list.begin(); it != writer->bean_list.end(); it++) {
		stable_bean_t bean = *it;
		delete bean;
	}

	for (auto it = writer->array_list.begin(); it != writer->array_list.end(); it++) {
		stable_array_t ary = *it;
		delete ary;
	}

	writer->array_list.clear();
	writer->proto_list.clear();
	writer->bean_list.clear();
	writer->string_list.clear();
	writer->string_map.clear();

	free(writer->body_output.data);

	delete(writer);

	return SET_ERRORCODE(STABLE_ERR_OK);
}

STABLE_API stable_proto_t stable_proto_new(stable_writer_t writer) {
	stable_proto_t proto = new stable_proto_s();
	if (proto == NULL) {
		SET_ERRORCODE(STABLE_ERR_OUT_OF_MEM);
		return NULL;
	}

	proto->size = 0;
	writer->ptr_map.insert({ proto, writer->proto_list.size() });
	writer->proto_list.push_back(proto);

	SET_ERRORCODE(STABLE_ERR_OK);
	return proto;
}

STABLE_API int stable_proto_field(stable_writer_t writer, stable_proto_t proto, const char *fieldname, stable_type_t type) {
	size_t fieldlen = strlen(fieldname);
	if (fieldlen > STABLE_NAME_MAX_LEN) {
		return SET_ERRORCODE(STABLE_ERR_STRING_TOO_LONG);
	}

	stable_field_s field;
	field.type = type;
	field.offset = proto->size;

	proto->fields.insert(proto_fieldmap_t::value_type(fieldname, field));
	proto->size += stable_type_sz[type];

	return SET_ERRORCODE(STABLE_ERR_OK);
}

STABLE_API stable_bean_t stable_bean_new(stable_writer_t writer, stable_proto_t proto) {
	if (!proto || !writer) {
		SET_ERRORCODE(STABLE_ERR_NULL_PTR);
		return NULL;
	}
	uint32_t offset = 0;
	if (!writer_allocate_bytes(writer, proto->size, &offset)) {
		SET_ERRORCODE(STABLE_ERR_OUT_OF_MEM);
		return NULL;
	}
	stable_bean_t bean = new stable_bean_s();
	if (bean == NULL) {
		SET_ERRORCODE(STABLE_ERR_OUT_OF_MEM);
		return bean;
	}
	auto it = writer->ptr_map.find(proto);
	if (it == writer->ptr_map.end()) {
		SET_ERRORCODE(STABLE_ERR_INVALID_PROTO);
		return NULL;
	}

	bean->offset = offset;
	bean->proto = it->second;

	writer->ptr_map.insert({ bean, writer->bean_list.size() });
	writer->bean_list.push_back(bean);

	SET_ERRORCODE(STABLE_ERR_OK);
	return bean;
}

STABLE_API int stable_bean_set(stable_writer_t writer, stable_bean_t bean, const char *fieldname, stable_value value) {
	stable_proto_t proto = writer->proto_list[bean->proto];
	auto it = proto->fields.find(fieldname);
	if (it == proto->fields.end())
		return SET_ERRORCODE(STABLE_ERR_FIELD_NOT_FOUND);
	if (it->second.type != value.stable_type)
		return SET_ERRORCODE(STABLE_ERR_TYPE_DISMATCH);
	if (!writer_bytes_assign(writer, bean->offset + it->second.offset, value))
		return SET_ERRORCODE(STABLE_ERR_INVALID_VALUE);
	return SET_ERRORCODE(STABLE_ERR_OK);
}

STABLE_API stable_array_t stable_array_new(stable_writer_t writer, stable_type_t type, uint32_t len) {
	uint32_t offset = 0;
	if (!writer_allocate_bytes(writer, stable_type_sz[type] * len, &offset))return NULL;
	stable_array_t ary = new stable_array_s();
	if (!ary) {
		SET_ERRORCODE(STABLE_ERR_OUT_OF_MEM);
		return NULL;
	}
	ary->data_type = type;
	ary->length = len;
	ary->offset = offset;
	writer->ptr_map.insert({ ary, writer->array_list.size() });
	writer->array_list.push_back(ary);

	SET_ERRORCODE(STABLE_ERR_OK);
	return ary;
}

STABLE_API int stable_array_set(stable_writer_t writer, stable_array_t ary, uint32_t index, stable_value value) {
	if (ary == NULL)
		return SET_ERRORCODE(STABLE_ERR_NULL_PTR);
	if (ary->data_type != value.stable_type)
		return SET_ERRORCODE(STABLE_ERR_TYPE_DISMATCH);
	if (index >= ary->length)
		return SET_ERRORCODE(STABLE_ERR_INDEX_OVERFLOW);
	if (!writer_bytes_assign(writer, ary->offset + (index * stable_type_sz[value.stable_type]), value))
		return SET_ERRORCODE(STABLE_ERR_INVALID_VALUE);
	return SET_ERRORCODE(STABLE_ERR_OK);
}

STABLE_API int stable_set(stable_writer_t writer, uint64_t key, stable_bean_t bean) {
	auto ptrIt = writer->ptr_map.find(bean);
	if (ptrIt == writer->ptr_map.end()) {
		return SET_ERRORCODE(STABLE_ERR_INVALID_VALUE);
	}
	auto it = writer->map.find(key);
	if (it != writer->map.end()) {
		writer->map.erase(it);
	}
	writer->map.insert(stable_map_t::value_type(key, ptrIt->second));
	return SET_ERRORCODE(STABLE_ERR_OK);
}

/********************************
 * functions for writing onto disk
 ***/

static inline int writer_OPHEADER(stable_writer_t writer, FILE *f) {
	encode(f, (uint16_t)STABLE_VERSION);
	return 0;
}

static inline int writer_OPBODY(stable_writer_t writer, FILE *f) {
	stable_body_output_t body_output = &writer->body_output;

	encode(f, body_output->size);
	fwrite(body_output->data, 1, body_output->size, f);

	return 0;
}

static inline int writer_OPSTRING(stable_writer_t writer, FILE *f) {
	encode(f, (uint32_t)writer->string_list.size());
	for (auto it = writer->string_list.begin(); it != writer->string_list.end();
		it++) {
		encode(f, (uint16_t)it->size());
		fwrite(it->c_str(), 1, it->size(), f);
	}
	return 0;
}

static inline int writer_OPPROTO(stable_writer_t writer, FILE *f) {
	uint32_t proto_count = writer->proto_list.size();
	encode(f, proto_count);
	for (uint32_t i = 0; i < proto_count; i++) {
		stable_proto_t proto = writer->proto_list[i];
		encode(f, (uint32_t)proto->fields.size());
		for (auto it = proto->fields.begin(); it != proto->fields.end(); it++) {
			const std::string& name = it->first;
			encode(f, (uint8_t)name.size());
			fwrite(name.c_str(), 1, name.size(), f);

			encode(f, it->second.type);
			encode(f, it->second.offset);
		}
	}
	return 0;
}

static inline int writer_OPBLOCK(stable_writer_t writer, FILE *f) {
	stable_body_output_t body_output = &writer->body_output;

	uint32_t count = (uint32_t)writer->bean_list.size();
	encode(f, count);
	for (uint32_t i = 0; i < count; i++) {
		const stable_bean_t bean = writer->bean_list[i];

		encode(f, bean->proto);
		encode(f, bean->offset);
	}

	count = (uint32_t)writer->array_list.size();
	encode(f, count);
	for (uint32_t i = 0; i < count; i++) {
		const stable_array_t ary = writer->array_list[i];

		encode(f, ary->data_type);
		encode(f, ary->length);
		encode(f, ary->offset);
	}

	return 0;
}

static inline int writer_OPMAP(stable_writer_t writer, FILE *f) {
	uint32_t count = (uint32_t)writer->map.size();
	encode(f, count);
	for (auto it = writer->map.begin(); it != writer->map.end(); it++) {
		encode(f, it->first);
		encode(f, it->second);
	}
	return 0;
}

static inline int writer_OPEND(stable_writer_t writer, FILE *f) {
	return 0;
}

#define WRITER_OP(writer, file, wk)				\
    {											\
		encode(file, (uint8_t)wk);				\
		int ret = writer_##wk(writer, file);	\
		if (ret)								\
			return SET_ERRORCODE(ret); 			\
	}

STABLE_API int stable_writer_save(stable_writer_t writer, const char *name) {
	AutoFILE f(fopen(name, "wb"));

	if (!f.file) return STABLE_ERR_FILE_CREATING;

	WRITER_OP(writer, f.file, OPHEADER);
	WRITER_OP(writer, f.file, OPBODY);
	WRITER_OP(writer, f.file, OPSTRING);
	WRITER_OP(writer, f.file, OPPROTO);
	WRITER_OP(writer, f.file, OPBLOCK);
	WRITER_OP(writer, f.file, OPMAP);
	WRITER_OP(writer, f.file, OPEND);

	return SET_ERRORCODE(STABLE_ERR_OK);
}

#endif // STABLE_ENABLE_WRITER