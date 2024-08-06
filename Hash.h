#pragma once

// A program to generate Hash.h which implements hash table with open addressing
// more key types and value types can be added here.
// See code below marked with $uint64$ that implements uint64_t to uint64_t map

#if defined(_MSC_VER)
    #define _CRT_SECURE_NO_WARNINGS 1
#endif

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define Hash_mem_alloc malloc
#define Hash_mem_free free
#define Hash_mem_realloc

// Common members of Hash and Set
#define HashCommonMember  \
    uint32_t num_buckets; \
    uint32_t size;        \
    HashFlags* flags

typedef union HashFlags
{
    struct
    {
        bool is_occupied : 1;
        bool is_deleted : 1;
    };
    uint8_t bits;
} HashFlags;

typedef struct HashIter
{
    HashFlags const* flags;
    uint32_t num_buckets;
    uint64_t i;
} HashIter;

// $uint64$ A hash table is a struct with at least the following members
//     uint32_t num_buckets;
//     uint32_t size;
//     HashFlags *flags;
//     [Generic key type] *keys
//     [Generic value type] default_value; // if is Set, this can be omitted
typedef struct Hash
{
    HashCommonMember;
    uint64_t* keys;
    uint64_t* values;
    uint64_t default_value;
} Hash;

typedef struct Set
{
    HashCommonMember;
    uint64_t* keys;
} Set;

typedef struct StringSet
{
    HashCommonMember;
    const char** keys;
} StringSet;

typedef struct StringHash
{
    HashCommonMember;
    const char** keys;
    uint64_t* values;
    uint64_t default_value;
} StringHash;

typedef struct StringStringHash
{
    HashCommonMember;
    const char** keys;
    char** values;
    char* default_value;
} StringStringHash;

typedef struct StringPtrHash
{
    HashCommonMember;
    const char** keys;
    void** values;
    void* default_value;
} StringPtrHash;

// The invalid index which means that the key doesn't exist
#define HASH_INVALID_INDEX UINT32_MAX

// Removes key from h
#define Set_remove(h, key) Hash_remove(h, key)

// Returns the end iterator of h
#define Set_end(h) Hash_end(h)

// Checks if key is in h
#define Set_has(h, key) (Hash_index(h, key) != UINT32_MAX)

// Checks if index 'i' is in h
#define Set_exist(h, i) Hash_exist(h, i)

// Returns the key of at index 'i' in h
#define Set_key(h, i) Hash_key(h, i)

// Returns number of keys in h
#define Set_count(h) Hash_count(h)

// Sets h to empty, keeps capacity
#define Set_reset(h) Hash_reset(h)

// Sets h to empty, frees memory
#define Set_free(h) Hash_free_impl((void**)&(h).keys, NULL, &(h).num_buckets, &(h).size)

// Returns the value of 'key' in 'h', or default_value if 'key' is not in 'h'
#define Hash_get(h, key) ((h).values ? (h).values[(int32_t)Hash_index(h, key)] : (h).default_value)

// Checks if 'key' is in 'h'
#define Hash_has(h, key) (Hash_index(h, key) != UINT32_MAX)

// Returns number of keys in 'h'
#define Hash_count(h) ((h).size)

// Returns the capacity of 'h'
#define Hash_capacity(h) ((h).num_buckets)

// Sets h to empty, frees memory
#define Hash_free(h) Hash_free_impl((void**)&(h).keys, (void**)&(h).values, &(h).num_buckets, &(h).size)

// Sets h to empty, keeps capacity
#define Hash_reset(h) Hash_reset_impl((h).num_buckets, &(h).size, (h).flags)

// Checks if index 'i' is in 'h'
#define Hash_exist(h, i) ((h).num_buckets > (uint32_t)(i) && Hash_key_exist((h).flags[i]))

// Returns the begin iterator of 'h'
#define Hash_begin(h) (Hash_next)((HashIter){.flags = (h).flags, .num_buckets = (h).num_buckets, .i = 0})

// Returns the next iterator of 'h'
#define Hash_next(it) Hash_next((HashIter){.flags = (it).flags, .num_buckets = (it).num_buckets, .i = it.i + 1})

// Returns the end iterator of 'h'
#define Hash_end(it) (it).num_buckets

// Returns the value of index 'i' in 'h'
#define Hash_value(h, i) ((h).values[i])

// Returns the key of index 'i' in 'h'
#define Hash_key(h, i) ((h).keys[i])

// Removes index 'i' from 'h'
#define Hash_remove_index(h, i) (Hash_set_as_deleted(&(h).flags[i]), --(h).size)

// clang-format off

// Adds key and value to h
#define Hash_put(h, key, value, ...)                                            \
    do                                                                          \
    {                                                                           \
        uint32_t TEMP_VAR_NAME(i) = Hash_get_or_insert_index(h, key);           \
        (h).values[TEMP_VAR_NAME(i)] = (value, ## __VA_ARGS__);                  \
    } while (0)

#define Hash_cast_key(hkey, k)                                                  \
    _Generic(hkey, \
        uint64_t: (uint64_t)(k),                                                \
        char const*: (char const*)((uintptr_t)(k)),                             \
        default: (uint64_t)(k))

// Returns the index of 'key' in 'h', if 'key' is not in 'h', inserts 'key'
#define Hash_get_or_insert_index(h, key)                                        \
    _Generic(*(h).keys, \
        uint64_t: Hash_get_or_insert_index_uint64,                              \
        char const*: Hash_get_or_insert_index_cstr)                             \
            (&(h).keys,                                                         \
            &(h).flags,                                                         \
            (void**)&(h).values,                                                \
            &(h).size,                                                          \
            &(h).num_buckets,                                                   \
            Hash_cast_key(*(h).keys, key),                                      \
            &(h).default_value,                                                 \
            sizeof((h).default_value),                                          \
            __FILE__,                                                           \
            __LINE__)

// Returns the index of 'key' in 'h'
#define Hash_index(h, key)                                                      \
    _Generic(*(h).keys, \
        uint64_t: Hash_index_uint64,                                            \
        char const*: Hash_index_cstr)                                           \
            ((h).keys,                                                          \
             (h).flags,                                                         \
             (h).num_buckets,                                                   \
             Hash_cast_key(*(h).keys,                                           \
             key),                                                              \
             false)

// Removes 'key' from 'h'
#define Hash_remove(h, key)                                                     \
    _Generic(*(h).keys, \
        uint64_t: Hash_remove_uint64,                                           \
        char const*: Hash_remove_cstr)                                          \
            ((h).keys,                                                          \
             (h).flags,                                                         \
             &(h).size,                                                         \
             Hash_cast_key(*(h).keys, key),                                     \
             (h).num_buckets)

// Adds 'key' to 'h', Set version
#define Set_put(h, key)                                                         \
    _Generic(*(h).keys, \
        uint64_t: Hash_get_or_insert_index_uint64,                              \
        char const*: Hash_get_or_insert_index_cstr)                             \
        (&(h).keys,                                                             \
         &(h).flags,                                                            \
         NULL, /* values_ptr*/                                                  \
         &(h).size,                                                             \
         &(h).num_buckets,                                                      \
         Hash_cast_key(*(h).keys, key),                                         \
         NULL, /* default_value */                                              \
         0, /* value_bytes */                                                   \
         __FILE__,                                                              \
         __LINE__)

// clang-format on
static inline bool Hash_is_grow_needed(uint32_t size, uint32_t num_buckets)
{
    return size >= num_buckets * 0.77;
}

static inline void Hash_set_as_deleted(HashFlags* flags_ptr)
{
    flags_ptr->is_deleted = true;
}

static inline uint32_t Hash_index_next(uint32_t current, uint32_t d, uint32_t num_buckets)
{
    return (current + d) & (num_buckets - 1);
}

static inline bool Hash_key_exist(HashFlags flags)
{
    return !flags.is_deleted && flags.is_occupied;
}

static inline bool Hash_key_empty(HashFlags flags)
{
    return !flags.is_occupied;
}

static inline uint32_t Hash_get_power_of_two_size(uint32_t x)
{
    --x;
    x |= x >> 1;
    x |= x >> 2;
    x |= x >> 4;
    x |= x >> 8;
    x |= x >> 16;
    ++x;
    return x > 4 ? x : 4;
}

static inline uint32_t Hash_first_index(uint32_t num_buckets, HashFlags const* flags, uint32_t start)
{
    if (flags == NULL)
    {
        return num_buckets;
    }
    for (uint32_t i = start; i != num_buckets; i++)
    {
        if (Hash_key_exist(flags[i]))
        {
            return i;
        }
    }
    return num_buckets;
}

static inline HashIter(Hash_next)(HashIter it)
{
    uint32_t i = Hash_first_index(it.num_buckets, it.flags, it.i);
    return (HashIter){.flags = it.flags, .num_buckets = it.num_buckets, .i = i};
}

static inline void Hash_set_key_value(uint32_t index, void* keys, HashFlags* flags, void* values, uint64_t value_bytes, uint32_t* size, const void* key, uint64_t key_bytes, void* value)
{
    if (flags[index].is_deleted || !flags[index].is_occupied)
    {
        if (size)
        {
            *size += 1;
        }
        flags[index].is_deleted = false;
        flags[index].is_occupied = true;
        memcpy((uint8_t*)keys + index * key_bytes, key, key_bytes);
        if (value_bytes)
        {
            memcpy((uint8_t*)values + index * value_bytes, value, value_bytes);
        }
    }
}

static inline void Hash_free_impl(void** keys_ptr, void** values_ptr, uint32_t* num_buckets_ptr, uint32_t* size_ptr)
{
    Hash_mem_free(*keys_ptr);
    *num_buckets_ptr = 0;
    *keys_ptr = NULL;
    if (values_ptr)
    {
        *values_ptr = NULL;
    }
    *size_ptr = 0;
}

static inline void Hash_reset_impl(uint32_t num_buckets, uint32_t* size_ptr, HashFlags* flags)
{
    if (flags)
    {
        memset(flags, 0, num_buckets * sizeof(HashFlags));
    }
    *size_ptr = 0;
}

static inline bool Hash_key_equal_uint64(uint64_t key1, uint64_t key2)
{
    return key1 == key2;
}

static inline bool Hash_key_equal_cstr(const char* key1, const char* key2)
{
    return strcmp(key1, key2) == 0;
}

static inline uint32_t Hash_hash_func_uint64(uint64_t key, uint32_t num_buckets)
{
    return (key >> 33 ^ key ^ key << 11) & num_buckets - 1;
    uint32_t* key_ptr = (uint32_t*)&key;
}

static inline uint32_t Hash_hash_func_cstr(const char* key, uint32_t num_buckets)
{
    int32_t h = (int32_t)*key;
    if (h)
    {
        for (++key; *key; ++key)
        {
            h = (h << 5) - h + (int32_t)*key;
        }
    }
    return h & (num_buckets - 1);
}

static inline uint32_t Hash_index_uint64(uint64_t const* keys, const HashFlags* flags, uint32_t num_buckets, uint64_t key, bool get_empty)
{
    if (num_buckets == 0)
    {
        return UINT32_MAX;
    }
    uint32_t begin = Hash_hash_func_uint64(key, num_buckets);
    for (uint32_t d = 0, i = begin;; ++d)
    {
        if (flags[i].is_occupied)
        {
            if (!flags[i].is_deleted && Hash_key_equal_uint64(keys[i], key))
            {
                return i;
            }
            i = Hash_index_next(i, d + 1, num_buckets);
            if (i == begin)
            {
                if (get_empty && flags[i].is_deleted)
                {
                    return i;
                }
                break;
            }
        }
        else
        {
            return get_empty ? i : UINT32_MAX;
        }
    }
    return UINT32_MAX;
}

static inline uint32_t Hash_index_cstr(char const* const* keys, const HashFlags* flags, uint32_t num_buckets, char const* key, bool get_empty)
{
    if (num_buckets == 0)
    {
        return UINT32_MAX;
    }
    uint32_t begin = Hash_hash_func_cstr(key, num_buckets);
    for (uint32_t d = 0, i = begin;; ++d)
    {
        if (flags[i].is_occupied)
        {
            if (!flags[i].is_deleted && Hash_key_equal_cstr(keys[i], key))
            {
                return i;
            }
            i = Hash_index_next(i, d + 1, num_buckets);
            if (i == begin)
            {
                if (get_empty && flags[i].is_deleted)
                {
                    return i;
                }
                break;
            }
        }
        else
        {
            return get_empty ? i : UINT32_MAX;
        }
    }
    return UINT32_MAX;
}

static inline uint32_t Hash_index_no_check_uint64(const HashFlags* flags, uint32_t num_buckets, uint64_t key)
{
    uint32_t begin = Hash_hash_func_uint64(key, num_buckets);
    uint32_t i = begin;
    uint32_t d = 0;
    while (Hash_key_exist(flags[i]))
    {
        i = Hash_index_next(i, ++d, num_buckets);
    }
    return i;
}

static inline uint32_t Hash_index_no_check_cstr(const HashFlags* flags, uint32_t num_buckets, char const* key)
{
    uint32_t begin = Hash_hash_func_cstr(key, num_buckets);
    uint32_t i = begin;
    uint32_t d = 0;
    while (Hash_key_exist(flags[i]))
    {
        i = Hash_index_next(i, ++d, num_buckets);
    }
    return i;
}

static inline void Hash_grow_uint64(
    uint32_t grow_size,
    uint64_t** keys_ptr,
    HashFlags** flags_ptr,
    void** values_ptr,
    uint64_t value_bytes,
    void* default_value,
    uint32_t* num_buckets_ptr,
    const char* file,
    uint64_t line)
{
    uint64_t const* keys = *keys_ptr;
    const HashFlags* flags = *flags_ptr;
    uint64_t* new_keys = NULL;
    uint32_t num_buckets = *num_buckets_ptr;
    uint32_t new_buckets = Hash_get_power_of_two_size(grow_size + num_buckets);
    const uint64_t key_bytes = sizeof(**keys_ptr);
    *num_buckets_ptr = new_buckets;
    uint64_t new_alloc_size = new_buckets * (value_bytes + key_bytes + sizeof(HashFlags)) + value_bytes;
    new_keys = Hash_mem_alloc(new_alloc_size);
    HashFlags* new_flags = (HashFlags*)((uint8_t*)new_keys + new_buckets * key_bytes);
    uint8_t* default_value_ptr = (uint8_t*)new_flags + new_buckets * sizeof(HashFlags);
    uint8_t* new_values_ptr = default_value_ptr + value_bytes;
    if (value_bytes)
    {
        memcpy(default_value_ptr, default_value, value_bytes);
    }
    memset(new_flags, 0, new_buckets * sizeof(HashFlags));
    for (uint64_t i = 0; i < num_buckets; i++)
    {
        if (!Hash_key_exist(flags[i]))
        {
            continue;
        }
        uint32_t index = Hash_index_no_check_uint64(new_flags, new_buckets, keys[i]);
        uint8_t* values = value_bytes ? *values_ptr : NULL;
        Hash_set_key_value(index, new_keys, new_flags, new_values_ptr, value_bytes, NULL, &keys[i], sizeof(*new_keys), values + i * value_bytes);
    }
    Hash_mem_free(*keys_ptr);
    *keys_ptr = new_keys;
    *flags_ptr = new_flags;
    if (value_bytes)
    {
        *values_ptr = new_values_ptr;
    }
}

static inline void Hash_grow_cstr(
    uint32_t grow_size,
    char const*** keys_ptr,
    HashFlags** flags_ptr,
    void** values_ptr,
    uint64_t value_bytes,
    void* default_value,
    uint32_t* num_buckets_ptr,
    const char* file,
    uint64_t line)
{
    char const* const* keys = *keys_ptr;
    const HashFlags* flags = *flags_ptr;
    char const** new_keys = NULL;
    uint32_t num_buckets = *num_buckets_ptr;
    uint32_t new_buckets = Hash_get_power_of_two_size(grow_size + num_buckets);
    const uint64_t key_bytes = sizeof(**keys_ptr);
    *num_buckets_ptr = new_buckets;
    uint64_t new_alloc_size = new_buckets * (value_bytes + key_bytes + sizeof(HashFlags)) + value_bytes;
    new_keys = Hash_mem_alloc(new_alloc_size);
    HashFlags* new_flags = (HashFlags*)((uint8_t*)new_keys + new_buckets * key_bytes);
    uint8_t* default_value_ptr = (uint8_t*)new_flags + new_buckets * sizeof(HashFlags);
    uint8_t* new_values_ptr = default_value_ptr + value_bytes;
    if (value_bytes)
    {
        memcpy(default_value_ptr, default_value, value_bytes);
    }
    memset(new_flags, 0, new_buckets * sizeof(HashFlags));
    for (uint64_t i = 0; i < num_buckets; i++)
    {
        if (!Hash_key_exist(flags[i]))
        {
            continue;
        }
        uint32_t index = Hash_index_no_check_cstr(new_flags, new_buckets, keys[i]);
        uint8_t* values = value_bytes ? *values_ptr : NULL;
        Hash_set_key_value(index, new_keys, new_flags, new_values_ptr, value_bytes, NULL, &keys[i], sizeof(*new_keys), values + i * value_bytes);
    }
    Hash_mem_free(*keys_ptr);
    *keys_ptr = new_keys;
    *flags_ptr = new_flags;
    if (value_bytes)
    {
        *values_ptr = new_values_ptr;
    }
}

static inline uint32_t Hash_get_or_insert_index_uint64(
    uint64_t** keys_ptr,
    HashFlags** flags_ptr,
    void** values_ptr,
    uint32_t* size,
    uint32_t* num_buckets_ptr,
    uint64_t key,
    void* default_value,
    uint32_t value_bytes,
    const char* file,
    uint64_t line)
{
    uint64_t const* keys = *keys_ptr;
    HashFlags* flags = *flags_ptr;
    const uint32_t num_buckets = *num_buckets_ptr;
    uint32_t index = Hash_index_uint64(keys, flags, num_buckets, key, true);
    if (index == UINT32_MAX || (Hash_key_empty(flags[index]) && Hash_is_grow_needed(*size + 1, num_buckets)))
    {
        Hash_grow_uint64(1, keys_ptr, flags_ptr, values_ptr, value_bytes, default_value, num_buckets_ptr, file, line);
        index = Hash_index_no_check_uint64(*flags_ptr, *num_buckets_ptr, key);
        if (value_bytes)
        {
            memcpy((uint8_t*)*values_ptr + index * value_bytes, default_value, value_bytes);
        }
    }
    void* values = values_ptr ? *values_ptr : NULL;
    Hash_set_key_value(index, *keys_ptr, *flags_ptr, values, value_bytes, size, &key, sizeof(key), default_value);
    return index;
}

static inline uint32_t Hash_get_or_insert_index_cstr(
    char const*** keys_ptr,
    HashFlags** flags_ptr,
    void** values_ptr,
    uint32_t* size,
    uint32_t* num_buckets_ptr,
    char const* key,
    void* default_value,
    uint32_t value_bytes,
    const char* file,
    uint64_t line)
{
    char const* const* keys = *keys_ptr;
    HashFlags* flags = *flags_ptr;
    const uint32_t num_buckets = *num_buckets_ptr;
    uint32_t index = Hash_index_cstr(keys, flags, num_buckets, key, true);
    if (index == UINT32_MAX || (Hash_key_empty(flags[index]) && Hash_is_grow_needed(*size + 1, num_buckets)))
    {
        Hash_grow_cstr(1, keys_ptr, flags_ptr, values_ptr, value_bytes, default_value, num_buckets_ptr, file, line);
        index = Hash_index_no_check_cstr(*flags_ptr, *num_buckets_ptr, key);
        if (value_bytes)
        {
            memcpy((uint8_t*)*values_ptr + index * value_bytes, default_value, value_bytes);
        }
    }
    void* values = values_ptr ? *values_ptr : NULL;
    Hash_set_key_value(index, *keys_ptr, *flags_ptr, values, value_bytes, size, &key, sizeof(key), default_value);
    return index;
}

static inline void Hash_remove_uint64(uint64_t* keys, HashFlags* flags, uint32_t* size, uint64_t key, uint32_t num_buckets)
{
    const HashFlags* flags_const = flags;
    uint32_t index = Hash_index_uint64(keys, flags_const, num_buckets, key, false);
    if (index != UINT32_MAX)
    {
        Hash_set_as_deleted(&flags[index]);
        --*size;
    }
}

static inline void Hash_remove_cstr(char const** keys, HashFlags* flags, uint32_t* size, char const* key, uint32_t num_buckets)
{
    const HashFlags* flags_const = flags;
    uint32_t index = Hash_index_cstr(keys, flags_const, num_buckets, key, false);
    if (index != UINT32_MAX)
    {
        Hash_set_as_deleted(&flags[index]);
        --*size;
    }
}
