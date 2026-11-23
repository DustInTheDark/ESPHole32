#pragma once
#include "Arduino.h"
typedef int esp_partition_type_t; typedef int esp_partition_subtype_t;
struct esp_partition_t{ uint32_t size; };
const esp_partition_t* esp_partition_find_first(esp_partition_type_t,esp_partition_subtype_t,const char*);
esp_err_t esp_partition_read(const esp_partition_t*,size_t,void*,size_t); esp_err_t esp_partition_write(const esp_partition_t*,size_t,const void*,size_t);
esp_err_t esp_partition_erase_range(const esp_partition_t*,size_t,size_t);
