#pragma once
#include "Arduino.h"
struct File{ operator bool()const{return 1;} int available(){return 0;} String readStringUntil(char){return "";} void print(const String&){} void print(char){} void close(){} };
struct LFS{ bool begin(bool){return 1;} File open(const char*,const char*){return {};} }; extern LFS LittleFS;
