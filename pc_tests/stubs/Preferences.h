#pragma once
#include "Arduino.h"
struct Preferences{ bool begin(const char*,bool){return 1;} void end(){} String getString(const char*,const char*){return "";} size_t putString(const char*,const String&){return 0;} bool remove(const char*){return 1;} };
