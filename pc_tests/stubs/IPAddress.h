#pragma once
#include "Arduino.h"
struct IPAddress{ IPAddress(){} IPAddress(int,int,int,int){} bool fromString(const String&){return true;} operator uint32_t()const{return 0;} String toString()const{return "";} };
