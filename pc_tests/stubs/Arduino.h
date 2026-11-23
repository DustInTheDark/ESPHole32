#pragma once
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <string>
#define PROGMEM
#define FPSTR(p) (p)
typedef const char* PGM_P;
#define LOW 0
#define INPUT_PULLUP 2
uint32_t millis(); void delay(uint32_t); void pinMode(int,int); int digitalRead(int); uint32_t esp_random();
class String { std::string s; public:
 String(){} String(const char*c):s(c){} String(const std::string&x):s(x){} String(int v){s=std::to_string(v);} String(unsigned v){s=std::to_string(v);}
 String(long v){s=std::to_string(v);} String(unsigned long v){s=std::to_string(v);} String(float v,int){s=std::to_string(v);}
 size_t length()const{return s.size();} const char* c_str()const{return s.c_str();} char operator[](size_t i)const{return s[i];}
 String& operator+=(const String&o){s+=o.s;return *this;} String& operator+=(const char*o){s+=o;return *this;} String& operator+=(char c){s+=c;return *this;}
 friend String operator+(const String&a,const String&b){return String(a.s+b.s);} friend String operator+(const char*a,const String&b){return String(std::string(a)+b.s);}
 friend String operator+(const String&a,const char*b){return String(a.s+b);}
 bool operator==(const String&o)const{return s==o.s;} bool operator==(const char*o)const{return s==o;} bool operator!=(const char*o)const{return s!=o;}
 bool equals(const char*o)const{return s==o;} void trim(){} void toLowerCase(){} bool startsWith(const char*)const{return false;} bool endsWith(const char*)const{return false;}
 String substring(int a,int b=-1)const{return String(s.substr(a));} int indexOf(char)const{return -1;} void remove(size_t){} void reserve(size_t){}
 long toInt()const{return 0;} void replace(const char*,const String&){} };
struct HardwareSerial{ void begin(int){} void println(const char* =""){} void print(char){} void printf(const char*,...){} }; extern HardwareSerial Serial;
struct EspClass{ void restart(){} uint32_t getFreeHeap(){return 0;} }; extern EspClass ESP;
typedef struct{int x;} portMUX_TYPE;
#define portMUX_INITIALIZER_UNLOCKED {0}
void portENTER_CRITICAL(portMUX_TYPE*); void portEXIT_CRITICAL(portMUX_TYPE*);
typedef void* SemaphoreHandle_t; SemaphoreHandle_t xSemaphoreCreateMutex(); int xSemaphoreTake(SemaphoreHandle_t,int); int xSemaphoreGive(SemaphoreHandle_t);
#define portMAX_DELAY 0xffffffff
void xTaskCreatePinnedToCore(void(*)(void*),const char*,int,void*,int,void*,int);
typedef int esp_err_t;
#define ESP_OK 0
