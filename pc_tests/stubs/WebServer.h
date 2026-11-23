#pragma once
#include "Arduino.h"
#include <functional>
enum HTTPMethod{HTTP_GET,HTTP_POST}; enum HTTPAuthMethod{BASIC_AUTH};
enum{UPLOAD_FILE_START,UPLOAD_FILE_WRITE,UPLOAD_FILE_END,UPLOAD_FILE_ABORTED};
struct HTTPUpload{int status; size_t currentSize; uint8_t buf[1436];};
typedef std::function<void()> THandlerFunction;
struct WebServer{ WebServer(int){} void on(const char*,HTTPMethod,THandlerFunction){} void on(const char*,HTTPMethod,THandlerFunction,THandlerFunction){}
 void onNotFound(THandlerFunction){} void begin(){} void handleClient(){} String arg(const char*){return "";} bool authenticate(const char*,const char*){return 1;}
 void requestAuthentication(HTTPAuthMethod,const char*){} void sendHeader(const char*,const String&){} void send(int,const char*,const String&){}
 void send_P(int,PGM_P,PGM_P){} HTTPUpload& upload(){static HTTPUpload u; return u;} };
