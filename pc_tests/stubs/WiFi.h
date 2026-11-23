#pragma once
#include "IPAddress.h"
enum{WIFI_STA,WIFI_AP_STA}; enum{WL_CONNECTED=3};
struct WiFiClass{ void mode(int){} void setHostname(const char*){} bool config(IPAddress,IPAddress,IPAddress,IPAddress,IPAddress){return 1;} void setAutoReconnect(bool){}
 void begin(const char*,const char*){} int status(){return 0;} void setSleep(bool){} IPAddress localIP(){return {};} void disconnect(bool){} int scanNetworks(){return 0;}
 String SSID(int){return "";} bool softAP(const char*,const char*){return 1;} IPAddress softAPIP(){return {};} int softAPgetStationNum(){return 0;} int RSSI(){return 0;} }; extern WiFiClass WiFi;
