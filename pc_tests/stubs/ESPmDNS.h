#pragma once
struct MDNSc{ bool begin(const char*){return 1;} void addService(const char*,const char*,int){} }; extern MDNSc MDNS;
