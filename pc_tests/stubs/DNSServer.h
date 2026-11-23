#pragma once
#include "IPAddress.h"
struct DNSServer{ bool start(int,const char*,IPAddress){return 1;} void processNextRequest(){} };
