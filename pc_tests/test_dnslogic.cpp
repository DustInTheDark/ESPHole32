#include "../src/dnslogic.h"
#include <cstdio>
#include <vector>
#include <cstdlib>
std::vector<uint8_t> bl; uint32_t cnt;
bool rd(uint32_t i, uint8_t* o){ memcpy(o,&bl[16+i*5],5); return true; }
bool blocked(const char* n){ return dns::anySuffix(n,[](const char*s){ return dns::sortedContains(cnt,dns::fnv40(s),rd);}); }
int fails=0;
#define CHECK(c) do{ if(!(c)){printf("FAIL line %d: %s\n",__LINE__,#c);fails++;} }while(0)
int main(int argc,char**argv){
  if(argc>1 && !strcmp(argv[1],"hash")){ for(int i=2;i<argc;i++) printf("%s %llu\n",argv[i],(unsigned long long)dns::fnv40(argv[i])); return 0;}
  FILE*f=fopen("blocklist.bin","rb"); fseek(f,0,SEEK_END); long sz=ftell(f); rewind(f); bl.resize(sz); fread(bl.data(),1,sz,f); fclose(f);
  long c=dns::parseHeader(bl.data(),0x220000); CHECK(c==4); cnt=c;
  CHECK(blocked("ads.example.com")); CHECK(blocked("x.y.ads.example.com")); CHECK(blocked("sub.ads.example.com"));
  CHECK(blocked("doubleclick.net")); CHECK(blocked("stats.g.doubleclick.net")); CHECK(blocked("TRACKER.example.NET")); // case-insensitive
  CHECK(blocked("tracker.example.net")); CHECK(blocked("plain-domain.org"));
  CHECK(!blocked("example.com")); CHECK(!blocked("google.com")); CHECK(!blocked("com")); CHECK(!blocked("notads.example.com"));
  // packet: query for Stats.DoubleClick.net AAAA with EDNS OPT record
  uint8_t q[]={0x12,0x34,0x01,0x00, 0,1,0,0,0,0,0,1,
    5,'S','t','a','t','s',11,'D','o','u','b','l','e','C','l','i','c','k',3,'n','e','t',0, 0,28,0,1,
    0, 0,41, 0x10,0, 0,0,0,0, 0,0};
  dns::Question qq; CHECK(dns::parseQuery(q,sizeof q,qq)); CHECK(!strcmp(qq.name,"stats.doubleclick.net")); CHECK(qq.qtype==28);
  CHECK(blocked(qq.name));
  uint8_t out[600]; int n=dns::buildBlocked(q,qq,out);
  FILE* o=fopen("resp_aaaa.bin","wb"); fwrite(out,1,n,o); fclose(o);
  q[sizeof q-1-10-4+2]=0; // no-op safety
  // A query
  uint8_t a[]={0xab,0xcd,0x01,0x00,0,1,0,0,0,0,0,0, 3,'a','d','s',7,'e','x','a','m','p','l','e',3,'c','o','m',0,0,1,0,1};
  CHECK(dns::parseQuery(a,sizeof a,qq)); n=dns::buildBlocked(a,qq,out); o=fopen("resp_a.bin","wb"); fwrite(out,1,n,o); fclose(o);
  // HTTPS (65) query -> NODATA
  a[sizeof a-3]=65; CHECK(dns::parseQuery(a,sizeof a,qq)); n=dns::buildBlocked(a,qq,out); o=fopen("resp_https.bin","wb"); fwrite(out,1,n,o); fclose(o);
  // malformed: truncated, compression pointer, response bit
  CHECK(!dns::parseQuery(a,20,qq)); uint8_t bad[sizeof a]; memcpy(bad,a,sizeof a); bad[12]=0xC0; CHECK(!dns::parseQuery(bad,sizeof bad,qq));
  memcpy(bad,a,sizeof a); bad[2]|=0x80; CHECK(!dns::parseQuery(bad,sizeof bad,qq));
  memcpy(bad,a,sizeof a); bad[12]=60; CHECK(!dns::parseQuery(bad,sizeof bad,qq)); // label overruns
  // fuzz parse for crashes
  srand(1); uint8_t fz[300]; for(int k=0;k<200000;k++){ int L=rand()%300; for(int i=0;i<L;i++) fz[i]=rand(); fz[2]&=0x07; if(dns::parseQuery(fz,L,qq)){ CHECK(qq.end<=L); CHECK(strlen(qq.name)<=253);} }
  printf(fails? "%d FAILURES\n":"all tests passed\n",fails); return fails!=0;
}
