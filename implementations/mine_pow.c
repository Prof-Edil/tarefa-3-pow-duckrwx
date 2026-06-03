#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#include <time.h>

#define THREADS 4
#define ROTR(x,n) (((x) >> (n)) | ((x) << (32-(n))))
#define CH(x,y,z) (((x)&(y)) ^ (~(x)&(z)))
#define MAJ(x,y,z) (((x)&(y)) ^ ((x)&(z)) ^ ((y)&(z)))
#define EP0(x) (ROTR(x,2) ^ ROTR(x,13) ^ ROTR(x,22))
#define EP1(x) (ROTR(x,6) ^ ROTR(x,11) ^ ROTR(x,25))
#define SIG0(x) (ROTR(x,7) ^ ROTR(x,18) ^ ((x)>>3))
#define SIG1(x) (ROTR(x,17) ^ ROTR(x,19) ^ ((x)>>10))

static const uint32_t K[64] = {
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};
static const char *PREV="00000000d1145790a8694403d4063f323d499e655c83426834d4ce2f8dd4a2ee";
static const char *MRKL="c0a692de10b69e2381a2856dcb0d0736dcd307bf25af7ce74831bf25793de626";
static atomic_int found=0;
static unsigned char found_header[80], found_hash[32];
static pthread_mutex_t lock=PTHREAD_MUTEX_INITIALIZER;

static int hexval(char c){ if(c>='0'&&c<='9')return c-'0'; if(c>='a'&&c<='f')return c-'a'+10; if(c>='A'&&c<='F')return c-'A'+10; return 0; }
static void hex_to_bytes(const char *hex, unsigned char *out, size_t n){ for(size_t i=0;i<n;i++) out[i]=(hexval(hex[2*i])<<4)|hexval(hex[2*i+1]); }
static void put_be32(unsigned char*p,uint32_t x){p[0]=x>>24;p[1]=x>>16;p[2]=x>>8;p[3]=x;}
static void put_be64(unsigned char*p,uint64_t x){for(int i=7;i>=0;i--){p[i]=x&255;x>>=8;}}
static uint32_t rd32(const unsigned char*p){return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3];}

static void compress(uint32_t state[8], const unsigned char block[64]){
    uint32_t w[64],a,b,c,d,e,f,g,h,t1,t2;
    for(int i=0;i<16;i++) w[i]=rd32(block+4*i);
    for(int i=16;i<64;i++) w[i]=SIG1(w[i-2])+w[i-7]+SIG0(w[i-15])+w[i-16];
    a=state[0];b=state[1];c=state[2];d=state[3];e=state[4];f=state[5];g=state[6];h=state[7];
    for(int i=0;i<64;i++){t1=h+EP1(e)+CH(e,f,g)+K[i]+w[i];t2=EP0(a)+MAJ(a,b,c);h=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;}
    state[0]+=a;state[1]+=b;state[2]+=c;state[3]+=d;state[4]+=e;state[5]+=f;state[6]+=g;state[7]+=h;
}

static void sha256_80(const unsigned char msg[80], unsigned char out[32]){
    uint32_t st[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    unsigned char b1[64], b2[64];
    memcpy(b1,msg,64); compress(st,b1);
    memset(b2,0,64); memcpy(b2,msg+64,16); b2[16]=0x80; put_be64(b2+56,640);
    compress(st,b2);
    for(int i=0;i<8;i++) put_be32(out+4*i,st[i]);
}
static int ok(const unsigned char h[32]){return h[0]==0&&h[1]==0&&h[2]==0&&h[3]==0;}

typedef struct{int tid;} Arg;
static void *worker(void *p){
    int tid=((Arg*)p)->tid; unsigned char header[80], hash[32];
    memset(header,0,80); put_be32(header,2); hex_to_bytes(PREV,header+4,32); hex_to_bytes(MRKL,header+36,32);
    uint64_t checked=0; time_t last=time(NULL);
    for(uint32_t ts=1231000000u+tid; ts<=1231723825u && !atomic_load(&found); ts+=THREADS){
        put_be32(header+68,ts);
        for(uint64_t nonce=0; nonce<UINT64_MAX && !atomic_load(&found); nonce++){
            put_be64(header+72,nonce); sha256_80(header,hash); checked++;
            if(ok(hash)){pthread_mutex_lock(&lock); if(!found){memcpy(found_header,header,80);memcpy(found_hash,hash,32);atomic_store(&found,1);} pthread_mutex_unlock(&lock); return NULL;}
            if(tid==0 && (checked & 0x3ffffff)==0){time_t now=time(NULL); if(now!=last){fprintf(stderr,"thread0 %lluM ts %u\n",(unsigned long long)(checked/1000000),ts); last=now;}}
        }
    }
    return NULL;
}
int main(){pthread_t th[THREADS]; Arg a[THREADS]; for(int i=0;i<THREADS;i++){a[i].tid=i; pthread_create(&th[i],0,worker,&a[i]);} for(int i=0;i<THREADS;i++) pthread_join(th[i],0); if(!found)return 1; for(int i=0;i<80;i++) printf("%02x",found_header[i]); printf("\n"); fprintf(stderr,"hash "); for(int i=0;i<32;i++) fprintf(stderr,"%02x",found_hash[i]); fprintf(stderr,"\n");}
