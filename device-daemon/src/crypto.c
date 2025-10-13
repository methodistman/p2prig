// Minimal SHA-256 and HMAC-SHA256 implementation (public domain style)
// Reference: RFC 2104 (HMAC), FIPS 180-4 (SHA-256)

#include "crypto.h"
#include <string.h>
#include <stdint.h>

typedef struct {
    uint32_t state[8];
    uint64_t bitcount;
    uint8_t buffer[64];
} sha256_ctx;

static uint32_t rotr(uint32_t x, uint32_t n){return (x>>n)|(x<<(32-n));}
static uint32_t Ch(uint32_t x,uint32_t y,uint32_t z){return (x&y)^(~x&z);}    
static uint32_t Maj(uint32_t x,uint32_t y,uint32_t z){return (x&y)^(x&z)^(y&z);} 
static uint32_t S0(uint32_t x){return rotr(x,2)^rotr(x,13)^rotr(x,22);}        
static uint32_t S1(uint32_t x){return rotr(x,6)^rotr(x,11)^rotr(x,25);}        
static uint32_t s0(uint32_t x){return rotr(x,7)^rotr(x,18)^(x>>3);}            
static uint32_t s1(uint32_t x){return rotr(x,17)^rotr(x,19)^(x>>10);}          

static const uint32_t K[64]={
0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};

static void sha256_init(sha256_ctx *c){
    c->state[0]=0x6a09e667; c->state[1]=0xbb67ae85; c->state[2]=0x3c6ef372; c->state[3]=0xa54ff53a;
    c->state[4]=0x510e527f; c->state[5]=0x9b05688c; c->state[6]=0x1f83d9ab; c->state[7]=0x5be0cd19;
    c->bitcount=0; memset(c->buffer,0,64);
}
static void sha256_transform(sha256_ctx *c,const uint8_t b[64]){
    uint32_t w[64]; for(int i=0;i<16;i++){w[i]=(uint32_t)b[i*4]<<24|(uint32_t)b[i*4+1]<<16|(uint32_t)b[i*4+2]<<8|b[i*4+3];}
    for(int i=16;i<64;i++) w[i]=s1(w[i-2])+w[i-7]+s0(w[i-15])+w[i-16];
    uint32_t a=c->state[0],b0=c->state[1],c0=c->state[2],d=c->state[3],e=c->state[4],f=c->state[5],g=c->state[6],h=c->state[7];
    for(int i=0;i<64;i++){
        uint32_t T1=h+S1(e)+Ch(e,f,g)+K[i]+w[i];
        uint32_t T2=S0(a)+Maj(a,b0,c0);
        h=g; g=f; f=e; e=d+T1; d=c0; c0=b0; b0=a; a=T1+T2;
    }
    c->state[0]+=a; c->state[1]+=b0; c->state[2]+=c0; c->state[3]+=d; c->state[4]+=e; c->state[5]+=f; c->state[6]+=g; c->state[7]+=h;
}
static void sha256_update(sha256_ctx *c,const uint8_t *data,size_t len){
    size_t i=(size_t)((c->bitcount>>3)%64); c->bitcount+=((uint64_t)len)<<3;
    size_t fill=64-i; size_t off=0;
    if(len>=fill){ memcpy(c->buffer+i,data,fill); sha256_transform(c,c->buffer); off=fill; for(; off+64<=len; off+=64) sha256_transform(c,data+off); i=0; }
    memcpy(c->buffer+i,data+off,len-off);
}
static void sha256_final(sha256_ctx *c,uint8_t out[32]){
    uint8_t pad[64]; size_t i=(size_t)((c->bitcount>>3)%64);
    size_t padlen = (i<56) ? (56-i) : (120-i);
    memset(pad,0,padlen); pad[0]=0x80; sha256_update(c,pad,padlen);
    uint8_t lenb[8]; for(int j=0;j<8;j++) lenb[7-j]=(uint8_t)(c->bitcount>>(8*j));
    sha256_update(c,lenb,8);
    for(int j=0;j<8;j++){ out[j*4]=(uint8_t)(c->state[j]>>24); out[j*4+1]=(uint8_t)(c->state[j]>>16); out[j*4+2]=(uint8_t)(c->state[j]>>8); out[j*4+3]=(uint8_t)(c->state[j]); }
}

static void sha256(const uint8_t *data,size_t len,uint8_t out[32]){
    sha256_ctx c; sha256_init(&c); sha256_update(&c,data,len); sha256_final(&c,out);
}

int hmac_sha256(const uint8_t *key, size_t key_len,
                const uint8_t *data, size_t data_len,
                uint8_t out[32]) {
    if (!key || !data || !out) return -1;
    uint8_t k_ipad[64], k_opad[64], keyhash[32];
    if (key_len > 64) { sha256(key, key_len, keyhash); key = keyhash; key_len = 32; }
    memset(k_ipad, 0x36, 64); memset(k_opad, 0x5c, 64);
    for (size_t i=0;i<key_len && i<64;i++){ k_ipad[i]^=key[i]; k_opad[i]^=key[i]; }
    uint8_t inner[32];
    // inner = H( (K^ipad) || data )
    sha256_ctx c; sha256_init(&c); sha256_update(&c, k_ipad, 64); sha256_update(&c, data, data_len); sha256_final(&c, inner);
    // out = H( (K^opad) || inner )
    sha256_ctx c2; sha256_init(&c2); sha256_update(&c2, k_opad, 64); sha256_update(&c2, inner, 32); sha256_final(&c2, out);
    return 0;
}
