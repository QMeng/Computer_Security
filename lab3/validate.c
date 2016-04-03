
// #define _BSD_SOURCE
#include <sys/types.h> // Defines BYTE_ORDER, iff _BSD_SOURCE is defined
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include <inttypes.h>
#include <ctype.h>
#include <stdlib.h>
#include <math.h>
#include <time.h>

#define SHA1_BLOCKSIZE     64
#define SHA1_DIGEST_LENGTH 20

typedef struct {
  uint32_t digest[8];
  uint32_t count_lo, count_hi;
  uint8_t  data[SHA1_BLOCKSIZE];
  int      local;
} SHA1_INFO;

#if !defined(BYTE_ORDER)
#if defined(_BIG_ENDIAN)
#define BYTE_ORDER 4321
#elif defined(_LITTLE_ENDIAN)
#define BYTE_ORDER 1234
#else
#error Need to define BYTE_ORDER
#endif
#endif

#ifndef TRUNC32
  #define TRUNC32(x)  ((x) & 0xffffffffL)
#endif

/* SHA f()-functions */
#define f1(x,y,z)    ((x & y) | (~x & z))
#define f2(x,y,z)    (x ^ y ^ z)
#define f3(x,y,z)    ((x & y) | (x & z) | (y & z))
#define f4(x,y,z)    (x ^ y ^ z)

/* SHA constants */
#define CONST1        0x5a827999L
#define CONST2        0x6ed9eba1L
#define CONST3        0x8f1bbcdcL
#define CONST4        0xca62c1d6L

/* truncate to 32 bits -- should be a null op on 32-bit machines */
#define T32(x)    ((x) & 0xffffffffL)

/* 32-bit rotate */
#define R32(x,n)    T32(((x << n) | (x >> (32 - n))))

/* the generic case, for when the overall rotation is not unraveled */
#define FG(n)    \
    T = T32(R32(A,5) + f##n(B,C,D) + E + *WP++ + CONST##n);    \
    E = D; D = C; C = R32(B,30); B = A; A = T

/* specific cases, for when the overall rotation is unraveled */
#define FA(n)    \
    T = T32(R32(A,5) + f##n(B,C,D) + E + *WP++ + CONST##n); B = R32(B,30)

#define FB(n)    \
    E = T32(R32(T,5) + f##n(A,B,C) + D + *WP++ + CONST##n); A = R32(A,30)

#define FC(n)    \
    D = T32(R32(E,5) + f##n(T,A,B) + C + *WP++ + CONST##n); T = R32(T,30)

#define FD(n)    \
    C = T32(R32(D,5) + f##n(E,T,A) + B + *WP++ + CONST##n); E = R32(E,30)

#define FE(n)    \
    B = T32(R32(C,5) + f##n(D,E,T) + A + *WP++ + CONST##n); D = R32(D,30)

#define FT(n)    \
    A = T32(R32(B,5) + f##n(C,D,E) + T + *WP++ + CONST##n); C = R32(C,30)


static void
sha1_transform(SHA1_INFO *sha1_info)
{
    int i;
    uint8_t *dp;
    uint32_t T, A, B, C, D, E, W[80], *WP;

    dp = sha1_info->data;

#undef SWAP_DONE

#if BYTE_ORDER == 1234
#define SWAP_DONE
    for (i = 0; i < 16; ++i) {
        T = *((uint32_t *) dp);
        dp += 4;
        W[i] = 
            ((T << 24) & 0xff000000) |
            ((T <<  8) & 0x00ff0000) |
            ((T >>  8) & 0x0000ff00) | ((T >> 24) & 0x000000ff);
    }
#endif

#if BYTE_ORDER == 4321
#define SWAP_DONE
    for (i = 0; i < 16; ++i) {
        T = *((uint32_t *) dp);
        dp += 4;
        W[i] = TRUNC32(T);
    }
#endif

#if BYTE_ORDER == 12345678
#define SWAP_DONE
    for (i = 0; i < 16; i += 2) {
        T = *((uint32_t *) dp);
        dp += 8;
        W[i] =  ((T << 24) & 0xff000000) | ((T <<  8) & 0x00ff0000) |
            ((T >>  8) & 0x0000ff00) | ((T >> 24) & 0x000000ff);
        T >>= 32;
        W[i+1] = ((T << 24) & 0xff000000) | ((T <<  8) & 0x00ff0000) |
            ((T >>  8) & 0x0000ff00) | ((T >> 24) & 0x000000ff);
    }
#endif

#if BYTE_ORDER == 87654321
#define SWAP_DONE
    for (i = 0; i < 16; i += 2) {
        T = *((uint32_t *) dp);
        dp += 8;
        W[i] = TRUNC32(T >> 32);
        W[i+1] = TRUNC32(T);
    }
#endif

#ifndef SWAP_DONE
#define SWAP_DONE
    for (i = 0; i < 16; ++i) {
        T = *((uint32_t *) dp);
        dp += 4;
        W[i] = TRUNC32(T);
    }
#endif /* SWAP_DONE */

    for (i = 16; i < 80; ++i) {
    W[i] = W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16];
    W[i] = R32(W[i], 1);
    }
    A = sha1_info->digest[0];
    B = sha1_info->digest[1];
    C = sha1_info->digest[2];
    D = sha1_info->digest[3];
    E = sha1_info->digest[4];
    WP = W;
#ifdef UNRAVEL
    FA(1); FB(1); FC(1); FD(1); FE(1); FT(1); FA(1); FB(1); FC(1); FD(1);
    FE(1); FT(1); FA(1); FB(1); FC(1); FD(1); FE(1); FT(1); FA(1); FB(1);
    FC(2); FD(2); FE(2); FT(2); FA(2); FB(2); FC(2); FD(2); FE(2); FT(2);
    FA(2); FB(2); FC(2); FD(2); FE(2); FT(2); FA(2); FB(2); FC(2); FD(2);
    FE(3); FT(3); FA(3); FB(3); FC(3); FD(3); FE(3); FT(3); FA(3); FB(3);
    FC(3); FD(3); FE(3); FT(3); FA(3); FB(3); FC(3); FD(3); FE(3); FT(3);
    FA(4); FB(4); FC(4); FD(4); FE(4); FT(4); FA(4); FB(4); FC(4); FD(4);
    FE(4); FT(4); FA(4); FB(4); FC(4); FD(4); FE(4); FT(4); FA(4); FB(4);
    sha1_info->digest[0] = T32(sha1_info->digest[0] + E);
    sha1_info->digest[1] = T32(sha1_info->digest[1] + T);
    sha1_info->digest[2] = T32(sha1_info->digest[2] + A);
    sha1_info->digest[3] = T32(sha1_info->digest[3] + B);
    sha1_info->digest[4] = T32(sha1_info->digest[4] + C);
#else /* !UNRAVEL */
#ifdef UNROLL_LOOPS
    FG(1); FG(1); FG(1); FG(1); FG(1); FG(1); FG(1); FG(1); FG(1); FG(1);
    FG(1); FG(1); FG(1); FG(1); FG(1); FG(1); FG(1); FG(1); FG(1); FG(1);
    FG(2); FG(2); FG(2); FG(2); FG(2); FG(2); FG(2); FG(2); FG(2); FG(2);
    FG(2); FG(2); FG(2); FG(2); FG(2); FG(2); FG(2); FG(2); FG(2); FG(2);
    FG(3); FG(3); FG(3); FG(3); FG(3); FG(3); FG(3); FG(3); FG(3); FG(3);
    FG(3); FG(3); FG(3); FG(3); FG(3); FG(3); FG(3); FG(3); FG(3); FG(3);
    FG(4); FG(4); FG(4); FG(4); FG(4); FG(4); FG(4); FG(4); FG(4); FG(4);
    FG(4); FG(4); FG(4); FG(4); FG(4); FG(4); FG(4); FG(4); FG(4); FG(4);
#else /* !UNROLL_LOOPS */
    for (i =  0; i < 20; ++i) { FG(1); }
    for (i = 20; i < 40; ++i) { FG(2); }
    for (i = 40; i < 60; ++i) { FG(3); }
    for (i = 60; i < 80; ++i) { FG(4); }
#endif /* !UNROLL_LOOPS */
    sha1_info->digest[0] = T32(sha1_info->digest[0] + A);
    sha1_info->digest[1] = T32(sha1_info->digest[1] + B);
    sha1_info->digest[2] = T32(sha1_info->digest[2] + C);
    sha1_info->digest[3] = T32(sha1_info->digest[3] + D);
    sha1_info->digest[4] = T32(sha1_info->digest[4] + E);
#endif /* !UNRAVEL */
}

/* initialize the SHA digest */

void
sha1_init(SHA1_INFO *sha1_info)
{
    sha1_info->digest[0] = 0x67452301L;
    sha1_info->digest[1] = 0xefcdab89L;
    sha1_info->digest[2] = 0x98badcfeL;
    sha1_info->digest[3] = 0x10325476L;
    sha1_info->digest[4] = 0xc3d2e1f0L;
    sha1_info->count_lo = 0L;
    sha1_info->count_hi = 0L;
    sha1_info->local = 0;
}

/* update the SHA digest */

void
sha1_update(SHA1_INFO *sha1_info, const uint8_t *buffer, int count)
{
    int i;
    uint32_t clo;

    clo = T32(sha1_info->count_lo + ((uint32_t) count << 3));
    if (clo < sha1_info->count_lo) {
    ++sha1_info->count_hi;
    }
    sha1_info->count_lo = clo;
    sha1_info->count_hi += (uint32_t) count >> 29;
    if (sha1_info->local) {
    i = SHA1_BLOCKSIZE - sha1_info->local;
    if (i > count) {
        i = count;
    }
    memcpy(((uint8_t *) sha1_info->data) + sha1_info->local, buffer, i);
    count -= i;
    buffer += i;
    sha1_info->local += i;
    if (sha1_info->local == SHA1_BLOCKSIZE) {
        sha1_transform(sha1_info);
    } else {
        return;
    }
    }
    while (count >= SHA1_BLOCKSIZE) {
    memcpy(sha1_info->data, buffer, SHA1_BLOCKSIZE);
    buffer += SHA1_BLOCKSIZE;
    count -= SHA1_BLOCKSIZE;
    sha1_transform(sha1_info);
    }
    memcpy(sha1_info->data, buffer, count);
    sha1_info->local = count;
}


static void
sha1_transform_and_copy(unsigned char digest[20], SHA1_INFO *sha1_info)
{
    sha1_transform(sha1_info);
    digest[ 0] = (unsigned char) ((sha1_info->digest[0] >> 24) & 0xff);
    digest[ 1] = (unsigned char) ((sha1_info->digest[0] >> 16) & 0xff);
    digest[ 2] = (unsigned char) ((sha1_info->digest[0] >>  8) & 0xff);
    digest[ 3] = (unsigned char) ((sha1_info->digest[0]      ) & 0xff);
    digest[ 4] = (unsigned char) ((sha1_info->digest[1] >> 24) & 0xff);
    digest[ 5] = (unsigned char) ((sha1_info->digest[1] >> 16) & 0xff);
    digest[ 6] = (unsigned char) ((sha1_info->digest[1] >>  8) & 0xff);
    digest[ 7] = (unsigned char) ((sha1_info->digest[1]      ) & 0xff);
    digest[ 8] = (unsigned char) ((sha1_info->digest[2] >> 24) & 0xff);
    digest[ 9] = (unsigned char) ((sha1_info->digest[2] >> 16) & 0xff);
    digest[10] = (unsigned char) ((sha1_info->digest[2] >>  8) & 0xff);
    digest[11] = (unsigned char) ((sha1_info->digest[2]      ) & 0xff);
    digest[12] = (unsigned char) ((sha1_info->digest[3] >> 24) & 0xff);
    digest[13] = (unsigned char) ((sha1_info->digest[3] >> 16) & 0xff);
    digest[14] = (unsigned char) ((sha1_info->digest[3] >>  8) & 0xff);
    digest[15] = (unsigned char) ((sha1_info->digest[3]      ) & 0xff);
    digest[16] = (unsigned char) ((sha1_info->digest[4] >> 24) & 0xff);
    digest[17] = (unsigned char) ((sha1_info->digest[4] >> 16) & 0xff);
    digest[18] = (unsigned char) ((sha1_info->digest[4] >>  8) & 0xff);
    digest[19] = (unsigned char) ((sha1_info->digest[4]      ) & 0xff);
}

/* finish computing the SHA digest */
void
sha1_final(SHA1_INFO *sha1_info, uint8_t digest[20])
{
    int count;
    uint32_t lo_bit_count, hi_bit_count;

    lo_bit_count = sha1_info->count_lo;
    hi_bit_count = sha1_info->count_hi;
    count = (int) ((lo_bit_count >> 3) & 0x3f);
    ((uint8_t *) sha1_info->data)[count++] = 0x80;
    if (count > SHA1_BLOCKSIZE - 8) {
    memset(((uint8_t *) sha1_info->data) + count, 0, SHA1_BLOCKSIZE - count);
    sha1_transform(sha1_info);
    memset((uint8_t *) sha1_info->data, 0, SHA1_BLOCKSIZE - 8);
    } else {
    memset(((uint8_t *) sha1_info->data) + count, 0,
        SHA1_BLOCKSIZE - 8 - count);
    }
    sha1_info->data[56] = (uint8_t)((hi_bit_count >> 24) & 0xff);
    sha1_info->data[57] = (uint8_t)((hi_bit_count >> 16) & 0xff);
    sha1_info->data[58] = (uint8_t)((hi_bit_count >>  8) & 0xff);
    sha1_info->data[59] = (uint8_t)((hi_bit_count >>  0) & 0xff);
    sha1_info->data[60] = (uint8_t)((lo_bit_count >> 24) & 0xff);
    sha1_info->data[61] = (uint8_t)((lo_bit_count >> 16) & 0xff);
    sha1_info->data[62] = (uint8_t)((lo_bit_count >>  8) & 0xff);
    sha1_info->data[63] = (uint8_t)((lo_bit_count >>  0) & 0xff);
    sha1_transform_and_copy(digest, sha1_info);
}






static int
validateHOTP(char* secret_hex, char * HOTP_string)
{    
  printf("\n\nThis is the validateHOTP ----------------\n\n");
  SHA1_INFO ctx; 
  unsigned char k_ipad[65];
  unsigned char k_opad[65];
  
  uint8_t digest[SHA1_DIGEST_LENGTH]; 
  uint8_t sha[SHA1_DIGEST_LENGTH]; 

  char * key = secret_hex;
  int key_len = 20;

  /* start out by storing key in pads */
  bzero( k_ipad, sizeof(k_ipad));
  bzero( k_opad, sizeof(k_opad));
  bcopy( key, k_ipad, key_len);
  bcopy( key, k_opad, key_len);
  /* XOR key with ipad and opad values */
  int i;
  for (i=0; i<64; i++) {
   k_ipad[i] ^= 0x36;
   k_opad[i] ^= 0x5c;
  }

  //const uint8_t * counter = "0";
  //const uint8_t counter[]= {1,0,0,0,0,0,0,0};
  const uint8_t counter[] = {0,0,0,0,0,0,0,1};
  //char * counter = "0";
  
  //uint8_t text = {0,0,0,0,0,0,0,0};
  // for (int i = strlen(text) - 1; i >= 0; i--) {
  //     text[i] = (uint8_t) (movingFactor & 0xff);
  //     movingFactor >>= 8;
  // }

  
  
  
  /* * perform inner  */ 
  sha1_init(&ctx);  /* init context for 1st * pass */ 
  sha1_update(&ctx, k_ipad, 64); /* start with inner pad */ 
  sha1_update(&ctx, counter, 8); /* then text of datagram */ 
  sha1_final(&ctx, digest); 
  
  /* * perform outer MD5 */     
  sha1_init(&ctx); /* init context for 2nd * pass */
  sha1_update(&ctx, k_opad, 64); /* start with outer pad */ 
  sha1_update(&ctx, digest, 20); /* then results of 1st * hash */
  sha1_final(&ctx,sha);

  int j;
  for(j = 0; j < 20; j++){
    printf("%x", sha[j]);
  }

  int offset   =  sha[19] & 0xf ;
  printf("\nThis is last integer: %d\n", offset);

  int bin_code = (sha[offset]  & 0x7f) << 24
           | (sha[offset+1] & 0xff) << 16
           | (sha[offset+2] & 0xff) << 8
           | (sha[offset+3] & 0xff);

  //This is the fvalue
  printf("This is last hex value: %d\n", bin_code);
  int mod = pow(10, 6);
  int fvalue = bin_code % mod;
  printf("This is last value: %d\n", fvalue);
  if(fvalue == atoi(HOTP_string)){
    return 1;
  }else{
    return 0;
  }
  
}

static int
validateTOTP(char * secret_hex, char * TOTP_string)
{
	
  printf("\n\nThis is the validateTOTP ----------------\n\n");
  SHA1_INFO ctx; 
  unsigned char k_ipad[65];
  unsigned char k_opad[65];
  
  uint8_t digest[SHA1_DIGEST_LENGTH]; 
  uint8_t sha[SHA1_DIGEST_LENGTH]; 

  char * key = secret_hex;
  int key_len = 20;

  /* start out by storing key in pads */
  bzero( k_ipad, sizeof(k_ipad));
  bzero( k_opad, sizeof(k_opad));
  bcopy( key, k_ipad, key_len);
  bcopy( key, k_opad, key_len);
  /* XOR key with ipad and opad values */
  int i;
  for (i=0; i<64; i++) {
   k_ipad[i] ^= 0x36;
   k_opad[i] ^= 0x5c;
  }

  time_t sec;
  sec = time (NULL)/30;
    
  printf ("%ld \n", sec);
  uint8_t mes = (uint8_t)sec;
  const uint8_t counter[] = {0,0,0,0,0,0,0,mes};

  
  /* * perform inner  */ 
  sha1_init(&ctx);  /* init context for 1st * pass */ 
  sha1_update(&ctx, k_ipad, 64); /* start with inner pad */ 
  sha1_update(&ctx, counter, 8); /* then text of datagram */ 
  sha1_final(&ctx, digest); 
  
  /* * perform outer MD5 */     
  sha1_init(&ctx); /* init context for 2nd * pass */
  sha1_update(&ctx, k_opad, 64); /* start with outer pad */ 
  sha1_update(&ctx, digest, 20); /* then results of 1st * hash */
  sha1_final(&ctx,sha);

  int j;
  for(j = 0; j < 20; j++){
    printf("%x", sha[j]);
  }

  int offset   =  sha[19] & 0xf ;
  printf("\nThis is last integer in TOTP: %d\n", offset);

  int bin_code = (sha[offset]  & 0x7f) << 24
           | (sha[offset+1] & 0xff) << 16
           | (sha[offset+2] & 0xff) << 8
           | (sha[offset+3] & 0xff);

  //This is the fvalue
  printf("This is last hex value: %d\n", bin_code);
  int mod = pow(10, 6);
  int fvalue = bin_code % mod;
  printf("This is last value: %d\n", fvalue);

  return 0;
}

int main()
{
  
  
  // if ( argc != 4 ) {
  //   printf("Usage: %s [secretHex] [HOTP] [TOTP]\n", argv[0]);
  //   return(-1);
  // }
  
  char * argv[] = {"","12345678901234567890","803282","134318"};
    //char output[20] = "";
    char * str = argv[1];
    
    char padStr[20] = "";
    //padding zero at the beginning
    if(strlen(str) < 20){
      int temp = 20 - strlen(str);
      int k;
      for(k = strlen(str) - 1;k >= 0;k--){
        padStr[k + temp] = str[k];
      }
      int l;
      for(l = 0;l < temp;l++){
        padStr[l] = '0';
      }
      padStr[20] = '\0';
      strcpy(str, padStr);
    }
    
   
    int i, j;
    int sum[10];
    char newStr[20] = "";
    for(i = 0,j = 0; i < 20;i+=2, j+=1){
      int first, second;
      if (str[i] <= 57){
        first = str[i] - 48;
      }
      else if(str[i] <= 70){
        first = str[i] - 65 + 10; 
      }
      else if(str[i]<= 102){
        first = str[i] - 97 + 10;
      }

      if (str[i+1] <= 57){
        second = str[i + 1] - 48;
      }
      else if(str[i+1] <= 70){
        second = str[i + 1] - 65 + 10;
      }
      else if(str[i+1]<= 102){
        second = str[i + 1] - 97 + 10;
      }

      sum[j] = first * 16 + second;
      newStr[j] = (char)sum[j];
      //printf("%c",newStr[j]);
    }

  //char * argv[] = {"","12345678901234567890","803282","134318"};   

  char *  secret_hex = newStr;
  char *  HOTP_value = argv[2];
  char *  TOTP_value = argv[3];
  
  
  //assert (strlen(secret_hex) <= 20);
  assert (strlen(HOTP_value) == 6);
  assert (strlen(TOTP_value) == 6);

  printf("\nSecret (Hex): %s\nHTOP Value: %s (%s)\nTOTP Value: %s (%s)\n\n",
    secret_hex,
    HOTP_value,
    validateHOTP(secret_hex, HOTP_value) ? "valid" : "invalid",
    TOTP_value,
    validateTOTP(secret_hex, TOTP_value) ? "valid" : "invalid");

  return(0);
}