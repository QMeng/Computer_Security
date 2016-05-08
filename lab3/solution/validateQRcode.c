
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
#include "lib/sha1.h"



static int
validateHOTP(char* secret_hex, char * HOTP_string)
{    
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

  const uint8_t counter[] = {0,0,0,0,0,0,0,1};
  
  sha1_init(&ctx);  /* init context for 1st * pass */ 
  sha1_update(&ctx, k_ipad, 64); /* start with inner pad */ 
  sha1_update(&ctx, counter, 8); /* then text of datagram */ 
  sha1_final(&ctx, digest); 
      
  sha1_init(&ctx); /* init context for 2nd * pass */
  sha1_update(&ctx, k_opad, 64); /* start with outer pad */ 
  sha1_update(&ctx, digest, 20); /* then results of 1st * hash */
  sha1_final(&ctx,sha);

  int offset   =  sha[19] & 0xf;

  int bin_code = (sha[offset]  & 0x7f) << 24
           | (sha[offset+1] & 0xff) << 16
           | (sha[offset+2] & 0xff) << 8
           | (sha[offset+3] & 0xff);


  int mod = pow(10, 6);
  int fvalue = bin_code % mod;

  if(fvalue == atoi(HOTP_string)){
    return 1;
  }else{
    return 0;
  }
  
}

static int
validateTOTP(char * secret_hex, char * TOTP_string)
{
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

  unsigned long long sec;
  sec = time (NULL)/30;
    
  //uint8_t mes = (uint8_t)sec;
  const uint8_t counter[] = {(sec >> 56) & 0xff,(sec >> 48)&0xff,(sec >> 40)&0xff,(sec >> 32)&0xff,(sec >> 24)&0xff,(sec >> 16)&0xff,(sec >> 8)&0xff,sec&0xff};

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

  int offset   =  sha[19] & 0xf ;

  int bin_code = (sha[offset]  & 0x7f) << 24
           | (sha[offset+1] & 0xff) << 16
           | (sha[offset+2] & 0xff) << 8
           | (sha[offset+3] & 0xff);

  //This is the fvalue
  int mod = pow(10, 6);
  int fvalue = bin_code % mod;

  if(fvalue == atoi(TOTP_string)){
    return 1;
  }else{
    return 0;
  }
}

int main(int argc, char * argv[])
{
  
  
  if ( argc != 4 ) {
    printf("Usage: %s [secretHex] [HOTP] [TOTP]\n", argv[0]);
    return(-1);
  }
  
      //char output[20] = "";
    char * str = argv[1];
    char *  HOTP_value = argv[2];
    char *  TOTP_value = argv[3];   

    char* padStr; 
    padStr = (char *)malloc(20);
    //padding zero at the beginning
    if(strlen(str) < 20){
  int l;
  for(l = 0;l < strlen(str);l++){
    padStr[l] = str[l];
  }
  int k;
  for(k = strlen(str);k < 20;k++){
    padStr[k] = '0';
  }
    padStr[20] = '\0';
  }else{
    strcpy(padStr, str);
  }

  
    int i, j;
    int sum[10];
    char newStr[20] = "";
    for(i = 0,j = 0; i < 20;i+=2, j+=1){
      int first, second;
      if (padStr[i] <= 57){
        first = padStr[i] - 48;
      }
      else if(padStr[i] <= 70){
        first = padStr[i] - 65 + 10; 
      }
      else if(padStr[i]<= 102){
        first = padStr[i] - 97 + 10;
      }

      if (padStr[i+1] <= 57){
        second = padStr[i + 1] - 48;
      }
      else if(padStr[i+1] <= 70){
        second = padStr[i + 1] - 65 + 10;
      }
      else if(padStr[i+1]<= 102){
        second = padStr[i + 1] - 97 + 10;
      }

      sum[j] = first * 16 + second;
      newStr[j] = (char)sum[j];
      //printf("%c",newStr[j]);
    }

  //char * argv[] = {"","12345678901234567890","803282","134318"};   

  char *  secret_hex = newStr;
  
  assert (strlen(secret_hex) <= 20);
  assert (strlen(HOTP_value) == 6);
  assert (strlen(TOTP_value) == 6);
  
  printf("\nSecret (Hex): %s\nHTOP Value: %s (%s)\nTOTP Value: %s (%s)\n\n",
    padStr,
    HOTP_value,
    validateHOTP(secret_hex, HOTP_value) ? "valid" : "invalid",
    TOTP_value,
    validateTOTP(secret_hex, TOTP_value) ? "valid" : "invalid");

  return(0);
}