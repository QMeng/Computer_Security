#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "lib/encoding.h"

int
main(int argc, char * argv[])
{
	//printf("This is %d\n", argc);

	if ( argc != 4 ) {
		printf("Usage: %s [issuer] [accountName] [secretHex]\n", argv[0]);
		return(-1);
	}

	char *	issuer = argv[1];
	char *	accountName = argv[2];
	char *	secret_hex = argv[3];

	assert (strlen(secret_hex) <= 20);



	// Create an otpauth:// URI and display a QR code that's compatible
	// with Google Authenticator
	
	const char* newName = urlEncode(accountName);

	const char* newissuer = urlEncode(issuer);

	// char result[50];
 	//int total = base32_encode(secret_hex, strlen(secret_hex), result, 50); 

	  char output[20] = "";
	  char * str = secret_hex;
	  //char input[20]= "\x12\x34\x56\x78\x90\x12\x34\x56\x78\x90";
	  
	  char padStr[20] = "";
	  //padding zero at the end
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
	    strcpy(str, padStr);
	  }

	  printf("\nIssuer: %s\nAccount Name: %s\nSecret (Hex): %s\n\n",
		issuer, accountName, str);
	  
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
	    
	  }
	  
	  
	  
	  base32_encode(newStr, 30, output,16);




	// //displayQRcode("otpauth://testing");
    char prefix1[100];
    sprintf(prefix1, "otpauth://hotp/%s?issuer=%s&secret=%s&counter=1", newName, newissuer, output);
	displayQRcode(prefix1);

	char prefix2[100];
	sprintf(prefix2, "otpauth://totp/%s?issuer=%s&secret=%s&period=30", newName, newissuer, output);
	displayQRcode(prefix2);


	//displayQRcode("otpauth://hotp/gibson?issuer=ECE568&secret=CI2FM6EQCI2FM6EQ&counter=1");


	return (0);
}
