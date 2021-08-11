#include <stdio.h>
#include <unistd.h>
#include <dlfcn.h>

char string[100] = "this is string.!!!!!!!";
int main()

{
	dlopen(0,0); //
	while(1)
	{
		printf("%s\n", string);
		sleep(1);
	}
}