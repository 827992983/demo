#include <stdio.h>

int main(int argc, char *argv[])
{
	int i=0;
	while(1){
		printf("Hello,ptrace! [pid:%d]! num is %d\n",getpid(),i++);
		sleep(2);
	}
	return 0;
}
