#include <stdio.h>
#include <v2xSe.h>

int main()
{
	printf("testprog: start\n");
	printf("1st time: v2xSe_connect returned %d\n",v2xSe_connect());
	printf("2nd time: v2xSe_connect returned %d\n",v2xSe_connect());
	printf("testprog: DONE\n");
	return 0;
}
