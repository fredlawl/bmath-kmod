#include <stdio.h>

static int cumulative = 0;

int add(int, int);
int summation(void);
void show_summation(void);

int add(int a, int b)
{
	int ret = a + b;
	cumulative += ret;
	return ret;
}

int summation(void)
{
	return cumulative;
}

void show_summation(void)
{
	printf("summation: %d\n", summation());
}
