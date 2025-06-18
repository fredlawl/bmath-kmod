static int c;

int add(int, int);
int cumulative(void);

int add(int a, int b)
{
	return c += a + b;
}

int cumulative()
{
	return c;
}
