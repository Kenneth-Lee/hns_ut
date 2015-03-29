#define UT_DUMPSTACK
#include "ut.c"

int testcase = 0;

void testcase1(void)
{
	testcase = 101;
	ut_assert(0);
}

int main(void) {
	testcase1();
	return 0;
}

