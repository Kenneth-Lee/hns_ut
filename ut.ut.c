#include "ut.c"

void test_ut_break(void) {
	ut_break(1);
}

int main(void) {
	test(101, test_ut_break);
	return 0;
}
