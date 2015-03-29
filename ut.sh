#!/bin/sh

make >/dev/null

for i in `ls *.ut`
do
	echo -n "--> test $i..."
	if ./$i >/dev/null; then
		echo "passed"
	else
		echo ""
		exit -1 
	fi
done

lcov -c -d . -o lcov.out 2>&1 > .lcov.log
genhtml lcov.out 2>&1 >> .lcov.log
