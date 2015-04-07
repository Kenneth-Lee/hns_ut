#!/bin/sh

#make >/dev/null

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

mkdir -p out
lcov -c -d . -o lcov.out 2>&1 |tee > lcov.log
genhtml -o out lcov.out 2>&1 |tee >> lcov.log
