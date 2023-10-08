
CWARNS = -Wall -Wextra -Werror=format-security -pedantic
CFLAGS = -std=c11 -D_FORTIFY_SOURCE=2 -D_GLIBCXX_ASSERTIONS $(CWARNS) -Wformat=2 -Wdate-time -Wstack-protector -fasynchronous-unwind-tables -fexceptions -fstack-protector-strong -fstack-clash-protection -z defs -z noexecstack -z now -z relro -z text -fPIE -O2 --static-pie

.PHONY = clean

all: shellcancer

clean:
	rm -f shellcancer

shellcancer: chall.S chall.c
	gcc -o $@ $(CFLAGS) $^ -lseccomp


solve: solve.c solve.S
	gcc -o $@ -nostdlib --static-pie -fPIE -O2 $^
