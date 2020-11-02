CC = /usr/bin/gcc
CFLAGS = -Wall -g -O3 -m64 -mavx2 -msse2 -fomit-frame-pointer -funroll-all-loops -Wextra -Wpedantic -Wno-shift-count-overflow
LDLIBS = -lcrypto -L/usr/lib/ -lgdsl

SOURCES = params.c hash.c fips202.c hash_address.c randombytes.c wots.c xmss.c xmss_core.c xmss_commons.c utils.c isg-attack-xmss.c
HEADERS = params.h hash.h fips202.h hash_address.h randombytes.h wots.h xmss.h xmss_core.h xmss_commons.h utils.h isg-attack-xmss.h

SOURCES_FAST = $(subst xmss_core.c,xmss_core_fast.c,$(SOURCES))
HEADERS_FAST = $(subst xmss_core.c,xmss_core_fast.c,$(HEADERS))

TESTS = test/main \

tests: $(TESTS)

test: $(TESTS:=.exec)

.PHONY: clean test

test/%.exec: test/%
	@$<

test/main: test/main.c $(SOURCES) $(OBJS) $(HEADERS)
	$(CC) -DXMSSMT $(CFLAGS) -o $@ $(SOURCES) $< $(LDLIBS)

clean:
	-$(RM) $(TESTS)
	-$(RM) $(UI)
