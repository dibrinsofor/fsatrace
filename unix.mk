SOSRCS=src/unix/fsatraceso.c src/emit.c src/unix/shm.c src/unix/proc.c

ifeq ($(OS),Darwin)
SOSRCS+=src/darwin/sip_detect.c src/darwin/lldb.c
endif

lib: fsatrace.so

%.os: %.c
	$(CC) -c -fPIC $(CPPFLAGS) $(CFLAGS) $< -o $@

fsatest32: fsatest
	cp $^ $@

fsatrace.so: $(patsubst %.c,%.os,$(SOSRCS))
	$(CC) -shared $(LDFLAGS) $^ -o $@ $(LDLIBS)

libinstall: fsatrace.so
	cp fsatrace.so $(INSTALLDIR)

cleanlib:
	rm -f fsatrace.so $(patsubst %.c,%.d,$(SOSRCS)) $(patsubst %.c,%.os,$(SOSRCS))

-include $(patsubst %.c,%.d,$(SOSRCS))
