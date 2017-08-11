
export PRAKTROOT=${HOME}/Share
include $(PRAKTROOT)/include/Makefile.Settings


all: attack

clean:
	rm -f texp.o attack.o daem_acc.o attack core

attack.o: attack.c texp.h daemon.h attack.c

attack: attack.o daem_acc.o texp.o
	gcc -o attack attack.o daem_acc.o texp.o -lgmp $(LFLAGS)
