# -*- Mode: makefile -*-
#
# This Makefile example is fairly independent from the main makefile
# so users can take and adapt it for their build. We only really
# include config-host.mak so we don't have to repeat probing for
# cflags that the main configure has already done for us.
#

BUILD_DIR := $(CURDIR)/../..

include $(BUILD_DIR)/config-host.mak

VPATH += $(SRC_PATH)/contrib/plugins

NAMES :=
NAMES += execlog
NAMES += hotblocks
NAMES += hotpages
NAMES += howvec
NAMES += lockstep
NAMES += hwprofile
NAMES += cache
NAMES += drcov
NAMES += taint

SONAMES := $(addsuffix .so,$(addprefix lib,$(NAMES)))

# The main QEMU uses Glib extensively so it's perfectly fine to use it
# in plugins (which many example do).
CFLAGS = $(GLIB_CFLAGS)
CFLAGS += -fPIC -Wall $(filter -W%, $(QEMU_CFLAGS))
CFLAGS += $(if $(findstring no-psabi,$(QEMU_CFLAGS)),-Wpsabi)
CFLAGS += -I$(SRC_PATH)/include/qemu

CFLAGS += -g

all: $(SONAMES)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

lib%.so: %.o
	$(CC) -shared -Wl,-soname,$@ -o $@ $^ $(LDLIBS)


TAINT_BUILD_DIR := $(CURDIR)/taint
TAINT_OBJS := taint/logging.o taint/params.o taint/propagate.o taint/regs.o taint/taint.o

$(TAINT_BUILD_DIR):
	mkdir $(TAINT_BUILD_DIR)

$(TAINT_OBJS): | $(TAINT_BUILD_DIR)

libtaint.so: $(TAINT_OBJS)
	$(CC) -shared -Wl,-soname,$@ -o $@ $^ $(LDLIBS)

clean:
	rm -f *.o *.so *.d
	rm -f taint/*.o
	rm -Rf .libs

.PHONY: all clean
