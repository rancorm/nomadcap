#
# nomadcap Makefile
#
PROJECT_NAME:=nomadcap
PROJECT_NAME6:=nomadcap6
BUILD_DIR:=build/

# Compiler stuff
CC:=$(shell which gcc)
CFLAGS=-std=gnu2x
LDFLAGS=-lpcap
OBJ=$(BUILD_DIR)$(PROJECT_NAME).o $(BUILD_DIR)syslog.o
OBJ6=$(BUILD_DIR)$(PROJECT_NAME6).o $(BUILD_DIR)syslog.o

# Paths to standard tools
MKDIR	:=$(shell which mkdir)
INSTALL	:=$(shell which install)
RM	:=$(shell which rm)

# Debian package commands
DPKG_BUILDPKG		:=dpkg-buildpackage
DPKG_BUILDPKG_FLAGS	:=--no-sign -b

# Test for libcsv, if found link to it.
LIBCSV_PROG	:="int main() { return 0; }"
LIBCSV_TEST	:=$(shell echo $(LIBCSV_PROG) > libcsv_test.c && $(CC) -o libcsv_test libcsv_test.c -lcsv 2> /dev/null && echo 1)

ifeq ($(LIBCSV_TEST),1)
	CFLAGS += -DUSE_LIBCSV
	LDFLAGS += -lcsv
endif

# Clean up after libcsv test
$(shell rm -f libcsv_test)
$(shell rm -f libcsv_test.c)

# Test for libjansson, if found link to it.
LIBJANSSON_PROG	:="int main() { return 0; }"
LIBJANSSON_TEST	:=$(shell echo $(LIBJANSSON_PROG) > libjansson_test.c && $(CC) -o libjansson_test libjansson_test.c -ljansson 2> /dev/null && echo 1)

ifeq ($(LIBJANSSON_TEST),1)
	CFLAGS += -DUSE_LIBJANSSON
	LDFLAGS += -ljansson
endif

# Clean up after libcsv test
$(shell rm -f libjansson_test)
$(shell rm -f libjansson_test.c)

.PHONY: clean deb

all: $(BUILD_DIR)$(PROJECT_NAME) $(BUILD_DIR)$(PROJECT_NAME6)

# Targets
$(BUILD_DIR)%.o: %.c %.h $(BUILD_DIR)
	$(CC) -c -o $@ $< $(CFLAGS)

$(BUILD_DIR)$(PROJECT_NAME): $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS)

$(BUILD_DIR)$(PROJECT_NAME6): $(OBJ6)
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS)

$(BUILD_DIR)$(PROJECT_NAME)-win32: $(BUILD_DIR)$(OBJ)
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS)

$(BUILD_DIR):
	$(MKDIR) $@

install:
	$(INSTALL) -s -D -m 755 $(BUILD_DIR)$(PROJECT_NAME) $(DESTDIR)/usr/bin/$(PROJECT_NAME)
	$(INSTALL) -s -D -m 755 $(BUILD_DIR)$(PROJECT_NAME6) $(DESTDIR)/usr/bin/$(PROJECT_NAME6)

clean:
	$(RM) -f $(BUILD_DIR)*.o
	$(RM) -f $(BUILD_DIR)$(PROJECT_NAME)
	$(RM) -f $(BUILD_DIR)$(PROJECT_NAME6)

deb:
	$(DPKG_BUILDPKG) $(DPKG_BUILDPKG_FLAGS)
