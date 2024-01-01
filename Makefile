#
# nomadcap Makefile
#
PROJECT_NAME:=nomadcap
BUILD_DIR:=build/

# Compiler stuff
CC=gcc
CFLAGS=
LDFLAGS=-lpcap
OBJ=$(PROJECT_NAME).o

# Paths to standard tools
MKDIR=$(which mkdir)
INSTALL=$(which install)
RM=$(which rm)

# Test for libcsv, if found link to it.
LIBCSV_PROG="int main() { return 0; }"
LIBCSV_TEST:=$(shell echo $(LIBCSV_PROG) > libcsv_test.c && $(CC) -o libcsv_test libcsv_test.c -lcsv 2> /dev/null && echo 1)

ifeq ($(LIBCSV_TEST),1)
	CFLAGS += -DUSE_LIBCSV
    LDFLAGS += -lcsv
endif

# Clean up after libcsv test
$(shell rm -f libcsv_test)
$(shell rm -f libcsv_test.c)

.PHONY: clean

# Targets
$(BUILD_DIR)%.o: %.c %.h $(BUILD_DIR)
	$(CC) -c -o $@ $< $(CFLAGS)

$(BUILD_DIR)$(PROJECT_NAME): $(BUILD_DIR)$(OBJ)
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS)

$(BUILD_DIR):
	$(MKDIR) $@

install:
	$(INSTALL) -D -m 755 $(BUILD_DIR)$(PROJECT_NAME) $(DESTDIR)/usr/sbin/$(PROJECT_NAME)

clean:
	$(RM) -f $(BUILD_DIR)*.o
	$(RM) -f $(BUILD_DIR)$(PROJECT_NAME)
