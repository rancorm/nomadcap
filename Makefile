#
# nomadcap Makefile
#
CC=gcc
CFLAGS=

#
PROJECT_NAME:=nomadcap
BUILD_DIR:=build/

# Uncomment the following line to include DEBUG code
# CFLAGS=-DEBUG
LDFLAGS=-lpcap
OBJ=$(PROJECT_NAME).o

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
$(BUILD_DIR)%.o: %.c %.h
	$(CC) -c -o $@ $< $(CFLAGS)

$(BUILD_DIR)$(PROJECT_NAME): $(BUILD_DIR)$(OBJ)
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS)

clean:
	rm -f $(BUILD_DIR)*.o
	rm -f $(BUILD_DIR)$(PROJECT_NAME)
