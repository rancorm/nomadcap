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
LIBCSV_TEST := $(shell echo "int main() { return 0; }" > libcsv_test.c && $(CC) -o libcsv_test libcsv_test.c -lcsv && echo 1)

ifeq ($(LIBCSV_TEST),1)
	CFLAGS += -DUSC_LIBCSV
        LDFLAGS += -lcsv
else
        $(error "libcsv not found. Please install it.")
endif

# Clean up after libcsv test
$(shell rm -f libcsv_test)
$(shell rm -f libcsv_test.c)

# Targets
$(BUILD_DIR)%.o: %.c %.h
	$(CC) -c -o $@ $< $(CFLAGS)

$(BUILD_DIR)$(PROJECT_NAME): $(BUILD_DIR)$(OBJ)
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS)

clean:
	rm -f $(BUILD_DIR)*.o
	rm -f $(BUILD_DIR)$(PROJECT_NAME)
