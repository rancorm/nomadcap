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

$(BUILD_DIR)%.o: %.c %.h
	$(CC) -c -o $@ $< $(CFLAGS)

$(BUILD_DIR)$(PROJECT_NAME): $(BUILD_DIR)$(OBJ)
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS)

clean:	
	rm -f $(BUILD_DIR)*.o
	rm -f $(BUILD_DIR)$(PROJECT_NAME)
