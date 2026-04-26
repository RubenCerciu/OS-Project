CC      = gcc
CFLAGS  = -Wall -Wextra -std=c11 -g
TARGET  = city_manager

all: $(TARGET)

$(TARGET): city_manager.c
	$(CC) $(CFLAGS) city_manager.c -o $(TARGET)

clean:
	rm -f $(TARGET)

.PHONY: all clean
