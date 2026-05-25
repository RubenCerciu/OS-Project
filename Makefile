CC      = gcc
CFLAGS  = -Wall -Wextra -std=c11 -g
TARGETS = city_manager monitor_reports city_hub scorer

all: $(TARGETS)

city_manager: city_manager.c
	$(CC) $(CFLAGS) city_manager.c -o city_manager

monitor_reports: monitor_reports.c
	$(CC) $(CFLAGS) monitor_reports.c -o monitor_reports

city_hub: city_hub.c
	$(CC) $(CFLAGS) city_hub.c -o city_hub

scorer: scorer.c
	$(CC) $(CFLAGS) scorer.c -o scorer

clean:
	rm -f $(TARGETS)

.PHONY: all clean
