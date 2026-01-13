# Phantom-Mirai Hybrid V3 Build System (Modular)

CC ?= gcc
CFLAGS = -Wall -Wextra -O2 -std=c99 -D_GNU_SOURCE
# Add Module Include Paths
# Network
CFLAGS += -I./modules/network/dns -I./modules/network/p2p -I./modules/network/proxy \
          -I./modules/network/scanner -I./modules/network/proto
# Attack
CFLAGS += -I./modules/attack -I./modules/attack/methods
# System
CFLAGS += -I./modules/system/stealth -I./modules/system/killer -I./modules/system/obfuscate
# Crypto
CFLAGS += -I./modules/crypto

LDFLAGS = 
# Strip binary for size/anti-re logic (optional, but good for IoT)
# LDFLAGS += -s 

# Source Modules
MODULE_NET = modules/network
MODULE_ATK = modules/attack
MODULE_SYS = modules/system

# Gather Sources
SRCS = main.c \
       $(wildcard $(MODULE_NET)/*/*.c) \
       $(wildcard $(MODULE_ATK)/*.c) \
       $(wildcard $(MODULE_ATK)/methods/*.c) \
       $(wildcard $(MODULE_SYS)/*/*.c) \
       $(wildcard modules/crypto/*.c)

OBJS = $(SRCS:.c=.o)
# Default Target Overrideable
TARGET ?= mirai_lite

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
	@echo "[+] Built $(TARGET)"
	@echo "[*] Cleaning up object files..."
	@find . -name "*.o" -type f -delete

# Generic Rule for object files
%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(TARGET)
	find . -name "*.o" -type f -delete
