# KPM 形态
# 用法:
#   make KPM_SDK=/path/to/KPatch/kpm CROSS=aarch64-linux-gnu-
CROSS   ?= aarch64-linux-gnu-
KPM_SDK ?= $(HOME)/KPatch/kpm
OUT     ?= pkdriver.kpm
CC      := $(CROSS)gcc

SRC := kpm.c ../common/crypto.c ../common/ptwalk.c
INC := -I. -I$(KPM_SDK) -I../common

CFLAGS := -O2 -fPIC -shared -nostdlib -fno-stack-protector \
          -fno-asynchronous-unwind-tables -ffreestanding \
          -Wno-unused-variable -Wno-unused-function

all:
	$(CC) $(CFLAGS) $(INC) $(SRC) -o $(OUT)

clean:
	rm -f $(OUT)

.PHONY: all clean
