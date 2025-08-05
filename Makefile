TOOLCHAIN := $(OO_PS4_TOOLCHAIN)
PROJDIR := src
INTDIR := build
TARGET := anomaly.prx

LIBS:= -lc -lc++ -lkernel -lSceLibcInternal -lSceSysUtil -lSceSysmodule -lSceFios2
				 
CFILES := $(wildcard $(PROJDIR)/*.c)
CPPFILES := $(wildcard $(PROJDIR)/*.cpp)
OBJS := $(patsubst $(PROJDIR)/%.c,$(INTDIR)/%.o,$(CFILES)) \
        $(patsubst $(PROJDIR)/%.cpp,$(INTDIR)/%.o,$(CPPFILES))

CFLAGS := --target=x86_64-pc-freebsd12-elf -fPIC -funwind-tables -c \
          -isysroot $(TOOLCHAIN) -isystem $(TOOLCHAIN)/include \
          -Iinclude -Isrc -std=c20 -D_DEFAULT_SOURCE -DFMT_HEADER_ONLY

CXXFLAGS := $(CFLAGS) -isystem $(TOOLCHAIN)/include/c++/v1 \
            -std=c++20 -Iinclude -Isrc -DFMT_HEADER_ONLY

LDFLAGS := -m elf_x86_64 -pie --script $(TOOLCHAIN)/link.x --eh-frame-hdr \
          -L$(TOOLCHAIN)/lib $(LIBS) $(TOOLCHAIN)/lib/crtlib.o --wrap=_init

UNAME_S := $(shell uname -s)

ifeq ($(UNAME_S),Linux)
	CC := clang
	CCX := clang++
	LD := ld.lld
	CDIR := linux
endif

ifeq ($(UNAME_S),Darwin)
	CC := /usr/local/opt/llvm/bin/clang
	CCX := /usr/local/opt/llvm/bin/clang++
	LD := /usr/local/opt/llvm/bin/ld.lld
	CDIR := macos
endif

$(TARGET): $(INTDIR) $(OBJS)
	$(LD) $(OBJS) -o $(INTDIR)/$(PROJDIR).elf $(LDFLAGS) -e _init
	$(TOOLCHAIN)/bin/$(CDIR)/create-fself -in=$(INTDIR)/$(PROJDIR).elf \
		-out=$(INTDIR)/$(PROJDIR).oelf --lib=$(TARGET) --paid 0x3800000000000011

$(INTDIR)/%.o: $(PROJDIR)/%.c
	$(CC) $(CFLAGS) -o $@ $<

$(INTDIR)/%.o: $(PROJDIR)/%.cpp
	$(CCX) $(CXXFLAGS) -o $@ $<

$(INTDIR):
	mkdir -p $(INTDIR)

.PHONY: clean all target

.DEFAULT_GOAL := all

clean:
	rm -f $(INTDIR)/$(PROJDIR).oelf $(OBJS) $(TARGET) $(INTDIR)/$(PROJDIR).elf

target: $(TARGET)

all: target

-include Makefile.local