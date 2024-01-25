
CC = gcc
CXX = g++
CFLAGS = -Wall -Wextra -ggdb3 -O2 -std=c99
CXXFLAGS = -Wall -Wextra -ggdb3 -O2 -std=c++14
LDFLAGS = -ggdb -O2
LIBS = -lpthread

SPEEDMGR_BIN := speedmgr
SPEEDMGR_C_SOURCES := src/speedmgr.c
SPEEDMGR_CXX_SOURCES := src/ip_map.cpp
SPEEDMGR_OBJECTS := $(SPEEDMGR_C_SOURCES:.c=.o) $(SPEEDMGR_CXX_SOURCES:.cpp=.o)

ifeq ($(ENABLE_STATIC), 1)
CFLAGS += -static
CXXFLAGS += -static
LDFLAGS += -static
endif

ifeq ($(ENABLE_SANITIZER), 1)
CFLAGS += -fsanitize=address
CXXFLAGS += -fsanitize=address
LDFLAGS += -fsanitize=address
endif

all: $(SPEEDMGR_BIN)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(SPEEDMGR_BIN): $(SPEEDMGR_OBJECTS)
	$(CXX) $(LDFLAGS) $(SPEEDMGR_OBJECTS) $(LIBS) -o $@

clean:
	rm -vf $(SPEEDMGR_BIN) $(SPEEDMGR_OBJECTS)

.PHONY: all clean
