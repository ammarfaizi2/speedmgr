
CC = gcc
CXX = g++
CFLAGS = -Wall -Wextra -ggdb3 -O0 -std=c99
CXXFLAGS = -Wall -Wextra -ggdb3 -O0 -std=c++14
LDFLAGS = -ggdb -O0
LIBS = -lpthread

TARGET := speedmgr

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

all: $(TARGET)

$(TARGET): speedmgr.o ht.o
	$(CXX) $(LDFLAGS) -o $@ $^ $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

%.o: %.cpp
	$(CC) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f *.o $(TARGET)

.PHONY: all clean
