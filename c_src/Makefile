# System-specific variables
UNAME_SYS := $(shell uname -s)
ifeq ($(UNAME_SYS), Darwin)
    CC ?= cc
    CFLAGS ?= -O3 -std=c11 -arch x86_64 -flat_namespace -undefined suppress
    LDFLAGS ?= -flat_namespace -undefined suppress
else ifeq ($(UNAME_SYS), Linux)
    CC ?= gcc
    CFLAGS ?= -O3 -std=c11
endif

# Erlang-specific variables
ERL_INCLUDE_DIR = $(shell erl -eval 'io:format("~s", [lists:concat([code:root_dir(), "/erts-", erlang:system_info(version), "/include"])])' -s init stop -noshell)

# Include and library paths
CFLAGS += -fPIC -I$(ERL_INCLUDE_DIR) -I/usr/local/include/tss2 -I/usr/include/tss2
LDFLAGS += -L/usr/local/lib -L/usr/lib -ltss2-fapi

# Project-specific variables
PRIV_DIR = ../priv
C_SRC_OUTPUT = $(PRIV_DIR)/tss_fapi_nif.so

# Source files
SOURCES = tss_fapi_nif.c
OBJECTS = $(SOURCES:.c=.o)

.PHONY: all clean

all: $(C_SRC_OUTPUT)

$(C_SRC_OUTPUT): $(OBJECTS)
	@mkdir -p $(PRIV_DIR)
	$(CC) $^ $(LDFLAGS) -shared -o $@
	@echo "NIF library created: $@"

%.o: %.c
	$(CC) -c $(CFLAGS) $< -o $@

clean:
	@rm -f $(OBJECTS) $(C_SRC_OUTPUT)
	@echo "Cleaned build artifacts"

# System-specific variables
# UNAME_SYS := $(shell uname -s)
# ifeq ($(UNAME_SYS), Darwin)
#     CC ?= cc
#     CFLAGS ?= -O3 -std=c11 -arch x86_64 -flat_namespace -undefined suppress
#     LDFLAGS ?= -flat_namespace -undefined suppress
# else ifeq ($(UNAME_SYS), Linux)
#     CC ?= gcc
#     CFLAGS ?= -O3 -std=c11
# endif

# # Erlang-specific variables
# ERL_INTERFACE_INCLUDE_DIR = $(shell erl -eval 'io:format("~s", [lists:concat([code:root_dir(), "/erts-", erlang:system_info(version), "/include"])])' -s init stop -noshell)
# ERL_INTERFACE_LIB_DIR = $(shell erl -eval 'io:format("~s", [lists:concat([code:root_dir(), "/erts-", erlang:system_info(version), "/lib"])])' -s init stop -noshell)

# # Include and library paths
# CFLAGS += -fPIC -I$(ERL_INTERFACE_INCLUDE_DIR) -I/usr/include/tss2
# LDFLAGS += -L$(ERL_INTERFACE_LIB_DIR) -ltss2-fapi

# # Project-specific variables
# PRIV_DIR = ../priv
# C_SRC_DIR = .
# C_SRC_OUTPUT = $(PRIV_DIR)/tss_fapi_nif.so

# # Source files
# SOURCES = $(wildcard $(C_SRC_DIR)/*.c)
# OBJECTS = $(SOURCES:.c=.o)

# .PHONY: all clean

# all: $(C_SRC_OUTPUT)

# $(C_SRC_OUTPUT): $(OBJECTS)
# 	@mkdir -p $(PRIV_DIR)
# 	$(CC) $(OBJECTS) $(LDFLAGS) -shared -o $(C_SRC_OUTPUT)

# %.o: %.c
# 	$(CC) -c $(CFLAGS) $< -o $@

# clean:
# 	@rm -f $(C_SRC_OUTPUT) $(OBJECTS)
