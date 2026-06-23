# Makefile for Forensic Recovery v1.0.1 (frecover)
#
#   make            # build ./frecover
#   make run        # build, then print usage
#   sudo make install     # install globally to $(BINDIR)
#   sudo make uninstall   # remove the global install
#   make clean      # remove build artifacts
#
# Override paths/flags on the command line, e.g.:
#   make CXX=clang++ CXXFLAGS='-O3'
#   sudo make install PREFIX=/usr           # -> /usr/bin/frecover

# ---- toolchain ----
CXX      ?= g++
CXXFLAGS ?= -O2 -Wall -Wextra -std=c++17
LDFLAGS  ?=

# ---- install layout (GNU-standard, DESTDIR-aware for packaging) ----
PREFIX  ?= /usr/local
BINDIR  ?= $(PREFIX)/bin
DESTDIR ?=
INSTALL ?= install

# ---- project ----
BIN     := frecover
SRC     := frecover.cpp

.PHONY: all build run clean install uninstall help

all: build

build: $(BIN)

$(BIN): $(SRC)
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)

run: build
	./$(BIN)

# Install globally. Needs root because BINDIR is system-owned.
install: build
	@if [ -z "$(DESTDIR)" ] && [ ! -w "$(BINDIR)" ]; then \
		echo "error: cannot write to $(BINDIR) -- run 'sudo make install'"; exit 1; \
	fi
	$(INSTALL) -d "$(DESTDIR)$(BINDIR)"
	$(INSTALL) -m 0755 $(BIN) "$(DESTDIR)$(BINDIR)/$(BIN)"
	@echo "installed $(BIN) -> $(DESTDIR)$(BINDIR)/$(BIN)"

# Remove the global install.
uninstall:
	@if [ -z "$(DESTDIR)" ] && [ ! -w "$(BINDIR)" ]; then \
		echo "error: cannot write to $(BINDIR) -- run 'sudo make uninstall'"; exit 1; \
	fi
	rm -f "$(DESTDIR)$(BINDIR)/$(BIN)"
	@echo "removed $(DESTDIR)$(BINDIR)/$(BIN)"

clean:
	rm -f $(BIN)

help:
	@echo "Targets:"
	@echo "  make              build ./frecover"
	@echo "  make run          build, then show usage"
	@echo "  sudo make install     install to $(BINDIR)"
	@echo "  sudo make uninstall   remove from $(BINDIR)"
	@echo "  make clean        remove build artifacts"
	@echo "Variables: CXX CXXFLAGS PREFIX(=$(PREFIX)) BINDIR(=$(BINDIR)) DESTDIR"
