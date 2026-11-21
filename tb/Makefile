SIM ?= icarus
TOPLEVEL_LANG ?= verilog

VERILOG_SOURCES += $(CURDIR)/../rtl/aes_sbox.v
VERILOG_SOURCES += $(CURDIR)/../rtl/aes256_pipe.v
VERILOG_SOURCES += $(CURDIR)/../rtl/ghash_128.v
VERILOG_SOURCES += $(CURDIR)/../rtl/aes256_gcm_top.v

TOPLEVEL = aes256_gcm_top
MODULE = test_aes256_gcm

ifeq ($(SIM),verilator)
EXTRA_ARGS += --Wall -Wno-DECLFILENAME -Wno-UNUSEDSIGNAL
endif

include $(shell cocotb-config --makefiles)/Makefile.sim
