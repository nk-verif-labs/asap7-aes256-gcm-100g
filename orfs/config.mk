export DESIGN_NAME      = aes256_gcm_top
export PLATFORM         = asap7
ORFS_CFG_DIR            := $(patsubst %/,%,$(dir $(lastword $(MAKEFILE_LIST))))
export VERILOG_FILES    = $(abspath $(ORFS_CFG_DIR)/../rtl/aes_sbox.v) \
                          $(abspath $(ORFS_CFG_DIR)/../rtl/aes256_pipe.v) \
                          $(abspath $(ORFS_CFG_DIR)/../rtl/ghash_128.v) \
                          $(abspath $(ORFS_CFG_DIR)/../rtl/aes256_gcm_top.v)
export SDC_FILE         = $(abspath $(ORFS_CFG_DIR)/constraint.sdc)
export CORE_UTILIZATION = 45
export PLACE_DENSITY    = 0.55
export TNS_END_PERCENT  = 100
