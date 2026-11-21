# ASAP7 time unit is picoseconds (1000 ps = 1.0 ns = 1.0 GHz -> 128 Gbps)
create_clock -name clk -period 1000 [get_ports clk]
set_input_delay  200 -clock clk [all_inputs]
set_output_delay 200 -clock clk [all_outputs]
