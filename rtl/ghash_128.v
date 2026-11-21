// ============================================================================
// Module: ghash_128
// Description: NIST SP 800-38D GF(2^128) Parallel GHASH Multiplier
//              P(x) = x^128 + x^7 + x^2 + x + 1 (reflected R = 0xE1 << 120)
// ============================================================================
`timescale 1ns / 1ps

module ghash_128 (
    input  wire [127:0] x_in,
    input  wire [127:0] h_in,
    output reg  [127:0] z_out
);
    localparam [127:0] R_POLY = 128'hE1000000_00000000_00000000_00000000;

    integer i;
    reg [127:0] v;
    reg [127:0] z;

    always @(*) begin
        z = 128'd0;
        v = h_in;
        for (i = 127; i >= 0; i = i - 1) begin
            if (x_in[i]) z = z ^ v;
            if (v[0])
                v = (v >> 1) ^ R_POLY;
            else
                v = (v >> 1);
        end
        z_out = z;
    end
endmodule
