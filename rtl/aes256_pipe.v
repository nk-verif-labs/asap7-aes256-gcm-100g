// ============================================================================
// Module: aes256_pipe
// Description: 14-Stage Pipelined AES-256 Encryption Core + Key Expansion
//              Sustains 128 bits/cycle (128 Gbps @ 1.0 GHz on ASAP7).
// ============================================================================
`timescale 1ns / 1ps

module aes256_round (
    input  wire [127:0] state_in,
    input  wire [127:0] rkey,
    input  wire         is_last,
    output wire [127:0] state_out
);
    function [7:0] xtime;
        input [7:0] b;
        begin
            xtime = b[7] ? ({b[6:0], 1'b0} ^ 8'h1b) : {b[6:0], 1'b0};
        end
    endfunction

    wire [127:0] sub_bytes;
    genvar g;
    generate
        for (g = 0; g < 16; g = g + 1) begin : gen_sb
            aes_sbox u_sb (
                .in_byte (state_in[127 - g*8 -: 8]),
                .out_byte(sub_bytes[127 - g*8 -: 8])
            );
        end
    endgenerate

    // ShiftRows (byte 0 = [127:120], byte 15 = [7:0])
    wire [7:0] s0  = sub_bytes[127:120]; wire [7:0] s1  = sub_bytes[119:112];
    wire [7:0] s2  = sub_bytes[111:104]; wire [7:0] s3  = sub_bytes[103:96];
    wire [7:0] s4  = sub_bytes[95:88];   wire [7:0] s5  = sub_bytes[87:80];
    wire [7:0] s6  = sub_bytes[79:72];   wire [7:0] s7  = sub_bytes[71:64];
    wire [7:0] s8  = sub_bytes[63:56];   wire [7:0] s9  = sub_bytes[55:48];
    wire [7:0] s10 = sub_bytes[47:40];   wire [7:0] s11 = sub_bytes[39:32];
    wire [7:0] s12 = sub_bytes[31:24];   wire [7:0] s13 = sub_bytes[23:16];
    wire [7:0] s14 = sub_bytes[15:8];    wire [7:0] s15 = sub_bytes[7:0];

    wire [127:0] shift_rows = {
        s0, s5, s10, s15,
        s4, s9, s14, s3,
        s8, s13, s2, s7,
        s12, s1, s6, s11
    };

    // MixColumns
    reg [127:0] mix_cols;
    integer c;
    reg [7:0] a0, a1, a2, a3;
    always @(*) begin
        for (c = 0; c < 4; c = c + 1) begin
            a0 = shift_rows[127 - c*32 -: 8];
            a1 = shift_rows[119 - c*32 -: 8];
            a2 = shift_rows[111 - c*32 -: 8];
            a3 = shift_rows[103 - c*32 -: 8];
            mix_cols[127 - c*32 -: 8] = xtime(a0) ^ xtime(a1) ^ a1 ^ a2 ^ a3;
            mix_cols[119 - c*32 -: 8] = a0 ^ xtime(a1) ^ xtime(a2) ^ a2 ^ a3;
            mix_cols[111 - c*32 -: 8] = a0 ^ a1 ^ xtime(a2) ^ xtime(a3) ^ a3;
            mix_cols[103 - c*32 -: 8] = xtime(a0) ^ a0 ^ a1 ^ a2 ^ xtime(a3);
        end
    end

    assign state_out = (is_last ? shift_rows : mix_cols) ^ rkey;
endmodule

module aes256_pipe (
    input  wire         clk,
    input  wire         rst_n,

    input  wire [255:0] key_in,
    input  wire         key_start,
    output reg          key_ready,

    input  wire [127:0] block_in,
    input  wire [127:0] aux_in,
    input  wire         valid_in,

    output wire [127:0] block_out,
    output wire [127:0] aux_out,
    output wire         valid_out
);

    // Key Expansion Storage: 60 32-bit words (15 round keys x 128 bits)
    reg [31:0] w [0:59];
    reg [5:0]  kidx;
    reg        kbusy;

    function [7:0] rcon_val;
        input [2:0] idx;
        begin
            case (idx)
                3'd0: rcon_val = 8'h01; 3'd1: rcon_val = 8'h02;
                3'd2: rcon_val = 8'h04; 3'd3: rcon_val = 8'h08;
                3'd4: rcon_val = 8'h10; 3'd5: rcon_val = 8'h20;
                3'd6: rcon_val = 8'h40; default: rcon_val = 8'h00;
            endcase
        end
    endfunction

    wire [31:0] kw_prev = w[kidx - 6'd1];
    wire [31:0] kw_m8   = w[kidx - 6'd8];
    wire [31:0] ksb_in  = (kidx[2:0] == 3'd0) ? {kw_prev[23:0], kw_prev[31:24]} : kw_prev;
    wire [31:0] ksb_out;

    aes_sbox u_ksb0 (.in_byte(ksb_in[31:24]), .out_byte(ksb_out[31:24]));
    aes_sbox u_ksb1 (.in_byte(ksb_in[23:16]), .out_byte(ksb_out[23:16]));
    aes_sbox u_ksb2 (.in_byte(ksb_in[15:8]),  .out_byte(ksb_out[15:8]));
    aes_sbox u_ksb3 (.in_byte(ksb_in[7:0]),   .out_byte(ksb_out[7:0]));

    wire [2:0]  rcon_idx = (kidx[5:3] - 3'd1);
    wire [31:0] k_sub = (kidx[2:0] == 3'd0) ? (ksb_out ^ {rcon_val(rcon_idx), 24'd0}) :
                        (kidx[2:0] == 3'd4) ? ksb_out : kw_prev;

    integer wi;
    always @(posedge clk) begin
        if (!rst_n) begin
            key_ready <= 1'b0;
            kbusy     <= 1'b0;
            kidx      <= 6'd0;
            for (wi = 0; wi < 60; wi = wi + 1) w[wi] <= 32'd0;
        end else if (key_start) begin
            w[0] <= key_in[255:224]; w[1] <= key_in[223:192];
            w[2] <= key_in[191:160]; w[3] <= key_in[159:128];
            w[4] <= key_in[127:96];  w[5] <= key_in[95:64];
            w[6] <= key_in[63:32];   w[7] <= key_in[31:0];
            kidx      <= 6'd8;
            kbusy     <= 1'b1;
            key_ready <= 1'b0;
        end else if (kbusy) begin
            w[kidx] <= kw_m8 ^ k_sub;
            if (kidx == 6'd59) begin
                kbusy     <= 1'b0;
                key_ready <= 1'b1;
            end else begin
                kidx <= kidx + 6'd1;
            end
        end
    end

    // 14-Stage Pipelined Encryption Datapath
    reg [127:0] st_q   [0:14];
    reg [127:0] aux_q  [0:14];
    reg         vld_q  [0:14];
    wire [127:0] rnd_out [1:14];

    wire [127:0] rk0 = {w[0], w[1], w[2], w[3]};

    always @(posedge clk) begin
        if (!rst_n) begin
            st_q[0]  <= 128'd0;
            aux_q[0] <= 128'd0;
            vld_q[0] <= 1'b0;
        end else begin
            st_q[0]  <= block_in ^ rk0;
            aux_q[0] <= aux_in;
            vld_q[0] <= valid_in;
        end
    end

    genvar r;
    generate
        for (r = 1; r <= 14; r = r + 1) begin : gen_rnd
            wire [127:0] rkr = {w[4*r], w[4*r+1], w[4*r+2], w[4*r+3]};
            aes256_round u_rnd (
                .state_in (st_q[r-1]),
                .rkey     (rkr),
                .is_last  (r == 14),
                .state_out(rnd_out[r])
            );
            always @(posedge clk) begin
                if (!rst_n) begin
                    st_q[r]  <= 128'd0;
                    aux_q[r] <= 128'd0;
                    vld_q[r] <= 1'b0;
                end else begin
                    st_q[r]  <= rnd_out[r];
                    aux_q[r] <= aux_q[r-1];
                    vld_q[r] <= vld_q[r-1];
                end
            end
        end
    endgenerate

    assign block_out = st_q[14];
    assign aux_out   = aux_q[14];
    assign valid_out = vld_q[14];

endmodule
