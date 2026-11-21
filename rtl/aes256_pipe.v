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
    input  wire         last_in,
    input  wire         valid_in,
    output wire         busy,

    output reg  [127:0] block_out,
    output reg  [127:0] aux_out,
    output reg          last_out,
    output reg          valid_out
);

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
            key_ready <= 1'b0; kbusy <= 1'b0; kidx <= 6'd0;
            for (wi = 0; wi < 60; wi = wi + 1) w[wi] <= 32'd0;
        end else if (key_start) begin
            w[0] <= key_in[255:224]; w[1] <= key_in[223:192];
            w[2] <= key_in[191:160]; w[3] <= key_in[159:128];
            w[4] <= key_in[127:96];  w[5] <= key_in[95:64];
            w[6] <= key_in[63:32];   w[7] <= key_in[31:0];
            kidx <= 6'd8; kbusy <= 1'b1; key_ready <= 1'b0;
        end else if (kbusy) begin
            w[kidx] <= kw_m8 ^ k_sub;
            if (kidx == 6'd59) begin
                kbusy <= 1'b0; key_ready <= 1'b1;
            end else kidx <= kidx + 6'd1;
        end
    end

    reg [127:0] st_q, aux_q;
    reg         last_q, rnd_busy;
    reg [3:0]   rnd_cnt;

    wire [127:0] rk0 = {w[0], w[1], w[2], w[3]};
    wire [127:0] rkr = {w[{rnd_cnt, 2'd0}], w[{rnd_cnt, 2'd1}], w[{rnd_cnt, 2'd2}], w[{rnd_cnt, 2'd3}]};
    wire [127:0] rnd_out;

    aes256_round u_rnd (
        .state_in (st_q),
        .rkey     (rkr),
        .is_last  (rnd_cnt == 4'd14),
        .state_out(rnd_out)
    );

    assign busy = rnd_busy;

    always @(posedge clk) begin
        if (!rst_n) begin
            st_q <= 128'd0; aux_q <= 128'd0; last_q <= 1'b0;
            rnd_busy <= 1'b0; rnd_cnt <= 4'd0;
            block_out <= 128'd0; aux_out <= 128'd0; last_out <= 1'b0; valid_out <= 1'b0;
        end else begin
            valid_out <= 1'b0;
            if (valid_in && !rnd_busy) begin
                st_q     <= block_in ^ rk0;
                aux_q    <= aux_in;
                last_q   <= last_in;
                rnd_cnt  <= 4'd1;
                rnd_busy <= 1'b1;
            end else if (rnd_busy) begin
                if (rnd_cnt == 4'd14) begin
                    block_out <= rnd_out;
                    aux_out   <= aux_q;
                    last_out  <= last_q;
                    valid_out <= 1'b1;
                    rnd_busy  <= 1'b0;
                end else begin
                    st_q    <= rnd_out;
                    rnd_cnt <= rnd_cnt + 4'd1;
                end
            end
        end
    end
endmodule
