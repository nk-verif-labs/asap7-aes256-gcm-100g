`timescale 1ns / 1ps

module ghash_128 (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         start,
    input  wire [127:0] x_in,
    input  wire [127:0] h_in,
    output reg  [127:0] z_out,
    output reg          done
);
    localparam [127:0] R_POLY = 128'hE1000000_00000000_00000000_00000000;

    reg [1:0]   cyc;
    reg         busy;
    reg [127:0] z_q, v_q, x_q;

    integer i;
    reg [127:0] z_next, v_next;
    reg [31:0]  x_slice;

    always @(*) begin
        z_next  = z_q;
        v_next  = v_q;
        x_slice = x_q[127:96];
        for (i = 31; i >= 0; i = i - 1) begin
            if (x_slice[i]) z_next = z_next ^ v_next;
            v_next = v_next[0] ? ((v_next >> 1) ^ R_POLY) : (v_next >> 1);
        end
    end

    always @(posedge clk) begin
        if (!rst_n) begin
            cyc <= 2'd0; busy <= 1'b0; done <= 1'b0;
            z_q <= 128'd0; v_q <= 128'd0; x_q <= 128'd0; z_out <= 128'd0;
        end else begin
            done <= 1'b0;
            if (start) begin
                z_q  <= 128'd0;
                v_q  <= h_in;
                x_q  <= x_in;
                cyc  <= 2'd0;
                busy <= 1'b1;
            end else if (busy) begin
                z_q <= z_next;
                v_q <= v_next;
                x_q <= {x_q[95:0], 32'd0};
                if (cyc == 2'd3) begin
                    z_out <= z_next;
                    done  <= 1'b1;
                    busy  <= 1'b0;
                end else begin
                    cyc <= cyc + 2'd1;
                end
            end
        end
    end
endmodule
