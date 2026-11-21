// ============================================================================
// Module: aes256_gcm_top
// Description: 128 Gbps AES-256-GCM (CTR + GHASH) Line-Rate Crypto Engine
//              Targeting ASAP7 (7nm FinFET) @ 1.0 GHz (1000 ps period).
//              AXI4-Lite CSRs:
//                0x00 CTRL   : [0] start_key_exp, [1] new_frame (reset GHASH/CTR)
//                0x04..0x20 KEY[0..7] (256-bit key, big-endian word order)
//                0x24..0x2C IV[0..2]  (96-bit IV, big-endian word order)
//                0x30..0x3C TAG[0..3] (128-bit GCM auth tag, RO)
//                0x40 STATUS : [0] key_ready, [1] tag_valid, [31:16] blk_cnt
// ============================================================================
`timescale 1ns / 1ps

module aes256_gcm_top (
    input  wire         clk,
    input  wire         rst_n,

    // AXI4-Lite Slave
    input  wire [6:0]   s_axil_awaddr,
    input  wire         s_axil_awvalid,
    output reg          s_axil_awready,
    input  wire [31:0]  s_axil_wdata,
    input  wire [3:0]   s_axil_wstrb,
    input  wire         s_axil_wvalid,
    output reg          s_axil_wready,
    output reg  [1:0]   s_axil_bresp,
    output reg          s_axil_bvalid,
    input  wire         s_axil_bready,
    input  wire [6:0]   s_axil_araddr,
    input  wire         s_axil_arvalid,
    output reg          s_axil_arready,
    output reg  [31:0]  s_axil_rdata,
    output reg  [1:0]   s_axil_rresp,
    output reg          s_axil_rvalid,
    input  wire         s_axil_rready,

    // AXI4-Stream Plaintext Input (128-bit)
    input  wire [127:0] s_axis_tdata,
    input  wire         s_axis_tvalid,
    output wire         s_axis_tready,
    input  wire         s_axis_tlast,

    // AXI4-Stream Ciphertext Output (128-bit)
    output reg  [127:0] m_axis_tdata,
    output reg          m_axis_tvalid,
    input  wire         m_axis_tready,
    output reg          m_axis_tlast
);

    reg [31:0] key_regs [0:7];
    reg [31:0] iv_regs  [0:2];
    reg [127:0] ghash_h;
    reg [127:0] ej0;
    reg [127:0] y_ghash;
    reg [127:0] tag_reg;
    reg         tag_valid;
    reg [31:0]  ctr_val;
    reg [15:0]  blk_cnt;

    reg         start_key_exp;
    reg         new_frame;

    // Internal AES-256 Pipeline Control
    localparam INIT_IDLE   = 3'd0;
    localparam INIT_WAIT_K = 3'd1;
    localparam INIT_SEND_H = 3'd2;
    localparam INIT_WAIT_H = 3'd3;
    localparam INIT_SEND_J = 3'd4;
    localparam INIT_WAIT_J = 3'd5;
    localparam INIT_READY  = 3'd6;

    reg [2:0] init_state;
    reg [127:0] aes_in_blk;
    reg [127:0] aes_in_aux;
    reg         aes_in_vld;
    wire [127:0] aes_out_blk;
    wire [127:0] aes_out_aux;
    wire         aes_out_vld;
    wire         key_ready;

    // Track tlast through 15-cycle pipeline (1 + 14)
    reg [15:0] tlast_pipe;

    wire [255:0] full_key = {
        key_regs[0], key_regs[1], key_regs[2], key_regs[3],
        key_regs[4], key_regs[5], key_regs[6], key_regs[7]
    };
    wire [95:0] full_iv = {iv_regs[0], iv_regs[1], iv_regs[2]};

    assign s_axis_tready = (init_state == INIT_READY) && m_axis_tready;

    aes256_pipe u_aes (
        .clk      (clk),
        .rst_n    (rst_n),
        .key_in   (full_key),
        .key_start(start_key_exp),
        .key_ready(key_ready),
        .block_in (aes_in_blk),
        .aux_in   (aes_in_aux),
        .valid_in (aes_in_vld),
        .block_out(aes_out_blk),
        .aux_out  (aes_out_aux),
        .valid_out(aes_out_vld)
    );

    // GHASH combinational step
    wire [127:0] ct_wire = aes_out_blk ^ aes_out_aux;
    wire [127:0] gh_in_x = y_ghash ^ ct_wire;
    wire [127:0] gh_mult_out;
    ghash_128 u_ghash (.x_in(gh_in_x), .h_in(ghash_h), .z_out(gh_mult_out));

    // Finalize tag with len(AAD)=0, len(C)=blk_cnt*128
    wire [127:0] len_blk = {64'd0, {41'd0, blk_cnt, 7'd0}};
    wire [127:0] gh_len_out;
    ghash_128 u_ghash_len (.x_in(gh_mult_out ^ len_blk), .h_in(ghash_h), .z_out(gh_len_out));

    // AXI4-Lite CSRs
    reg aw_en, aw_cap, w_cap;
    reg [6:0] awaddr_q;
    reg [31:0] wdata_q;
    integer idx;

    always @(posedge clk) begin
        if (!rst_n) begin
            s_axil_awready <= 1'b0; s_axil_wready <= 1'b0;
            s_axil_bvalid  <= 1'b0; s_axil_bresp  <= 2'b00;
            s_axil_arready <= 1'b0; s_axil_rvalid <= 1'b0;
            s_axil_rresp   <= 2'b00; s_axil_rdata <= 32'd0;
            aw_en <= 1'b1; aw_cap <= 1'b0; w_cap <= 1'b0;
            awaddr_q <= 7'd0; wdata_q <= 32'd0;
            start_key_exp <= 1'b0; new_frame <= 1'b0;
            for (idx = 0; idx < 8; idx = idx + 1) key_regs[idx] <= 32'd0;
            for (idx = 0; idx < 3; idx = idx + 1) iv_regs[idx]  <= 32'd0;
        end else begin
            start_key_exp <= 1'b0;
            new_frame     <= 1'b0;

            if (!s_axil_awready && s_axil_awvalid && !aw_cap && aw_en) begin
                s_axil_awready <= 1'b1; awaddr_q <= s_axil_awaddr; aw_cap <= 1'b1;
            end else s_axil_awready <= 1'b0;

            if (!s_axil_wready && s_axil_wvalid && !w_cap && aw_en) begin
                s_axil_wready <= 1'b1; wdata_q <= s_axil_wdata; w_cap <= 1'b1;
            end else s_axil_wready <= 1'b0;

            if (aw_cap && w_cap && !s_axil_bvalid) begin
                aw_cap <= 1'b0; w_cap <= 1'b0; aw_en <= 1'b0;
                s_axil_bvalid <= 1'b1; s_axil_bresp <= 2'b00;
                if (s_axil_wstrb[0]) begin
                    case (awaddr_q[6:2])
                        5'h00: begin
                            start_key_exp <= wdata_q[0];
                            new_frame     <= wdata_q[1];
                        end
                        5'h01: key_regs[0] <= wdata_q;
                        5'h02: key_regs[1] <= wdata_q;
                        5'h03: key_regs[2] <= wdata_q;
                        5'h04: key_regs[3] <= wdata_q;
                        5'h05: key_regs[4] <= wdata_q;
                        5'h06: key_regs[5] <= wdata_q;
                        5'h07: key_regs[6] <= wdata_q;
                        5'h08: key_regs[7] <= wdata_q;
                        5'h09: iv_regs[0]  <= wdata_q;
                        5'h0A: iv_regs[1]  <= wdata_q;
                        5'h0B: iv_regs[2]  <= wdata_q;
                        default: ;
                    endcase
                end
            end else if (s_axil_bvalid && s_axil_bready) begin
                s_axil_bvalid <= 1'b0; aw_en <= 1'b1;
            end

            if (!s_axil_arready && s_axil_arvalid && !s_axil_rvalid) begin
                s_axil_arready <= 1'b1; s_axil_rvalid <= 1'b1; s_axil_rresp <= 2'b00;
                case (s_axil_araddr[6:2])
                    5'h0C: s_axil_rdata <= tag_reg[127:96];
                    5'h0D: s_axil_rdata <= tag_reg[95:64];
                    5'h0E: s_axil_rdata <= tag_reg[63:32];
                    5'h0F: s_axil_rdata <= tag_reg[31:0];
                    5'h10: s_axil_rdata <= {blk_cnt, 14'd0, tag_valid, (init_state == INIT_READY)};
                    default: s_axil_rdata <= 32'd0;
                endcase
            end else begin
                s_axil_arready <= 1'b0;
                if (s_axil_rvalid && s_axil_rready) s_axil_rvalid <= 1'b0;
            end
        end
    end

    // Datapath & GCM Initialization FSM
    always @(posedge clk) begin
        if (!rst_n) begin
            init_state    <= INIT_IDLE;
            aes_in_blk    <= 128'd0;
            aes_in_aux    <= 128'd0;
            aes_in_vld    <= 1'b0;
            ghash_h       <= 128'd0;
            ej0           <= 128'd0;
            y_ghash       <= 128'd0;
            tag_reg       <= 128'd0;
            tag_valid     <= 1'b0;
            ctr_val       <= 32'd2;
            blk_cnt       <= 16'd0;
            tlast_pipe    <= 16'd0;
            m_axis_tdata  <= 128'd0;
            m_axis_tvalid <= 1'b0;
            m_axis_tlast  <= 1'b0;
        end else begin
            aes_in_vld    <= 1'b0;
            m_axis_tvalid <= 1'b0;
            m_axis_tlast  <= 1'b0;
            tlast_pipe    <= {tlast_pipe[14:0], (init_state == INIT_READY) && s_axis_tvalid && s_axis_tready && s_axis_tlast};

            if (start_key_exp) begin
                init_state <= INIT_WAIT_K;
                tag_valid  <= 1'b0;
                y_ghash    <= 128'd0;
                ctr_val    <= 32'd2;
                blk_cnt    <= 16'd0;
            end else if (new_frame) begin
                init_state <= INIT_SEND_J;
                tag_valid  <= 1'b0;
                y_ghash    <= 128'd0;
                ctr_val    <= 32'd2;
                blk_cnt    <= 16'd0;
            end else begin
                case (init_state)
                    INIT_WAIT_K: if (key_ready) init_state <= INIT_SEND_H;
                    INIT_SEND_H: begin
                        aes_in_blk <= 128'd0;
                        aes_in_aux <= 128'd0;
                        aes_in_vld <= 1'b1;
                        init_state <= INIT_WAIT_H;
                    end
                    INIT_WAIT_H: if (aes_out_vld) begin
                        ghash_h    <= aes_out_blk;
                        init_state <= INIT_SEND_J;
                    end
                    INIT_SEND_J: begin
                        aes_in_blk <= {full_iv, 32'd1}; // J0 = IV || 0x00000001
                        aes_in_aux <= 128'd0;
                        aes_in_vld <= 1'b1;
                        init_state <= INIT_WAIT_J;
                    end
                    INIT_WAIT_J: if (aes_out_vld) begin
                        ej0        <= aes_out_blk;
                        init_state <= INIT_READY;
                    end
                    INIT_READY: begin
                        if (s_axis_tvalid && s_axis_tready) begin
                            aes_in_blk <= {full_iv, ctr_val};
                            aes_in_aux <= s_axis_tdata;
                            aes_in_vld <= 1'b1;
                            ctr_val    <= ctr_val + 32'd1;
                            blk_cnt    <= blk_cnt + 16'd1;
                        end
                        if (aes_out_vld) begin
                            m_axis_tdata  <= ct_wire;
                            m_axis_tvalid <= 1'b1;
                            m_axis_tlast  <= tlast_pipe[15];
                            y_ghash       <= gh_mult_out;
                            if (tlast_pipe[15]) begin
                                tag_reg   <= gh_len_out ^ ej0;
                                tag_valid <= 1'b1;
                            end
                        end
                    end
                    default: init_state <= INIT_IDLE;
                endcase
            end
        end
    end

endmodule
