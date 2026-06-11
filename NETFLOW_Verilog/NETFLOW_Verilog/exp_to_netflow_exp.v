// ============================================================
//  exp_to_netflow_exp.v  —  Xuất flow sang pcore netflow_export
//
//  Chuyển từ: exp_to_netflow_exp.vhd
//
//  Mô tả:
//    Đọc entry 240-bit từ FIFO export và phát thành 4 transaction
//    AXI4-Stream 64-bit để gửi sang pcore netflow_export kế tiếp.
//    Được dùng khi NETFLOW_EXPORT_PRESENT = 1.
//
//    Layout trên bus (theo thứ tự gửi):
//      Beat 1: fifo_out[63:0]
//      Beat 2: fifo_out[127:64]
//      Beat 3: fifo_out[191:128]
//      Beat 4: {16'h0000, fifo_out[239:192]}  + tlast=1
// ============================================================

`include "flow_cache_pack.vh"

module exp_to_netflow_exp #(
    parameter C_S_AXIS_10GMAC_DATA_WIDTH    = 64,
    parameter C_M_AXIS_EXP_RECORDS_DATA_WIDTH = 64
)(
    input  wire        ACLK,
    input  wire        ARESETN,
    // AXI4-Stream master
    output reg  [63:0] M_AXIS_10GMAC_tdata,
    output reg  [C_M_AXIS_EXP_RECORDS_DATA_WIDTH/8-1:0] M_AXIS_10GMAC_tstrb,
    output reg         M_AXIS_10GMAC_tvalid,
    input  wire        M_AXIS_10GMAC_tready,
    output reg         M_AXIS_10GMAC_tlast,
    // FIFO interface
    output reg         fifo_rd_exp_en,
    input  wire [`FIFO_DATA_WIDTH-1:0] fifo_out_exp,
    input  wire        fifo_empty_exp
);

    localparam S0=3'd0, S1=3'd1, S2=3'd2,
               S3=3'd3, S4=3'd4, S5=3'd5, S6=3'd6;

    reg [2:0] fsm_exp;
    reg [`FIFO_DATA_WIDTH-1:0] flow_to_export;

    always @(posedge ACLK) begin
        if (!ARESETN) begin
            M_AXIS_10GMAC_tdata  <= 64'd0;
            M_AXIS_10GMAC_tstrb  <= {(C_M_AXIS_EXP_RECORDS_DATA_WIDTH/8){1'b0}};
            M_AXIS_10GMAC_tvalid <= 1'b0;
            M_AXIS_10GMAC_tlast  <= 1'b0;
            fifo_rd_exp_en       <= 1'b0;
            fsm_exp              <= S0;
        end else begin
            case (fsm_exp)
                S0: begin   // Chờ FIFO có dữ liệu
                    M_AXIS_10GMAC_tvalid <= 1'b0;
                    M_AXIS_10GMAC_tlast  <= 1'b0;
                    if (!fifo_empty_exp) begin
                        fifo_rd_exp_en <= 1'b1;
                        fsm_exp        <= S1;
                    end
                end
                S1: begin   // Pulse đọc FIFO
                    fifo_rd_exp_en <= 1'b0;
                    fsm_exp        <= S2;
                end
                S2: begin   // Latch dữ liệu FIFO
                    flow_to_export <= fifo_out_exp;
                    fsm_exp        <= S3;
                end
                S3: begin   // Beat 1
                    if (M_AXIS_10GMAC_tready) begin
                        M_AXIS_10GMAC_tstrb  <= {(C_M_AXIS_EXP_RECORDS_DATA_WIDTH/8){1'b1}};
                        M_AXIS_10GMAC_tvalid <= 1'b1;
                        M_AXIS_10GMAC_tdata  <= flow_to_export[63:0];
                        fsm_exp              <= S4;
                    end
                end
                S4: begin   // Beat 2
                    M_AXIS_10GMAC_tvalid <= 1'b0;
                    if (M_AXIS_10GMAC_tready) begin
                        M_AXIS_10GMAC_tvalid <= 1'b1;
                        M_AXIS_10GMAC_tdata  <= flow_to_export[127:64];
                        fsm_exp              <= S5;
                    end
                end
                S5: begin   // Beat 3
                    M_AXIS_10GMAC_tvalid <= 1'b0;
                    if (M_AXIS_10GMAC_tready) begin
                        M_AXIS_10GMAC_tvalid <= 1'b1;
                        M_AXIS_10GMAC_tdata  <= flow_to_export[191:128];
                        fsm_exp              <= S6;
                    end
                end
                S6: begin   // Beat 4 + tlast
                    M_AXIS_10GMAC_tvalid <= 1'b0;
                    if (M_AXIS_10GMAC_tready) begin
                        M_AXIS_10GMAC_tvalid <= 1'b1;
                        M_AXIS_10GMAC_tdata  <= {16'h0000, flow_to_export[239:192]};
                        M_AXIS_10GMAC_tlast  <= 1'b1;
                        fsm_exp              <= S0;
                    end
                end
                default: fsm_exp <= S0;
            endcase
        end
    end

endmodule