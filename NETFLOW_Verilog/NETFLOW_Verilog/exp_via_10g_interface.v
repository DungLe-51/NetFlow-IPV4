// ============================================================
//  exp_via_10g_interface.v  —  Xuất flow thẳng ra giao diện 10G
//
//  Chuyển từ: exp_via_10g_interface.vhd
//
//  Mô tả:
//    Dùng khi không có pcore netflow_export (NETFLOW_EXPORT_PRESENT=0).
//    Đọc entry 240-bit từ FIFO export và phát thành 6 transaction
//    AXI4-Stream 64-bit theo định dạng Ethernet phi chuẩn.
//    Byte order được đảo (big-endian) để dễ phân tích phía thu.
//
//    Layout 6 beat (sau khi đảo byte):
//      Beat 1: five_tuple[103:40]         — Src IP, Dst IP, Src Port (một phần)
//      Beat 2: five_tuple[39:0] + 3 byte 0 — Dst Port + Protocol + padding
//      Beat 3: frame_counter[31:0] | byte_counter[31:0]
//      Beat 4: initial_timestamp | last_timestamp
//      Beat 5: tcp_flags | 3 byte 0 | collision_counter
//      Beat 6: processed_packets | 4 byte 0  + tlast=1
// ============================================================

`include "flow_cache_pack.vh"

module exp_via_10g_interface #(
    parameter C_M_AXIS_EXP_RECORDS_DATA_WIDTH = 64
)(
    input  wire        ACLK,
    input  wire        ARESETN,
    // AXI4-Stream master
    output wire [63:0] M_AXIS_10GMAC_tdata,
    output reg  [63/8:0] M_AXIS_10GMAC_tstrb,
    output reg         M_AXIS_10GMAC_tvalid,
    input  wire        M_AXIS_10GMAC_tready,
    output reg         M_AXIS_10GMAC_tlast,
    // Counters
    input  wire [31:0] counters,          // num_processed_pkts
    input  wire [31:0] collision_counter,
    // FIFO interface
    output reg         fifo_rd_exp_en,
    input  wire [`FIFO_DATA_WIDTH-1:0] fifo_out_exp,
    input  wire        fifo_empty_exp
);

    localparam S0=4'd0, S1=4'd1, S2=4'd2, S3=4'd3,
               S4=4'd4, S5=4'd5, S6=4'd6, S7=4'd7, S8=4'd8;

    reg [3:0]  fsm_exp;
    reg [`FIFO_DATA_WIDTH-1:0] flow_to_export;
    reg [63:0] tdata_rev;   // dữ liệu trước khi đảo byte

    // Đảo thứ tự byte (little-endian → big-endian)
    genvar L;
    generate
        for (L = 0; L < C_M_AXIS_EXP_RECORDS_DATA_WIDTH/8; L = L + 1) begin : rev
            assign M_AXIS_10GMAC_tdata[C_M_AXIS_EXP_RECORDS_DATA_WIDTH - L*8 - 1 -: 8] =
                   tdata_rev[(L+1)*8 - 1 -: 8];
        end
    endgenerate

    // Giải nén các trường từ flow_to_export
    wire [31:0] byte_counter       = flow_to_export[31:0];
    wire [31:0] frame_counter      = flow_to_export[63:32];
    wire [31:0] last_timestamp     = flow_to_export[95:64];
    wire [31:0] initial_timestamp  = flow_to_export[127:96];
    wire [7:0]  tcp_flags          = flow_to_export[135:128];
    wire [103:0] five_tuple        = flow_to_export[239:136];
    wire [31:0]  processed_packets = counters;

    always @(posedge ACLK) begin
        if (!ARESETN) begin
            tdata_rev            <= 64'd0;
            M_AXIS_10GMAC_tstrb  <= 8'd0;
            M_AXIS_10GMAC_tvalid <= 1'b0;
            M_AXIS_10GMAC_tlast  <= 1'b0;
            fifo_rd_exp_en       <= 1'b0;
            fsm_exp              <= S0;
        end else begin
            case (fsm_exp)
                S0: begin
                    M_AXIS_10GMAC_tvalid <= 1'b0;
                    M_AXIS_10GMAC_tlast  <= 1'b0;
                    if (!fifo_empty_exp) begin
                        fifo_rd_exp_en <= 1'b1;
                        fsm_exp        <= S1;
                    end
                end
                S1: begin
                    fifo_rd_exp_en <= 1'b0;
                    fsm_exp        <= S2;
                end
                S2: begin
                    flow_to_export <= fifo_out_exp;
                    fsm_exp        <= S3;
                end
                S3: begin   // Beat 1: Src IP + Dst IP + 2 byte đầu Src Port
                    if (M_AXIS_10GMAC_tready) begin
                        M_AXIS_10GMAC_tstrb  <= 8'hFF;
                        M_AXIS_10GMAC_tvalid <= 1'b1;
                        tdata_rev            <= five_tuple[103:40];
                        fsm_exp              <= S4;
                    end
                end
                S4: begin   // Beat 2: 2 byte cuối Src Port + Dst Port + Proto + padding
                    M_AXIS_10GMAC_tvalid <= 1'b0;
                    if (M_AXIS_10GMAC_tready) begin
                        M_AXIS_10GMAC_tvalid <= 1'b1;
                        tdata_rev            <= {five_tuple[39:0], 24'h000000};
                        fsm_exp              <= S5;
                    end
                end
                S5: begin   // Beat 3: frame_counter | byte_counter
                    M_AXIS_10GMAC_tvalid <= 1'b0;
                    if (M_AXIS_10GMAC_tready) begin
                        M_AXIS_10GMAC_tvalid <= 1'b1;
                        tdata_rev            <= {frame_counter, byte_counter};
                        fsm_exp              <= S6;
                    end
                end
                S6: begin   // Beat 4: initial_timestamp | last_timestamp
                    M_AXIS_10GMAC_tvalid <= 1'b0;
                    if (M_AXIS_10GMAC_tready) begin
                        M_AXIS_10GMAC_tvalid <= 1'b1;
                        tdata_rev            <= {initial_timestamp, last_timestamp};
                        fsm_exp              <= S7;
                    end
                end
                S7: begin   // Beat 5: tcp_flags | padding | collision_counter
                    M_AXIS_10GMAC_tvalid <= 1'b0;
                    if (M_AXIS_10GMAC_tready) begin
                        M_AXIS_10GMAC_tvalid <= 1'b1;
                        tdata_rev            <= {tcp_flags, 24'h000000, collision_counter};
                        fsm_exp              <= S8;
                    end
                end
                S8: begin   // Beat 6: processed_packets | padding + tlast
                    M_AXIS_10GMAC_tvalid <= 1'b0;
                    if (M_AXIS_10GMAC_tready) begin
                        M_AXIS_10GMAC_tvalid <= 1'b1;
                        tdata_rev            <= {processed_packets, 32'h00000000};
                        M_AXIS_10GMAC_tlast  <= 1'b1;
                        fsm_exp              <= S0;
                    end
                end
                default: fsm_exp <= S0;
            endcase
        end
    end

endmodule