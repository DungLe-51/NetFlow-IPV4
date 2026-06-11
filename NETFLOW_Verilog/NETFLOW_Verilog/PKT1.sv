// ============================================================
//  pkt_classification.v  —  Phân loại gói tin & trích xuất 5-tuple
//
//  Chuyển từ: pkt_classification.vhd
//
//  Mô tả:
//    Nhận luồng AXI4-Stream 64-bit từ 10G MAC.
//    Hỗ trợ 3 loại frame Ethernet:
//      • Không VLAN      (EtherType 0x0800)
//      • 1 VLAN tag      (EtherType 0x8100)
//      • 2 VLAN tag QinQ (EtherType 0x88A8)
//    Chỉ xử lý IPv4 TCP/UDP; các frame khác bị bỏ qua.
//    Kết quả:
//      five_tuple          = src_ip[32]|dst_ip[32]|src_port[16]|dst_port[16]|proto[8]
//      pkt_info            = tcp_flags[8]|timestamp[32]|ip_total_length[16]
//      tuple_and_info_valid = 1 khi kết quả hợp lệ (cuối frame)
// ============================================================

`include "flow_cache_pack.vh"

module pkt_classification #(
    parameter C_S_AXIS_10GMAC_DATA_WIDTH = 64
)(
    input  wire        ACLK,
    input  wire        ARESETN,
    // AXI4-Stream slave
    output reg         S_AXIS_TREADY,
    input  wire [C_S_AXIS_10GMAC_DATA_WIDTH-1:0] S_AXIS_TDATA,
    input  wire [C_S_AXIS_10GMAC_DATA_WIDTH/8-1:0] S_AXIS_TSTRB,
    input  wire        S_AXIS_TLAST,
    input  wire        S_AXIS_TVALID,
    // Timestamp
    input  wire [`TIMESTAMP_WIDTH-1:0] timestamp_counter,
    
    // Handshake downstream (Fix cho valid pulse)
    input  wire        tuple_consumed, 

    // Outputs
    output reg  [31:0] num_processed_pkts,
    output wire [`FIVE_TUPLE_WIDTH-1:0]  five_tuple,
    output reg  [`PKT_INFO_WIDTH-1:0]   pkt_info,
    output reg         tuple_and_info_valid
);

    // ----------------------------------------------------------
    // Đảo thứ tự byte để phân tích header dễ hơn (big-endian)
    // ----------------------------------------------------------
    wire [C_S_AXIS_10GMAC_DATA_WIDTH-1:0] S_AXIS_TDATA_rev;
    genvar L;
    generate
        for (L = 0; L < C_S_AXIS_10GMAC_DATA_WIDTH/8; L = L + 1) begin : rev_byte
            assign S_AXIS_TDATA_rev[C_S_AXIS_10GMAC_DATA_WIDTH - L*8 - 1 -: 8] =
                   S_AXIS_TDATA[(L+1)*8 - 1 -: 8];
        end
    endgenerate

    // ----------------------------------------------------------
    // Thanh ghi frame info
    // ----------------------------------------------------------
    reg [`IP_TOTAL_LENGTH_FIELD_WIDTH-1:0] frame_ip_total_length;
    reg [`TCP_FLAGS_WIDTH-1:0]             frame_tcp_flags;
    reg [`TIMESTAMP_WIDTH-1:0]             frame_timestamp;

    reg [31:0] src_ip, dest_ip;
    reg [15:0] src_port, dest_port;
    reg [7:0]  protocol;

    assign five_tuple = {src_ip, dest_ip, src_port, dest_port, protocol};

    // ----------------------------------------------------------
    // FSM
    // ----------------------------------------------------------
    reg new_packet;

    localparam IDLE_STATE         = 5'd0,
               PASS_PKT           = 5'd1,
               DONT_TRANSMIT      = 5'd2,
               TRANSMIT_STATE     = 5'd3,
               RCV_1              = 5'd4,
               RCV_NO_VLAN_0      = 5'd5,
               RCV_NO_VLAN_1      = 5'd6,
               RCV_NO_VLAN_2      = 5'd7,
               RCV_NO_VLAN_3      = 5'd8,
               RCV_VLAN1_0        = 5'd9,
               RCV_VLAN1_1        = 5'd10,
               RCV_VLAN1_2        = 5'd11,
               RCV_VLAN1_3        = 5'd12,
               RCV_VLAN1_4        = 5'd13,
               RCV_VLAN2_0        = 5'd14,
               RCV_VLAN2_1        = 5'd15,
               RCV_VLAN2_2        = 5'd16,
               RCV_VLAN2_3        = 5'd17,
               RCV_VLAN2_SKIP     = 5'd18; // FIX: Thêm state nhảy qua tags cho QinQ

    reg [4:0] fsm5;

    always @(posedge ACLK) begin
        if (!ARESETN) begin
            new_packet           <= 1'b1;
            S_AXIS_TREADY        <= 1'b1; 
            num_processed_pkts   <= 32'd0;
            tuple_and_info_valid <= 1'b0;
            fsm5                 <= IDLE_STATE;
        end else begin

            // ----------------------------------------------------------
            // Handshake & Backpressure Logic (Giải quyết tuple_valid bug)
            // ----------------------------------------------------------
            if (tuple_consumed) begin
                tuple_and_info_valid <= 1'b0;
                S_AXIS_TREADY        <= 1'b1; // DOWNSTREAM đã đọc, mở cống nhận data mới
            end else if (fsm5 == TRANSMIT_STATE && S_AXIS_TVALID && S_AXIS_TREADY && S_AXIS_TLAST) begin
                tuple_and_info_valid <= 1'b1; // Kích hoạt valid
                S_AXIS_TREADY        <= 1'b0; // Khóa cống, không nhận frame tiếp theo cho đến khi consumed
            end

            // Ghi nhận timestamp khi bắt đầu frame mới
            if (S_AXIS_TVALID && S_AXIS_TREADY && new_packet) begin
                new_packet      <= 1'b0;
                frame_timestamp <= timestamp_counter;
            end

            // ----------------------------------------------------------
            // Data Path FSM 
            // Tất cả state transitions đều được bảo vệ bởi S_AXIS_TREADY
            // ----------------------------------------------------------
            case (fsm5)
                IDLE_STATE: begin
                    if (S_AXIS_TVALID && S_AXIS_TREADY)
                        fsm5 <= RCV_1;
                end

                RCV_1: begin
                    if (S_AXIS_TVALID && S_AXIS_TREADY) begin
                        num_processed_pkts <= num_processed_pkts + 1; // Chỉ cộng 1 lần
                        
                        if      (S_AXIS_TDATA_rev[31:16] == 16'h0800 &&
                                 S_AXIS_TDATA_rev[15:12] == 4'h4)
                            fsm5 <= RCV_NO_VLAN_0;
                        else if (S_AXIS_TDATA_rev[31:16] == 16'h8100)
                            fsm5 <= RCV_VLAN1_0;
                        else if (S_AXIS_TDATA_rev[31:16] == 16'h88A8)
                            fsm5 <= RCV_VLAN2_SKIP; // FIX QINQ: Nhảy vào state Skip
                        else
                            fsm5 <= DONT_TRANSMIT;
                    end
                end

                // -------- Không có VLAN --------
                RCV_NO_VLAN_0: begin
                    if (S_AXIS_TVALID && S_AXIS_TREADY) begin
                        frame_ip_total_length <= S_AXIS_TDATA_rev[63:48];
                        protocol              <= S_AXIS_TDATA_rev[7:0];
                        
                        if (S_AXIS_TDATA_rev[7:0] == 8'h06 ||   // TCP
                            S_AXIS_TDATA_rev[7:0] == 8'h11)     // UDP
                            fsm5 <= RCV_NO_VLAN_1;
                        else
                            fsm5 <= DONT_TRANSMIT;
                    end
                end
                RCV_NO_VLAN_1: begin
                    if (S_AXIS_TVALID && S_AXIS_TREADY) begin
                        src_ip         <= S_AXIS_TDATA_rev[47:16];
                        dest_ip[31:16] <= S_AXIS_TDATA_rev[15:0];
                        fsm5 <= RCV_NO_VLAN_2;
                    end
                end
                RCV_NO_VLAN_2: begin
                    if (S_AXIS_TVALID && S_AXIS_TREADY) begin
                        dest_ip[15:0]  <= S_AXIS_TDATA_rev[63:48];
                        src_port       <= S_AXIS_TDATA_rev[47:32];
                        dest_port      <= S_AXIS_TDATA_rev[31:16];
                        fsm5 <= RCV_NO_VLAN_3;
                    end
                end
                RCV_NO_VLAN_3: begin
                    if (S_AXIS_TVALID && S_AXIS_TREADY) begin
                        frame_tcp_flags <= (protocol == `TCP) ? S_AXIS_TDATA_rev[7:0] : 8'd0;
                        fsm5 <= TRANSMIT_STATE;
                    end
                end

                // -------- 1 VLAN tag --------
                RCV_VLAN1_0: begin
                    if (S_AXIS_TVALID && S_AXIS_TREADY) begin
                        if (S_AXIS_TDATA_rev[63:48] == 16'h8100 &&
                            S_AXIS_TDATA_rev[31:16] == 16'h0800 &&
                            S_AXIS_TDATA_rev[15:12] == 4'h4) begin
                            fsm5 <= RCV_VLAN2_0; 
                            // Không gán frame_ip_total_length ở đây vì sẽ gán đúng tại RCV_VLAN2_0
                        end 
                        else if (S_AXIS_TDATA_rev[63:48] == 16'h0800 &&
                                 S_AXIS_TDATA_rev[47:44] == 4'h4) begin
                            frame_ip_total_length <= S_AXIS_TDATA_rev[31:16]; // Gán đúng chỗ
                            fsm5 <= RCV_VLAN1_1;
                        end 
                        else begin
                            fsm5 <= DONT_TRANSMIT;
                        end
                    end
                end
                RCV_VLAN1_1: begin
                    if (S_AXIS_TVALID && S_AXIS_TREADY) begin
                        protocol       <= S_AXIS_TDATA_rev[39:32];
                        src_ip[31:16]  <= S_AXIS_TDATA_rev[15:0];
                        fsm5 <= RCV_VLAN1_2;
                    end
                end
                RCV_VLAN1_2: begin
                    if (S_AXIS_TVALID && S_AXIS_TREADY) begin
                        src_ip[15:0]   <= S_AXIS_TDATA_rev[63:48];
                        dest_ip        <= S_AXIS_TDATA_rev[47:16];
                        src_port       <= S_AXIS_TDATA_rev[15:0];
                        fsm5 <= RCV_VLAN1_3;
                    end
                end
                RCV_VLAN1_3: begin
                    if (S_AXIS_TVALID && S_AXIS_TREADY) begin
                        dest_port      <= S_AXIS_TDATA_rev[63:48];
                        fsm5 <= RCV_VLAN1_4;
                    end
                end
                RCV_VLAN1_4: begin
                    if (S_AXIS_TVALID && S_AXIS_TREADY) begin
                        frame_tcp_flags <= (protocol == `TCP) ? S_AXIS_TDATA_rev[7:0] : 8'd0;
                        fsm5 <= TRANSMIT_STATE;
                    end
                end

                // -------- 2 VLAN tag (QinQ) --------
                RCV_VLAN2_SKIP: begin
                    if (S_AXIS_TVALID && S_AXIS_TREADY) begin
                        // Skip qua inner tag, đọc thẳng EtherType bên trong tại bytes 20-21
                        if (S_AXIS_TDATA_rev[31:16] == 16'h0800 &&
                            S_AXIS_TDATA_rev[15:12] == 4'h4)
                            fsm5 <= RCV_VLAN2_0; // IP header sẵn sàng ở word tiếp theo
                        else
                            fsm5 <= DONT_TRANSMIT;
                    end
                end
                RCV_VLAN2_0: begin
                    if (S_AXIS_TVALID && S_AXIS_TREADY) begin
                        frame_ip_total_length <= S_AXIS_TDATA_rev[63:48];
                        protocol              <= S_AXIS_TDATA_rev[7:0];
                        fsm5 <= RCV_VLAN2_1;
                    end
                end
                RCV_VLAN2_1: begin
                    if (S_AXIS_TVALID && S_AXIS_TREADY) begin
                        src_ip         <= S_AXIS_TDATA_rev[47:16];
                        dest_ip[31:16] <= S_AXIS_TDATA_rev[15:0];
                        fsm5 <= RCV_VLAN2_2;
                    end
                end
                RCV_VLAN2_2: begin
                    if (S_AXIS_TVALID && S_AXIS_TREADY) begin
                        dest_ip[15:0]  <= S_AXIS_TDATA_rev[63:48];
                        src_port       <= S_AXIS_TDATA_rev[47:32];
                        dest_port      <= S_AXIS_TDATA_rev[31:16];
                        fsm5 <= RCV_VLAN2_3;
                    end
                end
                RCV_VLAN2_3: begin
                    if (S_AXIS_TVALID && S_AXIS_TREADY) begin
                        frame_tcp_flags <= (protocol == `TCP) ? S_AXIS_TDATA_rev[7:0] : 8'd0;
                        fsm5 <= TRANSMIT_STATE;
                    end
                end

                // -------- Bỏ qua phần còn lại của frame --------
                DONT_TRANSMIT: begin
                    if (S_AXIS_TVALID && S_AXIS_TREADY && S_AXIS_TLAST) begin
                        fsm5       <= IDLE_STATE;
                        new_packet <= 1'b1;
                    end
                end

                // -------- Phát 5-tuple khi frame kết thúc --------
                TRANSMIT_STATE: begin
                    if (S_AXIS_TVALID && S_AXIS_TREADY) begin
                        pkt_info[15:0]  <= frame_ip_total_length;
                        pkt_info[47:16] <= frame_timestamp;
                        pkt_info[55:48] <= frame_tcp_flags;
                        
                        if (S_AXIS_TLAST) begin
                            new_packet <= 1'b1;
                            fsm5       <= IDLE_STATE;
                            // Việc bật tuple_and_info_valid và backpressure đã được xử lý ở cụm handshake phía trên
                        end
                    end
                end

                default: fsm5 <= DONT_TRANSMIT;
            endcase
        end
    end

endmodule