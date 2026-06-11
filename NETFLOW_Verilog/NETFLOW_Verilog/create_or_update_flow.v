// ============================================================
//  create_or_update_flows.v  —  Tra cứu & ghi flow vào BRAM
//
//  Chuyển từ: create_or_update_flows.vhd
//
//  Mô tả:
//    FSM điều khiển Port A của BRAM để:
//      1. Tra cứu entry tại địa chỉ hash (hash_function tính sẵn).
//      2. Nếu slot trống → tạo flow mới.
//      3. Nếu 5-tuple khớp → cập nhật byte/packet counter + tcp_flags.
//      4. Nếu 5-tuple không khớp (hash collision) → tăng collision_counter.
//    Khi TCP FIN/RST → báo export_now để xuất ngay (export accelerator).
//
//  Cấu trúc entry BRAM (241 bit, từ MSB):
//    [240]     busy flag
//    [239:136] 5-tuple
//    [135:128] tcp_flags (OR tích luỹ)
//    [127:96]  initial_timestamp
//    [95:64]   last_timestamp
//    [63:32]   frame_counter
//    [31:0]    byte_counter
// ============================================================

`include "flow_cache_pack.vh"

module create_or_update_flows (
    input  wire        ACLK,
    input  wire        ARESETN,
    // 5-tuple + info từ pkt_classification
    input  wire [`FIVE_TUPLE_WIDTH-1:0] frame_five_tuple,
    input  wire [`PKT_INFO_WIDTH-1:0]   pkt_info,
    input  wire        tuple_and_info_valid,
    // Port A của BRAM
    output reg         ena,
    output reg         wea,
    output wire [`MEM_ADDR_WIDTH-1:0]  hash_code_out,
    input  wire [`MEM_DATA_WIDTH-1:0]  doa,
    output reg  [`MEM_DATA_WIDTH-1:0]  dia,
    // Export accelerator (khi TCP FIN/RST)
    output reg         export_now,
    output reg  [`MEM_ADDR_WIDTH-1:0]  export_this,
    input  wire        flow_exported_ok,
    // Bộ đếm collision
    output reg  [31:0] collision_counter
);

    // ----------------------------------------------------------
    // Hàm băm (tổ hợp, zero-latency)
    // ----------------------------------------------------------
    wire [`FIVE_TUPLE_WIDTH-1:0] frame_five_tuple_reg_w;
    reg  [`FIVE_TUPLE_WIDTH-1:0] frame_five_tuple_reg;
    wire [`MEM_ADDR_WIDTH-1:0]   hash_code;

    hash_function #(
        .INPUT_WIDTH (`FIVE_TUPLE_WIDTH),
        .OUTPUT_WIDTH(`MEM_ADDR_WIDTH)
    ) hash_function_inst (
        .hash_input (frame_five_tuple_reg),
        .hash_output(hash_code)
    );

    assign hash_code_out = hash_code;

    // ----------------------------------------------------------
    // Giải nén pkt_info
    // ----------------------------------------------------------
    wire [`IP_TOTAL_LENGTH_FIELD_WIDTH-1:0] frame_ip_total_length;
    wire [`TIMESTAMP_WIDTH-1:0]             frame_timestamp;
    wire [`TCP_FLAGS_WIDTH-1:0]             frame_tcp_flags;

    assign frame_ip_total_length = pkt_info[15:0];
    assign frame_timestamp       = pkt_info[47:16];
    assign frame_tcp_flags       = pkt_info[55:48];

    // ----------------------------------------------------------
    // FSM
    // ----------------------------------------------------------
    localparam IDLE              = 3'd0,
               REGISTER_STATE   = 3'd1,
               READ_STATE       = 3'd2,
               FLOW_LOOKUP      = 3'd3,
               CREATE_FLOW      = 3'd4,
               UPDATE_FLOW      = 3'd5,
               COLLISION        = 3'd6;

    reg [2:0] fsm;

    // Thanh ghi nội bộ
    reg [`MEM_DATA_WIDTH-1:0] reg_doa;
    reg [31:0] flow_pkt_counter;
    reg [31:0] flow_byte_counter;
    reg [7:0]  flow_tcp_flags;
    reg [31:0] flow_initial_timestamp;
    reg [31:0] flow_last_timestamp;

    // Thông tin protocol & FIN/RST (được tính ở FLOW_LOOKUP và dùng tiếp)
    reg [7:0]  protocol_reg;
    reg        fin_rst_flag;

    always @(posedge ACLK) begin
        if (!ARESETN) begin
            fsm              <= IDLE;
            collision_counter<= 32'd0;
            export_now       <= 1'b0;
            ena              <= 1'b0;
            wea              <= 1'b0;
        end else begin
            ena <= 1'b0;
            wea <= 1'b0;

            case (fsm)
                // ---- Chờ 5-tuple hợp lệ ----
                IDLE: begin
                    frame_five_tuple_reg     <= frame_five_tuple;
                    if (tuple_and_info_valid) begin
                        ena <= 1'b1;    // kích đọc BRAM tại địa chỉ hash
                        fsm <= READ_STATE;
                    end
                end

                // ---- Chờ 1 chu kỳ cho BRAM pipeline ----
                READ_STATE: begin
                    fsm <= REGISTER_STATE;
                end

                // ---- Đăng ký dữ liệu đọc từ BRAM ----
                REGISTER_STATE: begin
                    reg_doa <= doa;
                    fsm     <= FLOW_LOOKUP;
                end

                // ---- So sánh entry trong BRAM với 5-tuple hiện tại ----
                FLOW_LOOKUP: begin
                    // Tính sẵn counter mới
                    flow_byte_counter       <= reg_doa[31:0]   + {16'd0, frame_ip_total_length};
                    flow_pkt_counter        <= reg_doa[63:32]  + 32'd1;
                    flow_initial_timestamp  <= reg_doa[127:96];
                    flow_tcp_flags          <= reg_doa[135:128] | frame_tcp_flags;

                    // Lưu protocol & FIN/RST flags để dùng ở UPDATE/CREATE
                    protocol_reg <= frame_five_tuple_reg[7:0];
                    fin_rst_flag <= frame_tcp_flags[0] | frame_tcp_flags[2]; // FIN=bit0, RST=bit2

                    if (reg_doa[`MEM_ENTRY_STATUS_INDEX]) begin
                        // Slot đang có flow
                        if (reg_doa[239:136] != frame_five_tuple_reg)
                            fsm <= COLLISION;      // Collision: 5-tuple không khớp
                        else
                            fsm <= UPDATE_FLOW;    // 5-tuple khớp → cập nhật
                    end else begin
                        fsm <= CREATE_FLOW;        // Slot trống → tạo mới
                    end
                end

                // ---- Cập nhật flow đã tồn tại ----
                UPDATE_FLOW: begin
                    ena <= 1'b1;
                    wea <= 1'b1;
                    // Cấu trúc: busy|5-tuple|tcp_flags|initial_ts|last_ts|pkt_cnt|byte_cnt
                    dia <= {1'b1,
                            frame_five_tuple_reg,
                            flow_tcp_flags,
                            flow_initial_timestamp,
                            frame_timestamp,
                            flow_pkt_counter,
                            flow_byte_counter};
                    if (protocol_reg == `TCP && fin_rst_flag) begin
                        export_now  <= 1'b1;
                        export_this <= hash_code;
                    end
                    fsm <= IDLE;
                end

                // ---- Tạo flow mới ----
                CREATE_FLOW: begin
                    ena <= 1'b1;
                    wea <= 1'b1;
                    dia <= {1'b1,
                            frame_five_tuple_reg,
                            frame_tcp_flags,
                            frame_timestamp,            // initial_timestamp
                            frame_timestamp,            // last_timestamp = initial (flow mới)
                            32'd1,                      // frame_counter = 1
                            {16'd0, frame_ip_total_length}};
                    if (protocol_reg == `TCP && fin_rst_flag) begin
                        export_now  <= 1'b1;
                        export_this <= hash_code;
                    end
                    fsm <= IDLE;
                end

                // ---- Collision: bỏ qua gói, tăng counter ----
                COLLISION: begin
                    collision_counter <= collision_counter + 32'd1;
                    fsm <= IDLE;
                end

                default: fsm <= IDLE;
            endcase

            // Xoá export_now khi được xác nhận
            if (flow_exported_ok)
                export_now <= 1'b0;
        end
    end

endmodule