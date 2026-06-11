// ============================================================
//  export_expired_flows_from_mem.v  —  Quét & xuất flow hết hạn
//
//  Chuyển từ: export_expired_flows_from_mem.vhd
//
//  Mô tả:
//    Dùng Port B của BRAM để quét tuần tự toàn bộ bảng flow.
//    Một flow được xuất (expired) khi thoả 1 trong 3 điều kiện:
//      1. TCP FIN/RST flag được đặt trong entry (phát hiện muộn).
//      2. Active timeout: thời gian sống từ khi tạo > ACTIVE_TIMEOUT.
//      3. Inactive timeout: không có gói mới trong > INACTIVE_TIMEOUT.
//    Ngoài ra còn có đường export accelerator:
//      - Khi create_or_update_flows phát hiện TCP FIN/RST ngay lập tức,
//        nó set export_now='1' + export_this=địa chỉ,
//        module này nhảy thẳng đến địa chỉ đó và xuất ngay.
//    Sau khi xuất: ghi dib=0 (xoá entry) + set flow_exported_ok.
// ============================================================

`include "flow_cache_pack.vh"

module export_expired_flows_from_mem (
    input  wire        ACLK,
    input  wire        ARESETN,
    // Timeout (ms)
    input  wire [`TIMESTAMP_WIDTH-1:0] ACTIVE_TIMEOUT,
    input  wire [`TIMESTAMP_WIDTH-1:0] InACTIVE_TIMEOUT,
    // Port B của BRAM
    output reg         enb,
    output reg         web,
    output reg  [`MEM_ADDR_WIDTH-1:0]  addrb,
    input  wire [`MEM_DATA_WIDTH-1:0]  dob,
    output wire [`MEM_DATA_WIDTH-1:0]  dib,    // luôn = 0 (xoá entry)
    // Export accelerator
    input  wire        export_now,
    input  wire [`MEM_ADDR_WIDTH-1:0]  export_this,
    input  wire [`TIMESTAMP_WIDTH-1:0] timestamp_counter,
    output reg         flow_exported_ok,
    // FIFO ghi flow hết hạn
    output reg         fifo_exp_rst,
    output reg         fifo_w_exp_en,
    output reg  [`FIFO_DATA_WIDTH-1:0] fifo_in_exp,
    input  wire        fifo_full_exp
);

    // dib luôn bằng 0: xoá entry khi xuất
    assign dib = {`MEM_DATA_WIDTH{1'b0}};

    // ----------------------------------------------------------
    // FSM
    // ----------------------------------------------------------
    localparam S0              = 3'd0,
               READ_STATE      = 3'd1,
               REGISTER_STATE  = 3'd2,
               WR_ON_FIFO      = 3'd3,
               CHK_CONDITION   = 3'd4;

    reg [2:0] fsm;
    reg [`MEM_ADDR_WIDTH-1:0] linear_counter;
    reg [`MEM_DATA_WIDTH-1:0] reg_dob;
    reg export_immediately;   // cờ: đang xử lý export accelerator

    always @(posedge ACLK) begin
        if (!ARESETN) begin
            addrb            <= {`MEM_ADDR_WIDTH{1'b0}};
            linear_counter   <= {`MEM_ADDR_WIDTH{1'b0}};
            fifo_exp_rst     <= 1'b1;   // reset FIFO khi khởi động
            export_immediately <= 1'b0;
            fsm              <= S0;
            enb              <= 1'b0;
            web              <= 1'b0;
            flow_exported_ok <= 1'b0;
            fifo_w_exp_en    <= 1'b0;
        end else begin
            // Mặc định xoá các tín hiệu pulse
            enb              <= 1'b0;
            web              <= 1'b0;
            flow_exported_ok <= 1'b0;
            fifo_exp_rst     <= 1'b0;
            fifo_w_exp_en    <= 1'b0;

            case (fsm)
                // ---- Quyết định địa chỉ đọc ----
                S0: begin
                    enb <= 1'b1;
                    if (export_now) begin
                        // Export accelerator: nhảy đến địa chỉ yêu cầu
                        flow_exported_ok   <= 1'b1;
                        addrb              <= export_this;
                        export_immediately <= 1'b1;
                    end else begin
                        // Quét tuần tự
                        addrb              <= linear_counter;
                        export_immediately <= 1'b0;
                    end
                    fsm <= READ_STATE;
                end

                // ---- Chờ pipeline BRAM ----
                READ_STATE: begin
                    fsm <= REGISTER_STATE;
                end

                // ---- Đăng ký dữ liệu đọc ----
                REGISTER_STATE: begin
                    reg_dob <= dob;
                    fsm     <= export_immediately ? WR_ON_FIFO : CHK_CONDITION;
                end

                // ---- Ghi flow vào FIFO (xuất ra ngoài) ----
                WR_ON_FIFO: begin
                    // 240 bit = MEM_DATA_WIDTH-1 downto 0 (không kể busy flag)
                    fifo_in_exp <= reg_dob[`MEM_DATA_WIDTH-2:0];
                    if (!fifo_full_exp) begin
                        fifo_w_exp_en <= 1'b1;
                        enb           <= 1'b1;
                        web           <= 1'b1;   // xoá entry (dib=0)
                        fsm           <= S0;
                    end
                    // Nếu FIFO đầy thì chờ ở đây
                end

                // ---- Kiểm tra điều kiện timeout ----
                CHK_CONDITION: begin
                    // Phân tích entry
                    // reg_dob[143:136] = protocol (trong 5-tuple byte thấp nhất)
                    // tcp_flags tích luỹ tại [135:128]:
                    //   bit 128 = FIN (flags[0]), bit 130 = RST (flags[2])
                    // initial_timestamp tại [127:96]
                    // last_timestamp    tại [95:64]
                    if (reg_dob[`MEM_ENTRY_STATUS_INDEX]) begin
                        // Entry đang có flow
                        if ((reg_dob[143:136] == `TCP) &&
                            (reg_dob[128] | reg_dob[130])) begin
                            // TCP FIN/RST — export accelerator đã bỏ lỡ
                            fsm <= WR_ON_FIFO;
                        end else if ((timestamp_counter - reg_dob[127:96]) >= ACTIVE_TIMEOUT) begin
                            // Sống quá lâu → active timeout
                            fsm <= WR_ON_FIFO;
                        end else if ((timestamp_counter - reg_dob[95:64]) >= InACTIVE_TIMEOUT) begin
                            // Không có gói mới quá lâu → inactive timeout
                            fsm <= WR_ON_FIFO;
                        end else begin
                            // Còn hạn → chuyển sang entry kế tiếp
                            linear_counter <= linear_counter + 1'b1;
                            fsm <= S0;
                        end
                    end else begin
                        // Slot trống → bỏ qua
                        linear_counter <= linear_counter + 1'b1;
                        fsm <= S0;
                    end
                end

                default: fsm <= S0;
            endcase
        end
    end

endmodule