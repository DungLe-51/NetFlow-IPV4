// ============================================================
//  timestamp_counter_mod.v  —  Bộ tạo timestamp mili-giây
//
//  Chuyển từ: timestamp_counter_generator.vhd
//
//  Mô tả:
//    Chia tần số ACLK để tạo xung 1 kHz (mỗi 1 ms tăng counter lên 1).
//    - Chế độ phần cứng (SIM_ONLY=0): chia cho ACLK_FREQ/1000.
//    - Chế độ mô phỏng  (SIM_ONLY=1): chia thêm 10000 lần cho nhanh.
//    Giá trị timestamp được dùng để:
//      • Đánh dấu thời điểm đến của từng frame (pkt_classification).
//      • Kiểm tra inactive/active timeout (export_expired_flows_from_mem).
// ============================================================

`include "flow_cache_pack.vh"

module timestamp_counter_mod #(
    parameter SIM_ONLY  = 0,
    parameter ACLK_FREQ = 200_000_000   // Hz, mặc định 200 MHz
)(
    input  wire                       ACLK,
    input  wire                       ARESETN,          // active-low reset
    output wire [`TIMESTAMP_WIDTH-1:0] timestamp_counter_out
);

    // Giới hạn bộ chia: ACLK_FREQ/1000 chu kỳ = 1 ms
    localparam ONE_KHZ_MAX_COUNT = ACLK_FREQ / 1000;

    // Trong mô phỏng dùng giá trị nhỏ hơn để chạy nhanh
    wire [31:0] max_count = (SIM_ONLY == 0) ? ONE_KHZ_MAX_COUNT
                                            : ONE_KHZ_MAX_COUNT / 10000;

    reg [`TIMESTAMP_WIDTH-1:0] timestamp_counter;
    reg [`TIMESTAMP_WIDTH-1:0] divisor_for_ms;   // bộ chia tiền giảm tần

    assign timestamp_counter_out = divisor_for_ms;
    // Ghi chú: VHDL gốc xuất divisor_for_ms (đang tăng đều) chứ không phải
    // timestamp_counter (tăng theo ms). Giữ nguyên hành vi đó.

    always @(posedge ACLK or negedge ARESETN) begin
        if (!ARESETN) begin
            timestamp_counter <= {`TIMESTAMP_WIDTH{1'b0}};
            divisor_for_ms    <= {`TIMESTAMP_WIDTH{1'b0}};
        end else begin
            if (divisor_for_ms == max_count) begin
                divisor_for_ms    <= {`TIMESTAMP_WIDTH{1'b0}};
                timestamp_counter <= timestamp_counter + 1'b1;
            end else begin
                divisor_for_ms <= divisor_for_ms + 1'b1;
            end
        end
    end

endmodule