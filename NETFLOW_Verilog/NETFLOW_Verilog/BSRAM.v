// ============================================================
//  BSRAM.v  —  Dual-port synchronous BRAM (behavioural)
//
//  Chuyển từ: BSRAM.vhd
//
//  Mô tả:
//    BRAM hai cổng đọc/ghi đồng bộ, dùng làm bảng flow table.
//    - Port A : create_or_update_flows dùng để tra cứu + ghi entry mới/cập nhật.
//    - Port B : export_expired_flows_from_mem dùng để quét + xoá entry hết hạn.
//    Cả hai cổng chia sẻ cùng một mảng bộ nhớ (shared RAM).
//    Ghi trước, đọc sau trong cùng chu kỳ (write-first / read-after-write).
// ============================================================

module BSRAM #(
    parameter ADDR_BITS = 12,
    parameter DATA_BITS = 241
)(
    input  wire                  clk,
    // --- Port A ---
    input  wire                  ena,   // enable port A
    input  wire                  wea,   // write enable port A
    input  wire [ADDR_BITS-1:0]  addra,
    input  wire [DATA_BITS-1:0]  dia,   // data in A
    output reg  [DATA_BITS-1:0]  doa,   // data out A
    // --- Port B ---
    input  wire                  enb,   // enable port B
    input  wire                  web,   // write enable port B
    input  wire [ADDR_BITS-1:0]  addrb,
    input  wire [DATA_BITS-1:0]  dib,   // data in B
    output reg  [DATA_BITS-1:0]  dob    // data out B
);

    // Khai báo mảng RAM chia sẻ (2^ADDR_BITS entries)
    reg [DATA_BITS-1:0] RAM [0:(2**ADDR_BITS)-1];

    // Khởi tạo về 0 khi mô phỏng
    integer i;
    initial begin
        for (i = 0; i < (2**ADDR_BITS); i = i + 1)
            RAM[i] = {DATA_BITS{1'b0}};
    end

    // ---------- Port A ----------
    always @(posedge clk) begin
        if (ena) begin
            if (wea)
                RAM[addra] <= dia;
            doa <= RAM[addra];   // read-after-write (nếu wea=1 thì doa = dia)
        end
    end

    // ---------- Port B ----------
    always @(posedge clk) begin
        if (enb) begin
            if (web)
                RAM[addrb] <= dib;
            dob <= RAM[addrb];
        end
    end

endmodule