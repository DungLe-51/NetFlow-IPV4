// ============================================================
//  flow_cache_top.v  —  Top-level: kết nối toàn bộ các module
//
//  Chuyển từ: flow_cache_top.vhd (entity netflow_cache)
//
//  Mô tả:
//    Instantiate và nối dây tất cả các sub-module:
//      - pkt_classification      : trích xuất 5-tuple
//      - timestamp_counter_mod   : đếm thời gian ms
//      - BSRAM                   : bảng flow (dual-port)
//      - create_or_update_flows  : tra cứu/ghi flow (Port A)
//      - export_expired_flows    : quét timeout + xuất (Port B)
//      - FIFO export (4 đoạn 72-bit ghép thành 240-bit)
//      - exp_via_10g_interface   : xuất thẳng ra 10G (khi NETFLOW_EXPORT_PRESENT=0)
//      - exp_to_netflow_exp      : xuất sang pcore NetFlow (khi =1)
//
//  Lưu ý về FIFO:
//    VHDL gốc dùng Xilinx primitive FIFO_SYNC_MACRO (Virtex-5).
//    Ở đây thay bằng BRAM-based FIFO behavioural để tổng hợp được
//    trên mọi toolchain. Thay bằng primitive FPGA phù hợp khi cần.
// ============================================================

`include "flow_cache_pack.vh"

module netflow_cache #(
    parameter SIM_ONLY               = 0,
    parameter ACLK_FREQ              = 200_000_000,
    parameter C_S_AXIS_10GMAC_DATA_WIDTH        = 64,
    parameter C_M_AXIS_EXP_RECORDS_DATA_WIDTH   = 64,
    parameter C_ACTIVE_TIMEOUT_INIT             = 1500,  // giây
    parameter C_InACTIVE_TIMEOUT_INIT           = 1,     // giây
    parameter NETFLOW_EXPORT_PRESENT            = 0
)(
    input  wire        ACLK,
    input  wire        ARESETN,
    // AXI4-Stream slave (nhận frame Ethernet)
    output wire        S_AXIS_TREADY,
    input  wire [C_S_AXIS_10GMAC_DATA_WIDTH-1:0]   S_AXIS_TDATA,
    input  wire [C_S_AXIS_10GMAC_DATA_WIDTH/8-1:0]  S_AXIS_TSTRB,
    input  wire        S_AXIS_TLAST,
    input  wire        S_AXIS_TVALID,
    // AXI4-Stream master (gửi flow hết hạn)
    output wire [63:0] M_AXIS_EXP_RECORDS_TDATA,
    output wire [7:0]  M_AXIS_EXP_RECORDS_TSTRB,
    output wire        M_AXIS_EXP_RECORDS_TVALID,
    output wire        M_AXIS_EXP_RECORDS_TLAST,
    input  wire        M_AXIS_EXP_RECORDS_TREADY
);

    // ----------------------------------------------------------
    // Tính timeout (ms) lúc elaboration
    //   Hardware: giây × 1000
    //   Simulation: giá trị nhỏ hơn (ms)
    // ----------------------------------------------------------
    localparam ACTIVE_TIMEOUT_HW   = C_ACTIVE_TIMEOUT_INIT   * 1000;  // ms
    localparam InACTIVE_TIMEOUT_HW = C_InACTIVE_TIMEOUT_INIT * 100;   // ms (×100 giống VHDL)
    localparam ACTIVE_TIMEOUT_SIM  = 2;
    localparam InACTIVE_TIMEOUT_SIM= 1;

    wire [`TIMESTAMP_WIDTH-1:0] ACTIVE_TIMEOUT;
    wire [`TIMESTAMP_WIDTH-1:0] InACTIVE_TIMEOUT;

    assign ACTIVE_TIMEOUT   = (SIM_ONLY == 0) ? ACTIVE_TIMEOUT_HW[`TIMESTAMP_WIDTH-1:0]
                                              : ACTIVE_TIMEOUT_SIM;
    assign InACTIVE_TIMEOUT = (SIM_ONLY == 0) ? InACTIVE_TIMEOUT_HW[`TIMESTAMP_WIDTH-1:0]
                                              : InACTIVE_TIMEOUT_SIM;

    // ----------------------------------------------------------
    // Internal signals
    // ----------------------------------------------------------
    wire [`FIVE_TUPLE_WIDTH-1:0]  frame_five_tuple;
    wire [`PKT_INFO_WIDTH-1:0]    pkt_info;
    wire [31:0]                   num_processed_pkts;
    wire                          tuple_and_info_valid;
    wire [`TIMESTAMP_WIDTH-1:0]   timestamp_counter;

    // BRAM Port A
    wire                          ena, wea;
    wire [`MEM_ADDR_WIDTH-1:0]    addra;
    wire [`MEM_DATA_WIDTH-1:0]    dia, doa;
    // BRAM Port B
    wire                          enb, web;
    wire [`MEM_ADDR_WIDTH-1:0]    addrb;
    wire [`MEM_DATA_WIDTH-1:0]    dib, dob;

    // Export accelerator
    wire        export_now;
    wire [`MEM_ADDR_WIDTH-1:0] export_this;
    wire        flow_exported_ok;
    wire [31:0] collision_counter;

    // FIFO export (240-bit logically, 4×72-bit physically)
    wire [`FIFO_DATA_WIDTH-1:0] fifo_in_exp;
    wire [`FIFO_DATA_WIDTH-1:0] fifo_out_exp;
    wire        fifo_w_exp_en;
    wire        fifo_rd_exp_en;
    wire        fifo_exp_rst;
    wire        fifo_full_exp;
    wire        fifo_empty_exp;

    // ----------------------------------------------------------
    // pkt_classification
    // ----------------------------------------------------------
    pkt_classification #(
        .C_S_AXIS_10GMAC_DATA_WIDTH(C_S_AXIS_10GMAC_DATA_WIDTH)
    ) classification (
        .ACLK               (ACLK),
        .ARESETN            (ARESETN),
        .S_AXIS_TREADY      (S_AXIS_TREADY),
        .S_AXIS_TDATA       (S_AXIS_TDATA),
        .S_AXIS_TSTRB       (S_AXIS_TSTRB),
        .S_AXIS_TLAST       (S_AXIS_TLAST),
        .S_AXIS_TVALID      (S_AXIS_TVALID),
        .timestamp_counter  (timestamp_counter),
        .num_processed_pkts (num_processed_pkts),
        .five_tuple         (frame_five_tuple),
        .pkt_info           (pkt_info),
        .tuple_and_info_valid(tuple_and_info_valid)
    );

    // ----------------------------------------------------------
    // timestamp_counter_mod
    // ----------------------------------------------------------
    timestamp_counter_mod #(
        .SIM_ONLY (SIM_ONLY),
        .ACLK_FREQ(ACLK_FREQ)
    ) timestamp (
        .ACLK                (ACLK),
        .ARESETN             (ARESETN),
        .timestamp_counter_out(timestamp_counter)
    );

    // ----------------------------------------------------------
    // BSRAM — bảng flow dual-port
    // ----------------------------------------------------------
    BSRAM #(
        .ADDR_BITS(`MEM_ADDR_WIDTH),
        .DATA_BITS(`MEM_DATA_WIDTH)
    ) flow_table (
        .clk  (ACLK),
        .ena  (ena),  .wea (wea),  .addra(addra), .dia(dia), .doa(doa),
        .enb  (enb),  .web (web),  .addrb(addrb), .dib(dib), .dob(dob)
    );

    // ----------------------------------------------------------
    // create_or_update_flows
    // ----------------------------------------------------------
    create_or_update_flows create_or_update (
        .ACLK               (ACLK),
        .ARESETN            (ARESETN),
        .frame_five_tuple   (frame_five_tuple),
        .pkt_info           (pkt_info),
        .tuple_and_info_valid(tuple_and_info_valid),
        .ena                (ena),
        .wea                (wea),
        .hash_code_out      (addra),
        .doa                (doa),
        .dia                (dia),
        .export_now         (export_now),
        .export_this        (export_this),
        .flow_exported_ok   (flow_exported_ok),
        .collision_counter  (collision_counter)
    );

    // ----------------------------------------------------------
    // export_expired_flows_from_mem
    // ----------------------------------------------------------
    export_expired_flows_from_mem export_expired (
        .ACLK               (ACLK),
        .ARESETN            (ARESETN),
        .ACTIVE_TIMEOUT     (ACTIVE_TIMEOUT),
        .InACTIVE_TIMEOUT   (InACTIVE_TIMEOUT),
        .enb                (enb),
        .web                (web),
        .addrb              (addrb),
        .dob                (dob),
        .dib                (dib),
        .export_now         (export_now),
        .export_this        (export_this),
        .timestamp_counter  (timestamp_counter),
        .flow_exported_ok   (flow_exported_ok),
        .fifo_exp_rst       (fifo_exp_rst),
        .fifo_w_exp_en      (fifo_w_exp_en),
        .fifo_in_exp        (fifo_in_exp),
        .fifo_full_exp      (fifo_full_exp)
    );

    // ----------------------------------------------------------
    // FIFO export — behavioural (thay thế 4× FIFO_SYNC_MACRO)
    // Depth 512 entries × 240 bit.
    // Thay bằng FIFO primitive phù hợp khi targeting FPGA cụ thể.
    // ----------------------------------------------------------
    simple_sync_fifo #(
        .DATA_WIDTH(`FIFO_DATA_WIDTH),
        .DEPTH     (512)
    ) export_fifo (
        .clk   (ACLK),
        .rst   (fifo_exp_rst | ~ARESETN),
        .wr_en (fifo_w_exp_en),
        .din   (fifo_in_exp),
        .full  (fifo_full_exp),
        .rd_en (fifo_rd_exp_en),
        .dout  (fifo_out_exp),
        .empty (fifo_empty_exp)
    );

    // ----------------------------------------------------------
    // Xuất: chọn module theo tham số NETFLOW_EXPORT_PRESENT
    // ----------------------------------------------------------
    generate
        if (NETFLOW_EXPORT_PRESENT == 0) begin : no_netflow_exp
            exp_via_10g_interface #(
                .C_M_AXIS_EXP_RECORDS_DATA_WIDTH(C_M_AXIS_EXP_RECORDS_DATA_WIDTH)
            ) exp_via_10g (
                .ACLK                  (ACLK),
                .ARESETN               (ARESETN),
                .M_AXIS_10GMAC_tdata   (M_AXIS_EXP_RECORDS_TDATA),
                .M_AXIS_10GMAC_tstrb   (M_AXIS_EXP_RECORDS_TSTRB),
                .M_AXIS_10GMAC_tvalid  (M_AXIS_EXP_RECORDS_TVALID),
                .M_AXIS_10GMAC_tready  (M_AXIS_EXP_RECORDS_TREADY),
                .M_AXIS_10GMAC_tlast   (M_AXIS_EXP_RECORDS_TLAST),
                .counters              (num_processed_pkts),
                .collision_counter     (collision_counter),
                .fifo_rd_exp_en        (fifo_rd_exp_en),
                .fifo_out_exp          (fifo_out_exp),
                .fifo_empty_exp        (fifo_empty_exp)
            );
        end else begin : netflow_exp
            exp_to_netflow_exp #(
                .C_M_AXIS_EXP_RECORDS_DATA_WIDTH(C_M_AXIS_EXP_RECORDS_DATA_WIDTH)
            ) exp_to_nf (
                .ACLK                  (ACLK),
                .ARESETN               (ARESETN),
                .M_AXIS_10GMAC_tdata   (M_AXIS_EXP_RECORDS_TDATA),
                .M_AXIS_10GMAC_tstrb   (M_AXIS_EXP_RECORDS_TSTRB),
                .M_AXIS_10GMAC_tvalid  (M_AXIS_EXP_RECORDS_TVALID),
                .M_AXIS_10GMAC_tready  (M_AXIS_EXP_RECORDS_TREADY),
                .M_AXIS_10GMAC_tlast   (M_AXIS_EXP_RECORDS_TLAST),
                .fifo_rd_exp_en        (fifo_rd_exp_en),
                .fifo_out_exp          (fifo_out_exp),
                .fifo_empty_exp        (fifo_empty_exp)
            );
        end
    endgenerate

endmodule


// ============================================================
//  simple_sync_fifo — FIFO đồng bộ behavioural
//  Thay thế FIFO_SYNC_MACRO của Xilinx Virtex-5.
//  Dùng bộ nhớ reg thông thường, hoạt động đúng trong mô phỏng.
//  Khi triển khai trên FPGA thực: thay bằng native FIFO IP.
// ============================================================
module simple_sync_fifo #(
    parameter DATA_WIDTH = 240,
    parameter DEPTH      = 512
)(
    input  wire                  clk,
    input  wire                  rst,
    input  wire                  wr_en,
    input  wire [DATA_WIDTH-1:0] din,
    output reg                   full,
    input  wire                  rd_en,
    output reg  [DATA_WIDTH-1:0] dout,
    output reg                   empty
);
    reg [DATA_WIDTH-1:0] mem [0:DEPTH-1];
    reg [$clog2(DEPTH):0] wr_ptr, rd_ptr, count;

    always @(posedge clk) begin
        if (rst) begin
            wr_ptr <= 0; rd_ptr <= 0; count <= 0;
            full <= 0; empty <= 1;
        end else begin
            if (wr_en && !full) begin
                mem[wr_ptr[$clog2(DEPTH)-1:0]] <= din;
                wr_ptr <= wr_ptr + 1;
            end
            if (rd_en && !empty) begin
                dout   <= mem[rd_ptr[$clog2(DEPTH)-1:0]];
                rd_ptr <= rd_ptr + 1;
            end
            // Cập nhật count
            case ({wr_en & ~full, rd_en & ~empty})
                2'b10: count <= count + 1;
                2'b01: count <= count - 1;
                default: ;
            endcase
            full  <= (count == DEPTH);
            empty <= (count == 0);
        end
    end
endmodule