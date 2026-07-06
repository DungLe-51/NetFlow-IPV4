// ============================================================
//  flow_cache_top.v  -  Top-level: kết nối toàn bộ các module
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

module flow_cache_top #(
    parameter SIM_ONLY                          = 0,
    parameter ACLK_FREQ                         = 200_000_000,
    parameter C_S_AXIS_10GMAC_DATA_WIDTH        = 64,
    parameter C_M_AXIS_EXP_RECORDS_DATA_WIDTH   = 64,
    parameter C_ACTIVE_TIMEOUT_INIT             = 1500,  // giây
    parameter C_InACTIVE_TIMEOUT_INIT           = 1,     // giây
    parameter NETFLOW_EXPORT_PRESENT            = 0,
    // 0 = MicroBlaze reads export FIFO through AXI4-Lite.
    // 1 = M_AXIS_EXP_RECORDS consumes export FIFO.
    parameter C_ENABLE_AXIS_EXPORT          = 0,
    
    // --- CÁC THAM SỐ CHO BUS AXI4-LITE (XPS Yêu cầu) ---
    parameter C_S_AXI_DATA_WIDTH                = 32,
    parameter C_S_AXI_ADDR_WIDTH                = 32,
    parameter C_BASEADDR                        = 32'hFFFFFFFF,
    parameter C_HIGHADDR                        = 32'h00000000
)(
    input  wire        ACLK,
    input  wire        ARESETN,
    
    // =========================================================
    // CÁC CHÂN GIAO TIẾP AXI4-LITE (Nối với MicroBlaze)
    // =========================================================
    input  wire [C_S_AXI_ADDR_WIDTH-1:0]     S_AXI_AWADDR,
    input  wire                              S_AXI_AWVALID,
    input  wire [C_S_AXI_DATA_WIDTH-1:0]     S_AXI_WDATA,
    input  wire [(C_S_AXI_DATA_WIDTH/8)-1:0] S_AXI_WSTRB,
    input  wire                              S_AXI_WVALID,
    input  wire                              S_AXI_BREADY,
    input  wire [C_S_AXI_ADDR_WIDTH-1:0]     S_AXI_ARADDR,
    input  wire                              S_AXI_ARVALID,
    input  wire                              S_AXI_RREADY,
    output wire                              S_AXI_ARREADY,
    output wire [C_S_AXI_DATA_WIDTH-1:0]     S_AXI_RDATA,
    output wire [1:0]                        S_AXI_RRESP,
    output wire                              S_AXI_RVALID,
    output wire                              S_AXI_WREADY,
    output wire [1:0]                        S_AXI_BRESP,
    output wire                              S_AXI_BVALID,
    output wire                              S_AXI_AWREADY,

    // --- AXI4-Stream slave (nhận frame Ethernet) ---
    output wire        S_AXIS_TREADY,
    input  wire [C_S_AXIS_10GMAC_DATA_WIDTH-1:0]   S_AXIS_TDATA,
    input  wire [C_S_AXIS_10GMAC_DATA_WIDTH/8-1:0] S_AXIS_TSTRB,
    input  wire        S_AXIS_TLAST,
    input  wire        S_AXIS_TVALID,
    
    // --- AXI4-Stream master (gửi flow hết hạn) ---
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
    localparam InACTIVE_TIMEOUT_HW = C_InACTIVE_TIMEOUT_INIT * 1000;  // ms
    localparam ACTIVE_TIMEOUT_SIM  = 2;
    localparam InACTIVE_TIMEOUT_SIM= 1;

    wire [`TIMESTAMP_WIDTH-1:0] ACTIVE_TIMEOUT;
    wire [`TIMESTAMP_WIDTH-1:0] InACTIVE_TIMEOUT;

    localparam integer ACTIVE_TIMEOUT_DEFAULT_INT =
        (SIM_ONLY == 0) ? ACTIVE_TIMEOUT_HW : ACTIVE_TIMEOUT_SIM;
    localparam integer INACTIVE_TIMEOUT_DEFAULT_INT =
        (SIM_ONLY == 0) ? InACTIVE_TIMEOUT_HW : InACTIVE_TIMEOUT_SIM;

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
    wire        fifo_rd_exp_en_cpu;
    wire        fifo_rd_exp_en_axis;
    wire        fifo_exp_rst;
    wire        fifo_full_exp;
    wire        fifo_empty_exp;

    assign fifo_rd_exp_en = fifo_rd_exp_en_cpu |
                             ((C_ENABLE_AXIS_EXPORT != 0) ? fifo_rd_exp_en_axis : 1'b0);

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
    /*timestamp_counter_mod #(
        .SIM_ONLY (SIM_ONLY),
        .ACLK_FREQ(ACLK_FREQ)
    ) timestamp (
        .ACLK                (ACLK),
        .ARESETN             (ARESETN),
        .timestamp_counter_out(timestamp_counter)
    );*/

    // ----------------------------------------------------------
    // AXI4-Lite slave (MicroBlaze control/status)
    // ----------------------------------------------------------
    axi4_lite_slave #(
        .C_S_AXI_ADDR_WIDTH        (C_S_AXI_ADDR_WIDTH),
        .C_S_AXI_DATA_WIDTH        (C_S_AXI_DATA_WIDTH),
        .C_ACTIVE_TIMEOUT_DEFAULT  (ACTIVE_TIMEOUT_DEFAULT_INT),
        .C_INACTIVE_TIMEOUT_DEFAULT(INACTIVE_TIMEOUT_DEFAULT_INT)
    ) axi4_lite_slave_inst (
        .ACLK                 (ACLK),
        .ARESETN              (ARESETN),

        .S_AXI_AWADDR         (S_AXI_AWADDR),
        .S_AXI_AWVALID        (S_AXI_AWVALID),
        .S_AXI_AWREADY        (S_AXI_AWREADY),
        .S_AXI_WDATA          (S_AXI_WDATA),
        .S_AXI_WSTRB          (S_AXI_WSTRB),
        .S_AXI_WVALID         (S_AXI_WVALID),
        .S_AXI_WREADY         (S_AXI_WREADY),
        .S_AXI_BRESP          (S_AXI_BRESP),
        .S_AXI_BVALID         (S_AXI_BVALID),
        .S_AXI_BREADY         (S_AXI_BREADY),

        .S_AXI_ARADDR         (S_AXI_ARADDR),
        .S_AXI_ARVALID        (S_AXI_ARVALID),
        .S_AXI_ARREADY        (S_AXI_ARREADY),
        .S_AXI_RDATA          (S_AXI_RDATA),
        .S_AXI_RRESP          (S_AXI_RRESP),
        .S_AXI_RVALID         (S_AXI_RVALID),
        .S_AXI_RREADY         (S_AXI_RREADY),
        .S_AXI_ARPROT         (3'b000),
        .S_AXI_AWPROT         (3'b000),

        .timestamp_counter    (timestamp_counter),
        .active_timeout_out   (ACTIVE_TIMEOUT),
        .inactive_timeout_out (InACTIVE_TIMEOUT),
        .fifo_empty_exp       (fifo_empty_exp),
        .fifo_out_exp         (fifo_out_exp),
        .fifo_rd_exp_en       (fifo_rd_exp_en_cpu)
    );

    // ----------------------------------------------------------
    // BSRAM - bảng flow dual-port
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
    // FIFO export - behavioural (thay thế 4× FIFO_SYNC_MACRO)
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
    // Export AXIS output. Default C_ENABLE_AXIS_EXPORT=0 because
    // current MHS does not connect M_AXIS_EXP_RECORDS to another IP.
    // With default=0, MicroBlaze owns the export FIFO through AXI4-Lite.
    // ----------------------------------------------------------
    generate
        if (C_ENABLE_AXIS_EXPORT == 0) begin : cpu_export_only
            assign M_AXIS_EXP_RECORDS_TDATA  = 64'd0;
            assign M_AXIS_EXP_RECORDS_TSTRB  = 8'd0;
            assign M_AXIS_EXP_RECORDS_TVALID = 1'b0;
            assign M_AXIS_EXP_RECORDS_TLAST  = 1'b0;
            assign fifo_rd_exp_en_axis       = 1'b0;
        end else begin : axis_export_enabled
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
                    .fifo_rd_exp_en        (fifo_rd_exp_en_axis),
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
                    .fifo_rd_exp_en        (fifo_rd_exp_en_axis),
                    .fifo_out_exp          (fifo_out_exp),
                    .fifo_empty_exp        (fifo_empty_exp)
                );
            end
        end
    endgenerate

endmodule


// ============================================================
// simple_sync_fifo - synchronous FIFO, Verilog-2001 friendly
// ============================================================
module simple_sync_fifo #(
    parameter DATA_WIDTH = 432,
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
    function integer clogb2;
        input integer value;
        integer i;
        begin
            value = value - 1;
            for (i = 0; value > 0; i = i + 1)
                value = value >> 1;
            clogb2 = i;
        end
    endfunction

    localparam ADDR_WIDTH = clogb2(DEPTH);
    localparam [ADDR_WIDTH:0] DEPTH_COUNT = DEPTH;

    reg [DATA_WIDTH-1:0] mem [0:DEPTH-1];
    reg [ADDR_WIDTH-1:0] wr_ptr;
    reg [ADDR_WIDTH-1:0] rd_ptr;
    reg [ADDR_WIDTH:0]   count;
    reg [ADDR_WIDTH:0]   count_next;

    wire do_write = wr_en && !full;
    wire do_read  = rd_en && !empty;

    always @(*) begin
        count_next = count;
        case ({do_write, do_read})
            2'b10: count_next = count + 1'b1;
            2'b01: count_next = count - 1'b1;
            default: count_next = count;
        endcase
    end

    always @(posedge clk) begin
        if (rst) begin
            wr_ptr <= {ADDR_WIDTH{1'b0}};
            rd_ptr <= {ADDR_WIDTH{1'b0}};
            count  <= {(ADDR_WIDTH+1){1'b0}};
            dout   <= {DATA_WIDTH{1'b0}};
            full   <= 1'b0;
            empty  <= 1'b1;
        end else begin
            if (do_write) begin
                mem[wr_ptr] <= din;
                wr_ptr <= wr_ptr + 1'b1;
            end

            if (do_read) begin
                dout <= mem[rd_ptr];
                rd_ptr <= rd_ptr + 1'b1;
            end

            count <= count_next;
            full  <= (count_next == DEPTH_COUNT);
            empty <= (count_next == { (ADDR_WIDTH+1){1'b0} });
        end
    end
endmodule
