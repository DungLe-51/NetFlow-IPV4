`timescale 1ns / 1ps
`include "flow_cache_pack.vh"

// ============================================================
// axi4_lite_slave.v - board-safe AXI4-Lite control/status block
//
// FIXED REGISTER MAP, byte offsets from C firmware:
//   0x00 W  : FIFO pop pulse, bit0=1 pops one export entry
//   0x04 R  : FIFO empty status, bit0=1 empty, bit0=0 has data
//   0x08 R  : export word0  = byte_count
//   0x0C R  : export word1  = packet_count
//   0x10 R  : export word2  = last_timestamp
//   0x14 R  : export word3  = initial_timestamp
//   0x18 R  : export word4  = {dest_port, protocol, tcp_flags}
//   0x1C R  : export word5  = {dest_ip[15:0], src_port}
//   0x20 R  : export word6  = dest_ip[47:16]
//   0x24 R  : export word7  = dest_ip[79:48]
//   0x28 R  : export word8  = dest_ip[111:80]
//   0x2C R  : export word9  = {src_ip[15:0], dest_ip[127:112]}
//   0x30 R  : export word10 = src_ip[47:16]
//   0x34 R  : export word11 = src_ip[79:48]
//   0x38 R  : export word12 = src_ip[111:80]
//   0x3C R  : export word13 = {16'h0000, src_ip[127:112]}
//   0x40 RW : active_timeout_ms
//   0x44 RW : inactive_timeout_ms
//   0x48 RW : timestamp_counter_ms written by MicroBlaze
//   0x4C R  : FIFO not-empty status, bit0=1 has data
//   0x50 R  : last read address low bits, debug
//   0x54 R  : IP ID = 0x4E465636 ('NFV6')
// ============================================================
module axi4_lite_slave #(
    parameter integer C_S_AXI_DATA_WIDTH       = 32,
    parameter integer C_S_AXI_ADDR_WIDTH       = 32,
    parameter integer C_ACTIVE_TIMEOUT_DEFAULT = 1500000,
    parameter integer C_INACTIVE_TIMEOUT_DEFAULT = 1000
)(
    input  wire                            ACLK,
    input  wire                            ARESETN,

    input  wire                            S_AXI_ARVALID,
    output wire                            S_AXI_ARREADY,
    input  wire [C_S_AXI_ADDR_WIDTH-1:0]   S_AXI_ARADDR,
    input  wire [2:0]                      S_AXI_ARPROT,
    output wire                            S_AXI_RVALID,
    input  wire                            S_AXI_RREADY,
    output wire [C_S_AXI_DATA_WIDTH-1:0]   S_AXI_RDATA,
    output wire [1:0]                      S_AXI_RRESP,

    input  wire                            S_AXI_AWVALID,
    output wire                            S_AXI_AWREADY,
    input  wire [C_S_AXI_ADDR_WIDTH-1:0]   S_AXI_AWADDR,
    input  wire [2:0]                      S_AXI_AWPROT,
    input  wire                            S_AXI_WVALID,
    output wire                            S_AXI_WREADY,
    input  wire [C_S_AXI_DATA_WIDTH-1:0]   S_AXI_WDATA,
    input  wire [(C_S_AXI_DATA_WIDTH/8)-1:0] S_AXI_WSTRB,
    input  wire                            S_AXI_BREADY,
    output wire                            S_AXI_BVALID,
    output wire [1:0]                      S_AXI_BRESP,

    output reg  [`TIMESTAMP_WIDTH-1:0]     timestamp_counter,
    output reg  [`TIMESTAMP_WIDTH-1:0]     active_timeout_out,
    output reg  [`TIMESTAMP_WIDTH-1:0]     inactive_timeout_out,

    input  wire                            fifo_empty_exp,
    input  wire [`FIFO_DATA_WIDTH-1:0]     fifo_out_exp,
    output reg                             fifo_rd_exp_en
);

    localparam [11:0] REG_FIFO_RD_EN       = 12'h000;
    localparam [11:0] REG_FIFO_EMPTY       = 12'h004;
    localparam [11:0] REG_FLOW_W0          = 12'h008;
    localparam [11:0] REG_FLOW_W1          = 12'h00C;
    localparam [11:0] REG_FLOW_W2          = 12'h010;
    localparam [11:0] REG_FLOW_W3          = 12'h014;
    localparam [11:0] REG_FLOW_W4          = 12'h018;
    localparam [11:0] REG_FLOW_W5          = 12'h01C;
    localparam [11:0] REG_FLOW_W6          = 12'h020;
    localparam [11:0] REG_FLOW_W7          = 12'h024;
    localparam [11:0] REG_FLOW_W8          = 12'h028;
    localparam [11:0] REG_FLOW_W9          = 12'h02C;
    localparam [11:0] REG_FLOW_W10         = 12'h030;
    localparam [11:0] REG_FLOW_W11         = 12'h034;
    localparam [11:0] REG_FLOW_W12         = 12'h038;
    localparam [11:0] REG_FLOW_W13         = 12'h03C;
    localparam [11:0] REG_ACTIVE_TIMEOUT   = 12'h040;
    localparam [11:0] REG_INACTIVE_TIMEOUT = 12'h044;
    localparam [11:0] REG_TIMESTAMP        = 12'h048;
    localparam [11:0] REG_FIFO_NOT_EMPTY   = 12'h04C;
    localparam [11:0] REG_LAST_RADDR       = 12'h050;
    localparam [11:0] REG_IP_ID            = 12'h054;

    reg axi_awready;
    reg axi_wready;
    reg axi_bvalid;
    reg axi_arready;
    reg axi_rvalid;
    reg [C_S_AXI_DATA_WIDTH-1:0] axi_rdata;

    reg [C_S_AXI_ADDR_WIDTH-1:0] awaddr_latched;
    reg [C_S_AXI_DATA_WIDTH-1:0] wdata_latched;
    reg [C_S_AXI_ADDR_WIDTH-1:0] araddr_latched;
    reg aw_seen;
    reg w_seen;

    wire [11:0] wr_addr = awaddr_latched[11:0];
    wire [11:0] rd_addr = araddr_latched[11:0];
    wire write_fire;
    wire read_fire;

    assign S_AXI_AWREADY = axi_awready;
    assign S_AXI_WREADY  = axi_wready;
    assign S_AXI_BVALID  = axi_bvalid;
    assign S_AXI_BRESP   = 2'b00;
    assign S_AXI_ARREADY = axi_arready;
    assign S_AXI_RVALID  = axi_rvalid;
    assign S_AXI_RDATA   = axi_rdata;
    assign S_AXI_RRESP   = 2'b00;

    assign write_fire = aw_seen && w_seen && !axi_bvalid;
    assign read_fire  = axi_arready && S_AXI_ARVALID;

    // ---------------- AXI write address/data capture ----------------
    always @(posedge ACLK or negedge ARESETN) begin
        if (!ARESETN) begin
            axi_awready  <= 1'b1;
            axi_wready   <= 1'b1;
            axi_bvalid   <= 1'b0;
            aw_seen      <= 1'b0;
            w_seen       <= 1'b0;
            awaddr_latched <= {C_S_AXI_ADDR_WIDTH{1'b0}};
            wdata_latched  <= {C_S_AXI_DATA_WIDTH{1'b0}};
        end else begin
            axi_awready <= !aw_seen && !axi_bvalid;
            axi_wready  <= !w_seen  && !axi_bvalid;

            if (S_AXI_AWVALID && axi_awready) begin
                awaddr_latched <= S_AXI_AWADDR;
                aw_seen <= 1'b1;
            end

            if (S_AXI_WVALID && axi_wready) begin
                wdata_latched <= S_AXI_WDATA;
                w_seen <= 1'b1;
            end

            if (write_fire) begin
                axi_bvalid <= 1'b1;
                aw_seen <= 1'b0;
                w_seen  <= 1'b0;
            end else if (axi_bvalid && S_AXI_BREADY) begin
                axi_bvalid <= 1'b0;
            end
        end
    end

    // ---------------- Register writes ----------------
    always @(posedge ACLK or negedge ARESETN) begin
        if (!ARESETN) begin
            timestamp_counter    <= {`TIMESTAMP_WIDTH{1'b0}};
            active_timeout_out   <= C_ACTIVE_TIMEOUT_DEFAULT;
            inactive_timeout_out <= C_INACTIVE_TIMEOUT_DEFAULT;
            fifo_rd_exp_en       <= 1'b0;
        end else begin
            fifo_rd_exp_en <= 1'b0;

            if (write_fire) begin
                case (wr_addr)
                    REG_FIFO_RD_EN: begin
                        if (wdata_latched[0] && !fifo_empty_exp)
                            fifo_rd_exp_en <= 1'b1;
                    end
                    REG_ACTIVE_TIMEOUT: begin
                        active_timeout_out <= wdata_latched[`TIMESTAMP_WIDTH-1:0];
                    end
                    REG_INACTIVE_TIMEOUT: begin
                        inactive_timeout_out <= wdata_latched[`TIMESTAMP_WIDTH-1:0];
                    end
                    REG_TIMESTAMP: begin
                        timestamp_counter <= wdata_latched[`TIMESTAMP_WIDTH-1:0];
                    end
                    default: begin
                        // Ignore writes to read-only addresses.
                    end
                endcase
            end
        end
    end

    // ---------------- AXI read channel ----------------
    always @(posedge ACLK or negedge ARESETN) begin
        if (!ARESETN) begin
            axi_arready <= 1'b1;
            axi_rvalid  <= 1'b0;
            araddr_latched <= {C_S_AXI_ADDR_WIDTH{1'b0}};
        end else begin
            axi_arready <= !axi_rvalid;

            if (read_fire) begin
                araddr_latched <= S_AXI_ARADDR;
                axi_rvalid <= 1'b1;
            end else if (axi_rvalid && S_AXI_RREADY) begin
                axi_rvalid <= 1'b0;
            end
        end
    end

    // ---------------- Read data mux ----------------
    always @(*) begin
        case (rd_addr)
            REG_FIFO_RD_EN      : axi_rdata = {31'd0, fifo_rd_exp_en};
            REG_FIFO_EMPTY      : axi_rdata = {31'd0, fifo_empty_exp};
            REG_FLOW_W0         : axi_rdata = fifo_out_exp[31:0];
            REG_FLOW_W1         : axi_rdata = fifo_out_exp[63:32];
            REG_FLOW_W2         : axi_rdata = fifo_out_exp[95:64];
            REG_FLOW_W3         : axi_rdata = fifo_out_exp[127:96];
            REG_FLOW_W4         : axi_rdata = fifo_out_exp[159:128];
            REG_FLOW_W5         : axi_rdata = fifo_out_exp[191:160];
            REG_FLOW_W6         : axi_rdata = fifo_out_exp[223:192];
            REG_FLOW_W7         : axi_rdata = fifo_out_exp[255:224];
            REG_FLOW_W8         : axi_rdata = fifo_out_exp[287:256];
            REG_FLOW_W9         : axi_rdata = fifo_out_exp[319:288];
            REG_FLOW_W10        : axi_rdata = fifo_out_exp[351:320];
            REG_FLOW_W11        : axi_rdata = fifo_out_exp[383:352];
            REG_FLOW_W12        : axi_rdata = fifo_out_exp[415:384];
            REG_FLOW_W13        : axi_rdata = {16'h0000, fifo_out_exp[431:416]};
            REG_ACTIVE_TIMEOUT  : axi_rdata = active_timeout_out;
            REG_INACTIVE_TIMEOUT: axi_rdata = inactive_timeout_out;
            REG_TIMESTAMP       : axi_rdata = timestamp_counter;
            REG_FIFO_NOT_EMPTY  : axi_rdata = {31'd0, !fifo_empty_exp};
            REG_LAST_RADDR      : axi_rdata = {20'd0, rd_addr};
            REG_IP_ID           : axi_rdata = 32'h4E465636; // 'NFV6'
            default             : axi_rdata = 32'hBAD0_0000 | {20'd0, rd_addr};
        endcase
    end

endmodule
