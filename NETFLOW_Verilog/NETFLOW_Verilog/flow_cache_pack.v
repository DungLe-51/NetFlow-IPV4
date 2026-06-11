// *******************************************************************************
// * Design:
// * NF_BRAM
// * // * File:
// * netflow_cache_pack.v
// *
// * Pcore:
// * flow_cache
// *
// * Authors:
// * Marco Forconesi, Gustavo Sutter, Sergio Lopez-Buedo
// *
// * Description:
// * Contains definitions of constants and types.
// * Declares components of the Pcore.
// *******************************************************************************

`ifndef NETFLOW_CACHE_PACK_V
`define NETFLOW_CACHE_PACK_V

// ------------------------------------------------------------------
// Constants definition
// ------------------------------------------------------------------

`define ZEROS                          200'b0
`define TCP                            8'h06

// PACKET_INFO
`define IP_TOTAL_LENGTH_FIELD_WIDTH    16
`define TIMESTAMP_WIDTH                32
`define TCP_FLAGS_WIDTH                8
`define FIVE_TUPLE_WIDTH               104
`define PKT_INFO_WIDTH                 (`TCP_FLAGS_WIDTH + `TIMESTAMP_WIDTH + `IP_TOTAL_LENGTH_FIELD_WIDTH)

// FLOW_COUNTERS
`define BYTE_COUNTER_WIDTH             32
`define FRAME_COUNTER_WIDTH            32

// FLOW_MEMORY
// Memory organization:
//             - Entry_status (1 bit)
//             - 5-tuple
//             - tcp_flags
//             - Initial_timestamp
//             - Last_timestamp
//             - frame_counter
//             - byte_counter

`define MEM_ADDR_WIDTH                 12

`define MEM_DATA_WIDTH                 (1 + \
                                        `FIVE_TUPLE_WIDTH + \
                                        `TCP_FLAGS_WIDTH + \
                                        (`TIMESTAMP_WIDTH * 2) + \
                                        `FRAME_COUNTER_WIDTH + \
                                        `BYTE_COUNTER_WIDTH)

`define MEM_ENTRY_STATUS_INDEX         (`MEM_DATA_WIDTH - 1)

// FIFO
`define FIFO_DATA_WIDTH                240

// ------------------------------------------------------------------
// Component declarations translated to Verilog module declarations
// ------------------------------------------------------------------

// ------------------------------------------------------------------
module pkt_classification #
(
    parameter C_S_AXIS_10GMAC_DATA_WIDTH = 64
)
(
    // AXI4-Stream slave interface
    input  wire                                         ACLK,
    input  wire                                         ARESETN,
    output wire                                         S_AXIS_TREADY,
    input  wire [C_S_AXIS_10GMAC_DATA_WIDTH-1:0]        S_AXIS_TDATA,
    input  wire [(C_S_AXIS_10GMAC_DATA_WIDTH/8)-1:0]    S_AXIS_TSTRB,
    input  wire                                         S_AXIS_TLAST,
    input  wire                                         S_AXIS_TVALID,

    // Input timestamp_counter
    input  wire [`TIMESTAMP_WIDTH-1:0]                  timestamp_counter,

    // Outputs
    output wire [31:0]                                  num_processed_pkts,
    output wire [`FIVE_TUPLE_WIDTH-1:0]                 five_tuple,
    output wire [`PKT_INFO_WIDTH-1:0]                   pkt_info,
    output wire                                         tuple_and_info_valid
);

endmodule

// ------------------------------------------------------------------
module timestamp_counter_mod #
(
    parameter SIM_ONLY  = 0,
    parameter ACLK_FREQ = 200000000
)
(
    // AXI4-Stream slave interface
    input  wire                             ACLK,
    input  wire                             ARESETN,

    // Output counter
    output wire [`TIMESTAMP_WIDTH-1:0]      timestamp_counter_out
);
endmodule

// ------------------------------------------------------------------
// BRAM Component declaration
// ------------------------------------------------------------------
module BSRAM #
(
    parameter ADDR_BITS = `MEM_ADDR_WIDTH,
    parameter DATA_BITS = `MEM_DATA_WIDTH
)
(
    input  wire                             clk,

    input  wire                             ena,
    input  wire                             enb,

    input  wire                             wea,
    input  wire                             web,

    input  wire [`MEM_ADDR_WIDTH-1:0]       addra,
    input  wire [`MEM_ADDR_WIDTH-1:0]       addrb,

    input  wire [`MEM_DATA_WIDTH-1:0]       dia,
    input  wire [`MEM_DATA_WIDTH-1:0]       dib,

    output wire [`MEM_DATA_WIDTH-1:0]       doa,
    output wire [`MEM_DATA_WIDTH-1:0]       dob
);
endmodule

// ------------------------------------------------------------------
module create_or_update_flows
(
    input  wire                             ACLK,
    input  wire                             ARESETN,

    // 5-tuple receive interface
    input  wire [`FIVE_TUPLE_WIDTH-1:0]     frame_five_tuple,
    input  wire [`PKT_INFO_WIDTH-1:0]       pkt_info,
    input  wire                             tuple_and_info_valid,

    // RAM SIGNALS PORT_A
    output wire                             ena,
    output wire                             wea,
    output wire [`MEM_ADDR_WIDTH-1:0]       hash_code_out,
    input  wire [`MEM_DATA_WIDTH-1:0]       doa,
    output wire [`MEM_DATA_WIDTH-1:0]       dia,

    // Export accelerator
    output wire                             export_now,
    output wire [`MEM_ADDR_WIDTH-1:0]       export_this,
    input  wire                             flow_exported_ok,

    // Output counter
    output wire [31:0]                      collision_counter
);
endmodule

// ------------------------------------------------------------------
module export_expired_flows_from_mem
(
    input  wire                             ACLK,
    input  wire                             ARESETN,

    input  wire [`TIMESTAMP_WIDTH-1:0]      ACTIVE_TIMEOUT,
    input  wire [`TIMESTAMP_WIDTH-1:0]      InACTIVE_TIMEOUT,

    // RAM SIGNALS PORTB
    output wire                             enb,
    output wire                             web,
    output wire [`MEM_ADDR_WIDTH-1:0]       addrb,
    input  wire [`MEM_DATA_WIDTH-1:0]       dob,
    output wire [`MEM_DATA_WIDTH-1:0]       dib,

    // Export accelerator
    input  wire                             export_now,
    input  wire [`MEM_ADDR_WIDTH-1:0]       export_this,
    input  wire [`TIMESTAMP_WIDTH-1:0]      timestamp_counter,
    output wire                             flow_exported_ok,

    // flow output fifo
    output wire                             fifo_exp_rst,
    output wire                             fifo_w_exp_en,
    output wire [`FIFO_DATA_WIDTH-1:0]      fifo_in_exp,
    input  wire                             fifo_full_exp
);
endmodule

// ------------------------------------------------------------------
module exp_via_10g_interface
(
    input  wire                             ACLK,
    input  wire                             ARESETN,

    output wire [63:0]                      M_AXIS_10GMAC_tdata,
    output wire [7:0]                       M_AXIS_10GMAC_tstrb,
    output wire                             M_AXIS_10GMAC_tvalid,
    input  wire                             M_AXIS_10GMAC_tready,
    output wire                             M_AXIS_10GMAC_tlast,

    // counters
    input  wire [31:0]                      counters,
    input  wire [31:0]                      collision_counter,

    // FIFO signals
    output wire                             fifo_rd_exp_en,
    input  wire [239:0]                     fifo_out_exp,
    input  wire                             fifo_empty_exp
);
endmodule

// ------------------------------------------------------------------
module exp_to_netflow_exp
(
    input  wire                             ACLK,
    input  wire                             ARESETN,

    output wire [63:0]                      M_AXIS_10GMAC_tdata,
    output wire [7:0]                       M_AXIS_10GMAC_tstrb,
    output wire                             M_AXIS_10GMAC_tvalid,
    input  wire                             M_AXIS_10GMAC_tready,
    output wire                             M_AXIS_10GMAC_tlast,

    // FIFO signals
    output wire                             fifo_rd_exp_en,
    input  wire [239:0]                     fifo_out_exp,
    input  wire                             fifo_empty_exp
);
endmodule

`endif