#include "platform.h"
#include "xparameters.h"
#include "xil_io.h"
#include "xil_types.h"
#include "xuartlite_l.h"
#include "xil_printf.h"

// ============================================================
// Board-safe firmware for ML605 NetFlow IPv4/IPv6 integration
// Main fixes:
//   1. No infinite UART wait at boot.
//   2. No mandatory EEPROM/RTC IIC access at boot, so missing DS3231/EEPROM
//      cannot freeze the board during first bring-up.
//   3. AXI4-Lite register offsets match fixed Axi4_lite_slave.v.
//   4. FIFO is popped first, then the exported record is read from dout.
// ============================================================

#ifndef XPAR_FLOW_CACHE_TOP_0_BASEADDR
#define XPAR_FLOW_CACHE_TOP_0_BASEADDR 0x71A00000U
#endif

#ifndef XPAR_UARTLITE_1_BASEADDR
#define XPAR_UARTLITE_1_BASEADDR 0x77E14000U
#endif

#define NETFLOW_BASE            XPAR_FLOW_CACHE_TOP_0_BASEADDR
#define UART_BASE               XPAR_UARTLITE_1_BASEADDR

#define NF_REG_FIFO_RD_EN       0x00U
#define NF_REG_FIFO_EMPTY       0x04U
#define NF_REG_FLOW_W0          0x08U
#define NF_REG_FLOW_W1          0x0CU
#define NF_REG_FLOW_W2          0x10U
#define NF_REG_FLOW_W3          0x14U
#define NF_REG_FLOW_W4          0x18U
#define NF_REG_FLOW_W5          0x1CU
#define NF_REG_FLOW_W6          0x20U
#define NF_REG_FLOW_W7          0x24U
#define NF_REG_FLOW_W8          0x28U
#define NF_REG_FLOW_W9          0x2CU
#define NF_REG_FLOW_W10         0x30U
#define NF_REG_FLOW_W11         0x34U
#define NF_REG_FLOW_W12         0x38U
#define NF_REG_FLOW_W13         0x3CU
#define NF_REG_ACTIVE_TIMEOUT   0x40U
#define NF_REG_INACTIVE_TIMEOUT 0x44U
#define NF_REG_TIMESTAMP        0x48U
#define NF_REG_FIFO_NOT_EMPTY   0x4CU
#define NF_REG_LAST_RADDR       0x50U
#define NF_REG_IP_ID            0x54U

#define DEFAULT_ACTIVE_SEC      1500U
#define DEFAULT_INACTIVE_SEC    1U
#define MS_PER_SEC              1000U
#define APP_TICK_MS             10U

// Tune these only for UI feel. They do not need to be cycle-accurate.
#define UART_BOOT_TIMEOUT       25000000U
#define UART_DIGIT_TIMEOUT      8000000U
#define MAIN_LOOP_DELAY         120000U
#define POP_TO_READ_DELAY       2000U

#define NF_WRITE(offset, data)   Xil_Out32((NETFLOW_BASE) + (offset), (u32)(data))
#define NF_READ(offset)          Xil_In32((NETFLOW_BASE) + (offset))

static void delay_loop(volatile u32 n)
{
    while (n != 0U) {
        n--;
    }
}

static int uart_try_getc(u8 *ch)
{
    if (!XUartLite_IsReceiveEmpty(UART_BASE)) {
        *ch = XUartLite_RecvByte(UART_BASE);
        return 1;
    }
    return 0;
}

static int uart_getc_timeout(u8 *ch, u32 timeout)
{
    while (timeout != 0U) {
        if (uart_try_getc(ch)) {
            return 1;
        }
        timeout--;
    }
    return 0;
}

static void uart_flush_rx(void)
{
    u8 dummy;
    while (uart_try_getc(&dummy)) {
        ;
    }
}

static int ask_yes_no_timeout(const char *prompt, int default_yes)
{
    u8 ch;
    xil_printf("%s", prompt);
    if (uart_getc_timeout(&ch, UART_BOOT_TIMEOUT)) {
        if (ch == 'y' || ch == 'Y') {
            xil_printf("y\r\n");
            return 1;
        }
        if (ch == 'n' || ch == 'N') {
            xil_printf("n\r\n");
            return 0;
        }
    }

    if (default_yes) {
        xil_printf("default: y\r\n");
        return 1;
    }

    xil_printf("default: n\r\n");
    return 0;
}

static u32 read_u32_timeout(const char *prompt, u32 default_value)
{
    u8 ch;
    u32 value;
    int got_digit;

    xil_printf("%s", prompt);
    value = 0U;
    got_digit = 0;

    while (1) {
        if (!uart_getc_timeout(&ch, UART_DIGIT_TIMEOUT)) {
            if (!got_digit) {
                xil_printf("default\r\n");
                return default_value;
            }
            xil_printf("\r\n");
            return value;
        }

        if (ch == '\r' || ch == '\n') {
            xil_printf("\r\n");
            return got_digit ? value : default_value;
        }

        if (ch >= '0' && ch <= '9') {
            got_digit = 1;
            value = (value * 10U) + (u32)(ch - '0');
            xil_printf("%c", ch);
        }
    }
}

static void nf_fifo_pop_one(void)
{
    NF_WRITE(NF_REG_FIFO_RD_EN, 1U);
    NF_WRITE(NF_REG_FIFO_RD_EN, 0U);
    delay_loop(POP_TO_READ_DELAY);
}

static void print_ipv4(u32 ip)
{
    xil_printf("%d.%d.%d.%d",
               (int)((ip >> 24) & 0xffU),
               (int)((ip >> 16) & 0xffU),
               (int)((ip >> 8)  & 0xffU),
               (int)( ip        & 0xffU));
}

static void print_ipv6_from_words(u32 w13, u32 w12, u32 w11, u32 w10, u32 w9)
{
    xil_printf("%x:%x:%x:%x:%x:%x:%x:%x",
               (unsigned int)(w13 & 0xffffU),
               (unsigned int)((w12 >> 16) & 0xffffU),
               (unsigned int)(w12 & 0xffffU),
               (unsigned int)((w11 >> 16) & 0xffffU),
               (unsigned int)(w11 & 0xffffU),
               (unsigned int)((w10 >> 16) & 0xffffU),
               (unsigned int)(w10 & 0xffffU),
               (unsigned int)((w9 >> 16) & 0xffffU));
}

static void print_ipv6_dst_from_words(u32 w9, u32 w8, u32 w7, u32 w6, u32 w5)
{
    xil_printf("%x:%x:%x:%x:%x:%x:%x:%x",
               (unsigned int)(w9 & 0xffffU),
               (unsigned int)((w8 >> 16) & 0xffffU),
               (unsigned int)(w8 & 0xffffU),
               (unsigned int)((w7 >> 16) & 0xffffU),
               (unsigned int)(w7 & 0xffffU),
               (unsigned int)((w6 >> 16) & 0xffffU),
               (unsigned int)(w6 & 0xffffU),
               (unsigned int)((w5 >> 16) & 0xffffU));
}

static void read_and_print_flow(u32 index)
{
    u32 w[14];
    u32 byte_count;
    u32 pkt_count;
    u32 last_ts;
    u32 init_ts;
    u32 src_port;
    u32 dst_port;
    u32 proto;
    u32 flags;
    u32 src_ipv4;
    u32 dst_ipv4;
    int is_ipv4;
    int i;

    for (i = 0; i < 14; i++) {
        w[i] = NF_READ(NF_REG_FLOW_W0 + ((u32)i * 4U));
    }

    byte_count = w[0];
    pkt_count  = w[1];
    last_ts    = w[2];
    init_ts    = w[3];
    dst_port   = (w[4] >> 16) & 0xffffU;
    proto      = (w[4] >> 8)  & 0xffU;
    flags      = w[4] & 0xffU;
    src_port   = w[5] & 0xffffU;

    // IPv4 is stored in the low 32 bits of the 128-bit src/dst IP fields.
    src_ipv4 = ((w[10] & 0xffffU) << 16) | ((w[9] >> 16) & 0xffffU);
    dst_ipv4 = ((w[6]  & 0xffffU) << 16) | ((w[5] >> 16) & 0xffffU);

    is_ipv4 = ((w[13] == 0U) && (w[12] == 0U) && (w[11] == 0U) &&
               ((w[10] >> 16) == 0U) && ((w[9] & 0xffffU) == 0U) &&
               (w[8] == 0U) && (w[7] == 0U) && ((w[6] >> 16) == 0U));

    xil_printf("\r\n[FLOW %d]\r\n", (int)index);
    xil_printf("  proto=%d  src_port=%d  dst_port=%d  flags=0x%x\r\n",
               (int)proto, (int)src_port, (int)dst_port, (unsigned int)flags);
    xil_printf("  init_ts=%d  last_ts=%d  packets=%d  bytes=%d\r\n",
               (int)init_ts, (int)last_ts, (int)pkt_count, (int)byte_count);

    if (is_ipv4) {
        xil_printf("  src_ip=");
        print_ipv4(src_ipv4);
        xil_printf("  dst_ip=");
        print_ipv4(dst_ipv4);
        xil_printf("\r\n");
    } else {
        xil_printf("  src_ip=");
        print_ipv6_from_words(w[13], w[12], w[11], w[10], w[9]);
        xil_printf("\r\n  dst_ip=");
        print_ipv6_dst_from_words(w[9], w[8], w[7], w[6], w[5]);
        xil_printf("\r\n");
    }

    xil_printf("  raw W13..W0: ");
    for (i = 13; i >= 0; i--) {
        xil_printf("%x ", (unsigned int)w[i]);
        if (i == 0) {
            break;
        }
    }
    xil_printf("\r\n");
}

int main(void)
{
    u32 active_sec;
    u32 inactive_sec;
    u32 active_ms;
    u32 inactive_ms;
    u32 ts_ms;
    u32 flow_index;
    u32 ip_id;
    u32 empty;

    init_platform();
    uart_flush_rx();

    xil_printf("\r\n============================================================\r\n");
    xil_printf(" ML605 NetFlow IPv4/IPv6 - BOARD SAFE FW\r\n");
    xil_printf(" NETFLOW_BASE = 0x%x\r\n", (unsigned int)NETFLOW_BASE);
    xil_printf(" UART_BASE    = 0x%x\r\n", (unsigned int)UART_BASE);
    xil_printf("============================================================\r\n");

    // This read verifies that the AXI slave responds. If it hangs here,
    // the hardware AXI slave is still wrong or the bitstream is old.
    ip_id = NF_READ(NF_REG_IP_ID);
    xil_printf("AXI IP ID = 0x%x  expected 0x4E465636\r\n", (unsigned int)ip_id);

    active_sec = DEFAULT_ACTIVE_SEC;
    inactive_sec = DEFAULT_INACTIVE_SEC;

    if (ask_yes_no_timeout("Configure timeout now? press y within timeout, else default n: ", 0)) {
        active_sec = read_u32_timeout("ACTIVE timeout seconds: ", DEFAULT_ACTIVE_SEC);
        inactive_sec = read_u32_timeout("INACTIVE timeout seconds: ", DEFAULT_INACTIVE_SEC);
        if (active_sec == 0U) {
            active_sec = DEFAULT_ACTIVE_SEC;
        }
        if (inactive_sec == 0U) {
            inactive_sec = DEFAULT_INACTIVE_SEC;
        }
    }

    active_ms = active_sec * MS_PER_SEC;
    inactive_ms = inactive_sec * MS_PER_SEC;

    NF_WRITE(NF_REG_ACTIVE_TIMEOUT, active_ms);
    NF_WRITE(NF_REG_INACTIVE_TIMEOUT, inactive_ms);
    NF_WRITE(NF_REG_TIMESTAMP, 0U);

    xil_printf("ACTIVE_TIMEOUT   = %d sec / %d ms\r\n", (int)active_sec, (int)NF_READ(NF_REG_ACTIVE_TIMEOUT));
    xil_printf("INACTIVE_TIMEOUT = %d sec / %d ms\r\n", (int)inactive_sec, (int)NF_READ(NF_REG_INACTIVE_TIMEOUT));
    xil_printf("System running. Waiting for exported flows...\r\n");
    xil_printf("FIFO_EMPTY register: bit0=1 empty, bit0=0 has data.\r\n");

    ts_ms = 0U;
    flow_index = 0U;

    while (1) {
        ts_ms += APP_TICK_MS;
        NF_WRITE(NF_REG_TIMESTAMP, ts_ms);

        empty = NF_READ(NF_REG_FIFO_EMPTY) & 0x1U;
        if (empty == 0U) {
            // FIFO is not first-word-fall-through: pop first, then read dout.
            nf_fifo_pop_one();
            read_and_print_flow(flow_index);
            flow_index++;
        }

        delay_loop(MAIN_LOOP_DELAY);
    }

    cleanup_platform();
    return 0;
}
