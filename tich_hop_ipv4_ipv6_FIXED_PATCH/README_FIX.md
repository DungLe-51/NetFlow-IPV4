# tich_hop_ipv4_ipv6 FIXED PATCH

## Mục tiêu bản sửa
Bản này xử lý lỗi board bị đứng khi nạp xuống ML605 theo hướng bring-up an toàn trước:

1. Firmware không còn đứng vô hạn vì chờ UART input `XUartLite_RecvByte()`.
2. Firmware không tự động truy cập EEPROM/RTC IIC khi boot, tránh treo nếu DS3231/EEPROM chưa nối đúng hoặc bus IIC bị kẹt.
3. Sửa AXI4-Lite register map giữa C và Verilog về byte offset thống nhất.
4. Nối lại `timestamp_counter`, `active_timeout`, `inactive_timeout`, `fifo_empty_exp`, `fifo_out_exp`, `fifo_rd_exp_en` từ AXI slave vào `flow_cache_top`.
5. Tách FIFO read enable của CPU và AXIS exporter để tránh multiple-driver trên `fifo_rd_exp_en`.
6. Mặc định CPU/MicroBlaze đọc export FIFO; AXIS exporter bị disable vì trong MHS hiện tại `M_AXIS_EXP_RECORDS` không được nối sang IP khác.

## File cần chép đè
Chép 3 file này vào đúng vị trí trong project gốc:

- `final/src/helloworld.c`
- `pcores/flow_cache_top_v1_00_a/hdl/verilog/Axi4_lite_slave.v`
- `pcores/flow_cache_top_v1_00_a/hdl/verilog/flow_cache_top.v`

## Register map mới

| Offset | Access | Ý nghĩa |
|---|---|---|
| 0x00 | W/R | FIFO pop pulse, ghi bit0=1 để pop 1 record |
| 0x04 | R | FIFO empty, bit0=1 empty, bit0=0 has data |
| 0x08..0x3C | R | 14 word export record W0..W13 |
| 0x40 | RW | active_timeout_ms |
| 0x44 | RW | inactive_timeout_ms |
| 0x48 | RW | timestamp_counter_ms |
| 0x4C | R | FIFO not empty, bit0=1 has data |
| 0x50 | R | last read address debug |
| 0x54 | R | IP ID = 0x4E465636 ('NFV6') |

## Cách build lại

Trong XPS/ISE:
1. Chép đè 2 file Verilog vào `pcores/.../hdl/verilog/`.
2. XPS -> Project -> Rescan User Repositories.
3. Hardware -> Clean Hardware.
4. Hardware -> Generate Netlist.
5. Hardware -> Generate Bitstream.
6. Export Hardware to SDK.

Trong SDK:
1. Chép đè `final/src/helloworld.c`.
2. Clean `final_bsp` nếu hardware platform thay đổi.
3. Build BSP.
4. Build `final`.
5. Program FPGA bằng bitstream mới.
6. Run `final.elf`.

## Output UART mong đợi
Nếu hardware AXI slave đúng, UART sẽ in:

```text
ML605 NetFlow IPv4/IPv6 - BOARD SAFE FW
NETFLOW_BASE = 0x71A00000
AXI IP ID = 0x4E465636 expected 0x4E465636
Configure timeout now? ... default: n
ACTIVE_TIMEOUT = ...
System running. Waiting for exported flows...
```

Nếu đứng ngay tại dòng `AXI IP ID`, nghĩa là bạn vẫn đang nạp bitstream cũ hoặc AXI slave trong hardware chưa respond.
