# HƯỚNG DẪN THỰC NGHIỆM VÀ KỊCH BẢN ĐÁNH GIÁ HỆ THỐNG PHÁT HIỆN DoS TRÊN MẠNG SDN

Tài liệu này tổng hợp toàn bộ quy trình thao tác, kịch bản thử nghiệm (TCP SYN Flood, UDP Flood, ICMP Flood) và biểu mẫu thu thập số liệu phục vụ cho báo cáo đồ án.

---

## I. CHUẨN BỊ MÔ TRƯỜNG THỰC NGHIỆM

### 1. Thứ tự khởi động hệ thống (Bắt buộc)

* **Terminal 1 (Ryu Controller):**
  ```bash
  cd ~/Projects/DOAN/Controller
  ryu-manager dos_controller.py
  ```
  *(Đảm bảo terminal hiển thị `instantiating app dos_controller.py` và dừng lại ở trạng thái lắng nghe).*

* **Terminal 2 (Mininet Topology):**
  ```bash
  cd ~/Projects/DOAN/Topology
  sudo python3 23521717_custom_topology.py
  ```

* **Terminal 3 (Wireshark Monitoring):**
  ```bash
  sudo wireshark &
  ```
  *(Trên giao diện Wireshark, chọn interface `s1-eth1` hoặc `s2-eth1` và bấm Bắt đầu ghi gói tin).*

### 2. Thiết lập trạng thái mạng ban đầu (Baseline)

Tại dấu nhắc lệnh Mininet CLI (`mininet>`):
```bash
mininet> pingall
mininet> xterm h1 h2 h4
```
> **Phân bổ vai trò các Host:**
> - **`h1` (10.0.0.1):** Máy tấn công (Attacker).
> - **`h2` (10.0.0.2):** Máy người dùng hợp lệ (Legitimate Client).
> - **`h4` (10.0.0.4):** Web Server / Nạn nhân (Victim Target).

---

## II. DANH SÁCH CÁC KỊCH BẢN THỰC NGHIỆM

---

### KỊCH BẢN 1: TẤN CÔNG TCP SYN FLOOD (MẶC ĐỊNH)

#### Mục tiêu:
Đánh giá khả năng phát hiện và chặn lưu lượng TCP SYN Flood, đồng thời đo lường mức độ ảnh hưởng tới băng thông (Throughput) và độ trễ (Latency) của người dùng hợp lệ (`h2`).

#### Các bước thực hiện:

1. **Bước 1: Đo lưu lượng chuẩn khi chưa có tấn công (Baseline)**
   - Trên **`xterm h4`** (Server):
     ```bash
     iperf -s -i 1
     ```
   - Trên **`xterm h2`** (Client hợp lệ):
     ```bash
     iperf -c 10.0.0.4 -t 30 -i 1
     ```
   - Ghi lại băng thông trung bình (ví dụ: ~10 Mbps theo cấu hình TCLink).

2. **Bước 2: Kích hoạt tấn công từ `h1`**
   - Trên **`xterm h1`** (Attacker), chạy lệnh gửi TCP SYN gói tốc độ cao:
     ```bash
     hping3 -S -p 80 -i u1000 10.0.0.4
     ```
     *(Tham số `-i u1000` = gửi 1 gói mỗi 1000 microsecond = ~1000 pps).*

3. **Bước 3: Quan sát phản ứng hệ thống & Ghi nhận số liệu**
   - **Terminal Ryu Controller:** Quan sát dòng thông báo log phát hiện tấn công:
     ```text
     🚨 [PHÁT HIỆN TẤN CÔNG] Kẻ tấn công: 10.0.0.1 | Nạn nhân: 10.0.0.4
     🛑 Đang thả rule chặn mọi lưu lượng từ 10.0.0.1...
     ```
   - **`xterm h2`:** Kiểm tra xem kết nối `iperf` của `h2` có hồi phục về trạng thái bình thường sau khi `h1` bị ngắt hay không.
   - **Wireshark:** Đặt filter `tcp.flags.syn == 1 && tcp.flags.ack == 0` để kiểm tra các gói tin bị drop.

---

### KỊCH BẢN 2: TẤN CÔNG UDP FLOOD

#### Mục tiêu:
Đánh giá thuật toán phát hiện đối với lưu lượng UDP không hướng kết nối (Connectionless).

#### Các bước thực hiện:

1. **Bước 1: Chuẩn bị kiểm tra độ trễ (Ping)**
   - Trên **`xterm h2`**, bật lệnh ping liên tục tới Server để theo dõi latency (RTT):
     ```bash
     ping 10.0.0.4
     ```

2. **Bước 2: Thực hiện UDP Flood từ `h1`**
   - Trên **`xterm h1`**, kích hoạt UDP Flood nhắm vào port 80:
     ```bash
     hping3 --udp -p 80 -i u1000 10.0.0.4
     ```

3. **Bước 3: Đánh giá kết quả**
   - Kiểm tra thời gian từ khi `h1` bắt đầu bắn gói tin cho đến khi Ryu Controller in ra log chặn IP `10.0.0.1` (Thời gian phản ứng - Detection Latency).
   - Xác nhận `ping` từ `h2` không bị rớt gói (0% packet loss) sau khi Controller hạ rule chặn `h1`.

---

### KỊCH BẢN 3: TẤN CÔNG ICMP FLOOD (PING FLOOD)

#### Mục tiêu:
Kiểm tra hiệu quả của cơ chế đếm `packet_in` đối với các gói tin định tuyến layer 3 (ICMP Echo Request).

#### Các bước thực hiện:

1. **Bước 1: Bắt đầu tấn công ICMP từ `h1`**
   - Trên **`xterm h1`**, chạy lệnh flood gói tin Ping:
     ```bash
     hping3 --icmp -i u1000 10.0.0.4
     ```

2. **Bước 2: Kiểm tra bảng Flow Table trên Switch (Open vSwitch)**
   - Mở Terminal Ubuntu mới và gõ lệnh kiểm tra flow entry đã được nạp xuống switch `s1`:
     ```bash
     sudo ovs-ofctl dump-flows s1
     ```
   - Tìm rule chặn có `priority=100` và `nw_src=10.0.0.1` với `actions=drop` (hoặc `actions=` trống).

---

## III. BẢNG THU THẬP SỐ LIỆU CHO BÁO CÁO

Bạn ghi chép lại các giá trị đo đạc vào bảng sau để vẽ biểu đồ so sánh:

| Kịch bản Tấn công | Băng thông người dùng (`h2`) trước DoS | Băng thông trong khi DoS (Chưa chặn) | Băng thông sau khi Controller chặn DoS | Thời gian phát hiện (Detection Time) |
| :--- | :--- | :--- | :--- | :--- |
| **TCP SYN Flood** | ~10 Mbps | < 2 Mbps (Tùy tải) | ~10 Mbps (Phục hồi) | ~1 - 3 giây |
| **UDP Flood** | ~10 Mbps | < 1 Mbps | ~10 Mbps (Phục hồi) | ~1 - 2 giây |
| **ICMP Flood** | ~10 Mbps | ~3 - 5 Mbps | ~10 Mbps (Phục hồi) | ~1 - 2 giây |

---

## IV. ĐỌC VÀ DỌN DẸP HỆ THỐNG SAU MỖI LẦN TEST

Sau mỗi kịch bản thực nghiệm, thực hiện dọn dẹp theo thứ tự:

1. Tại **`xterm h1`**: Nhấn `Ctrl + C` để dừng `hping3`.
2. Tại **Mininet CLI (`mininet>`)**: Gõ `exit` để thoát Mininet.
3. Chạy lệnh dọn dẹp bộ đệm Open vSwitch trên Ubuntu:
   ```bash
   sudo mn -c
   ```
4. Khởi động lại Ryu Controller để reset bộ đếm `packet_in_count` và danh sách `blocked_ips`.