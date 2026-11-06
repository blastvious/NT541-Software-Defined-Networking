# DoS Guard

Controller Ryu phat hien va ngan chan DoS, thay cho `dos_controller.py`.
Da test logic va thong diep OpenFlow bang unit test; chua chay tren Mininet + OVS.

## Mo hinh

1. Thong ke: moi giay lay flow stats, chi tinh flow tai cong bien, rule theo (MAC, IP, giao thuc).
2. Xac nhan:
   - TCP tu 100 pps: lay toi da 20 goi, tu 80% la SYN khong ACK moi ket luan SYN flood.
   - ICMP tu 100 pps: tuong tu voi echo request.
   - UDP: goi nho tu 500 pps, hoac tu 60 Mbps, trong 2 chu ky lien tiep.
3. Gia mao va qua tai controller, tinh theo tung cong bien moi giay:
   - Moi cong gan mot cap MAC/IP; qua 20 goi sai thi chan ca cong.
   - Qua 100 packet_in cung chan ca cong, tru cac goi cua flow vua duoc cai rule trong 2 giay.
4. Ngan chan tai cong vao, rule co thoi han 30, 60, 120... toi da 480 giay:
   - Tan cong thuong: chan (cong, IP dich, giao thuc); host van di duoc toi dich khac.
   - Gia mao: chan ca cong.

Moi nguong nam trong `Config`, file `Controller/dos_engine.py`.
Neu doi topology, sua `TRANSIT_PORTS` trong `Controller/dos_guard.py`.

## Chay tay

    cd Controller
    ryu-manager dos_guard.py

`DOS_MITIGATE=0 ryu-manager dos_guard.py` chi phat hien, khong chan.
Su kien co timestamp duoc ghi vao `dos_events.csv`.

## Thuc nghiem tu dong

    cd Experiments
    sudo python3 run_experiment.py --controller guard --attack syn --rate 1000
    sudo python3 run_experiment.py --all --rate flood

- `--controller`: `old` (ban cu), `detect` (chi phat hien), `guard` (co chan)
- `--attack`: `syn`, `udp`, `icmp`, `rand`, `benign`
- `--rate`: so goi/giay hoac `flood`
- Ket qua: `Experiments/results/results.csv`

Script tu tat va khoi dong Ryu, Mininet; khong can mo san terminal nao.
iperf h2->h4 chay 35 giay, tan cong tu giay 5 den giay 30, nen `attack_last5s_mbps`
la bang thong khi tan cong van dang chay.

## Unit test

    python3 -m pytest tests/

## Gioi han da biet

- Chua phat hien ACK, RST, FIN flood.
- Flood duoi 100 pps khong bi nghi ngo.
- Nhieu nguon cung tan cong, moi nguon duoi nguong, se khong bi phat hien.
- Host dau tien gia IP khi cong chua co binding co the duoc gan sai, den khi het han.
- Moi cong bien duoc gia dinh chi co mot host; `TRANSIT_PORTS` dang khai bao tinh.
