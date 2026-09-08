---
title: NNS CTF/REV

---

Hello mọi người, nay mình sẽ viết write-up cho 3 bài phần rev của giải NNS nhé!

> 1. Harald Blåtann

+ Đề bài:
![image](https://hackmd.io/_uploads/S1G92qaufx.png)

+ Phân tích:
![image](https://hackmd.io/_uploads/Hkw7pcp_Gl.png)

Vì mình thấy file .hex khá lạ nên mình đã đi tìm hiểu và biết được đây là một tệp Intel HEX. Địa chỉ đã được mã hóa trong từng record.

Vì nếu để nguyên import tệp vào IDA thì sẽ bị code segments nên ta sẽ chọn trình nạp Intel HEX và chọn cấu trúc là ARM little-endian để đọc nhé. Và vì là không có giả mã nên bài này ta phải đọc chay code assembly nhé!

Các vùng được nạp là:

```text
0x01000000 - 0x01026A58
0x01026A60 - 0x01028B6C
```

Tại địa chỉ `0x01000000` thì hai giá trị đầu tiên thành các word 32-bit:

```text
0x01000000: 0x21005C50    con trỏ stack ban đầu
0x01000004: 0x01013065    reset vector
```

Bit thấp nhất của con trỏ hàm ARM cho biết hàm chạy ở chế độ Thumb. Vì vậy địa chỉ thật của reset handler là `0x01013064`.

Tiếp đến, mình đã dùng Strings và tìm kiếm thử thông tin . Các kết quả trả mà mình thấy quan trọng gồm:

```text
0x0102793C  "NNS flag checker"
0x01027992  "Flag checker"
0x010279A8  "*** Booting nRF Connect SDK ..."
0x0102806C  "main"
0x010288D4  "NNS{th15_is_n0t_th3_fl4g}"
```

Các chuỗi NCS/Zephyr, địa chỉ flash bắt đầu tại `0x01000000`, địa chỉ RAM bắt đầu bằng `0x21000000` và tên các peripheral cho thấy đây là firmware cho network core của nRF5340. Quan trọng hơn, chúng cho biết mình nên đọc mã ARM Thumb, mã khởi động Zephyr và các cấu trúc Bluetooth GATT.

Mình nhận ra rằng là firmware đã bị strip symbol, vì ban đầu IDA mình đã tìm hàm main trong `main` trong code nhưng không thấy đâu. Vậy mình đã đi tìm hàm main bằng cách là đi từ tên main thread của Zephyr. Đầu tiên mình nhảy tới `0x0102806C` rồi dùng xref bằng cách nhấn `X`. Con trỏ tới chuỗi được lưu trong literal pool quanh `0x0101C634`. Rồi mình kiểm tra hàm khởi động xung quanh, bắt đầu gần `0x0101C570` để rồi nhận ra rằng là hàm này tạo main thread của Zephyr với entry wrapper tại `0x0101C43C`. Con trỏ Thumb được lưu là `0x0101C43D`. Và trong wrapper đó, lệnh gọi tại `0x0101C476` trỏ tới `0x01011954`.

Sau đó mình đổi tên `sub_1011954` thành `main` cho tiện theo dõi.

Gần đầu hàm có các lệnh gọi quan trọng sau để sinh thuật toán:

```text
0x0101195A  BL  sub_101E530    tạo PSA crypto
0x0101195E  BL  sub_1011B80    import khóa AES
0x01011964  BL  sub_1014BBC    bật Bluetooth
```

Vậy nên mình đã đổi tên `sub_1011B80` thành `flag_key_init`.

Tiếp đến , mình đào sâu hơn tại hàm `0x01011B80`, mã xóa một đối tượng giống `psa_key_attributes_t`, điền các field rồi gọi routine tại `0x0101E020`. Literal pool ngay sau hàm chứa sẽ là:

```text
0x01011BB0  0x01002400
0x01011BB4  0x04404000
0x01011BB8  0x210029F8
0x01011BBC  0x01028163
```

Vậy giá trị đóng gói `0x01002400` mô tả một khóa AES 256-bit (`PSA_KEY_TYPE_AES == 0x2400`, kích thước `0x100` bit) và giá trị thuật toán là

```
PSA_ALG_CBC_NO_PADDING == 0x04404000
```

Vậy nên mình đã viết lại nó thành:

```
psa_import_key(
    &attributes,
    (const uint8_t *)0x01028163,
    0x20,
    (psa_key_id_t *)0x210029F8
);
```

Mình đã đổi tên hàm `sub_101E020` thành `psa_import_key`. Như vậy dễ dàng nhận ra 32 byte tại `0x01028163` chính là khóa AES-256:

```
2fe96d47402f3ea712adb224b1be475185e524848646c58897be4893f67abf76
```

Trong `main`, chuỗi lệnh quanh `0x010119A8` truyền các giá trị:

```text
R0 = 0x01026DCC    GATT attribute
R1 = 0x0B          11 attribute
R2 = 0x010280E1    UUID 128-bit
```

cho một hàm tìm attribute theo UUID. Kiểm tra mảng attribute tại`0x01026DCC`. Tại `0x01026ED8`, nó chứa con trỏ hàm Thumb:

```text
0x01011B15
```

Bỏ bit Thumb thấp nhất khi tính địa chỉ rồi đi tới `0x01011B14` (ở đây mình đã đổi tên thành `flag_write_callback`).

Mình đã kiểm tra lại cách sử dụng các resgisters hoàn toàn khớp với callback ghi GATT của Zephyr:

```
ssize_t write_cb(
    struct bt_conn *conn,             // R0
    const struct bt_gatt_attr *attr,  // R1
    const void *buf,                  // R2
    uint16_t len,                     // R3
    uint16_t offset,                  // stack
    uint8_t flags                     // stack
);
```

Và hàm lưu `buf` vào `R5` và `len` vào `R4`.

Nửa đầu của `flag_write_callback` chuẩn bị bảy đối số rồi gọi `sub_101E188`:

```
status = psa_cipher_decrypt(
    *(psa_key_id_t *)0x210029F8,
    0x04404000,
    (const uint8_t *)0x01028103,
    0x60,
    decrypted,
    0x60,
    &decrypted_length
);
```

Các giá trị literal pool liên quan nằm tại `0x01011B74` (địa chỉ key), `0x01011B78` (thuật toán) và `0x01011B7C` (địa chỉ blob mã hóa).

Mình ở đây đã đổi tên `sub_101E188` thành `psa_cipher_decrypt` cho tiện nhớ.

Các lệnh sau tương đương với:

```
if (len <= 0x3c) {
    valid = 0;
} else {
    size_t count = len < 0x60 ? len : 0x60;
    valid = strncmp(
        (const char *)decrypted,
        (const char *)buf + offset,
        count
    ) == 0;
}
```

Check lại với assembly:

```text
0x01011B3E  CMP   R4, #0x3C       len > 60
0x01011B54  LDRH  R1, [SP,#...]   GATT offset
0x01011B58  CMP   R4, #0x60
0x01011B5A  MOV   R2, R4
0x01011B60  MOVCS R2, #0x60       count = min(len, 96)
0x01011B5C  MOV   R0, R6          buffer decrypt
0x01011B62  ADD   R1, R5          buffer send + offset
0x01011B64  BL    0x010264B8
```

Vậy có thể hiểu hàm `0x010264B8` như sau:
Nó sẽ so sánh từng byte cho tới khi khác nhau, hết độ dài,hoặc gặp hai byte NUL bằng nhau. Vì vậy đây là `strncmp`, không phải `memcmp`. Chuỗi `CLZ` rồi shift phía sau biến kết quả trả về bằng 0 thành `1`, và
mọi kết quả khác 0 thành `0`.

Vậy mình đã biết địa chỉ của key và blob giải mã rồi, mình sẽ nhờ idapython làm hộ mình việc trích ra giá trị nhé
```
import ida_bytes

blob = ida_bytes.get_bytes(0x01028103, 0x60)
key = ida_bytes.get_bytes(0x01028163, 0x20)

print("blob =", blob.hex())
print("key  =", key.hex())
```

Output:

```
blob = 43a70bc8e54e61cfff8d0a6d7d09fe20dde4bdfff3b45d91a80b420fdca73a90af6d2d7655f11d6646b85959d4caa9bc395864fbbc039cd14f1eb6fab295bd2dc267e789262d9b333cc23aef59583b31e2d1016f63c132366525561708f76f0f
key  = 2fe96d47402f3ea712adb224b1be475185e524848646c58897be4893f67abf76
```

Với PSA cipher API dạng one-shot, input giải mã có dạng IV và ciphertext. AES-CBC dùng IV 16 byte, nên tách blob như sau:

```text
IV = 43a70bc8e54e61cfff8d0a6d7d09fe20

ciphertext =
dde4bdfff3b45d91a80b420fdca73a90
af6d2d7655f11d6646b85959d4caa9bc
395864fbbc039cd14f1eb6fab295bd2d
c267e789262d9b333cc23aef59583b31
e2d1016f63c132366525561708f76f0f
```

Có đủ yếu tố cho thuật toán AES-256-CBC rồi, giờ mình sẽ viết chuogn trình giải mã nhé :
```
from Crypto.Cipher import AES

def decrypt_flag():
    key = bytes.fromhex("2fe96d47402f3ea712adb224b1be475185e524848646c58897be4893f67abf76")
    iv = bytes.fromhex("43a70bc8e54e61cfff8d0a6d7d09fe20")
    ciphertext = bytes.fromhex(
        "dde4bdfff3b45d91a80b420fdca73a90"
        "af6d2d7655f11d6646b85959d4caa9bc"
        "395864fbbc039cd14f1eb6fab295bd2d"
        "c267e789262d9b333cc23aef59583b31"
        "e2d1016f63c132366525561708f76f0f"
    )
    plaintext = AES.new(key, AES.MODE_CBC, iv).decrypt(ciphertext)
    return plaintext.split(b"\0", 1)[0].decode()

print(decrypt_flag())
```
Output:![image](https://hackmd.io/_uploads/r1h-m3T_Mg.png)

Vậy flag bài này sẽ là:
```
NNS{w1r3lessly_s3nt_4nd_ch3ck3d_by_th3_p0w3r_0f_k1ng_bl4t4nn}
```

> 2. No Strings Attached
+ Đề bài: ![image](https://hackmd.io/_uploads/Sym3L36_Me.png)

+ Phân tích: ![image](https://hackmd.io/_uploads/rkuaLnTOGg.png)

Đầu tiên mình sẽ chạy thử file trước:
![image](https://hackmd.io/_uploads/r1Uavnp_Gl.png)

Nhìn qua có vẻ là chương trình check yes no cơ bản, giờ vào IDA phân tích xem nhé:

```
int __fastcall main(int argc, const char **argv, const char **envp)
{
  int v4; // [rsp+0h] [rbp-10h]
  unsigned int i; // [rsp+4h] [rbp-Ch]
  ssize_t v6; // [rsp+8h] [rbp-8h]

  v4 = 6;
  write(1, "guess: ", 7uLL);
  v6 = read(0, input, 0x7FuLL);
  if ( v6 <= 0 )
    return 1;
  if ( input[v6 - 1] == 10 )
    --v6;
  input[v6] = 0;
  for ( i = 0; i <= 0x37; ++i )
  {
    v4 = 1103515245 * v4 + 12345;
    secret[i] ^= BYTE2(v4);
  }
  if ( !strcmp(input, secret) )
  {
    write(1, "correct\n", 8uLL);
    return 0;
  }
  else
  {
    write(1, "rejected\n", 9uLL);
    return 2;
  }
}
```
Cơ bản cách chương trình thực hiện là: in chuỗi `guess:`  qua hàm `write`, đọc 127 bytes từ `stdin (0)` vào mảng `input` qua `read(0, input, 0x7FuLL)`, rồi kiểm tra nếu người dùng không nhập gì hoặc lỗi (`v6 <= 0`), chương trình thoát sẽ với mã lỗi 1 còn không thì nó sẽ loại bỏ ký tự xuống dòng bằng cách nếu ký tự cuối cùng là `10`, giảm độ dài `v6` đi 1 và gán byte kết thúc chuỗi `input[v6] = 0`, sau đó nó sài LCG bằng việc khởi tạo seed `v4 = 6` rồi chạy vòng lặp 56 lần (i từ 0 đến 0x37).Rồi lấy v4 = 1103515245 * v4 + 12345 (LCG đây nè) và thực hiện phép XOR `secret[i] ^= BYTE2(v4)` để giải mã `secret` tại chỗ. Sau khi sài thuật toán nó sẽ check lại với `strcmp == 0` nếu đúng thì trả về `0` với chuỗi `correct` và ngược lại sẽ là 2 với chuỗi `rejected`.

Vậy giờ chỉ cần trích xuất nốt dữ liệu ở `secret` để viết lại thuật toán thôi:

Dữ liệu ở `secret`:
```
data:0000000000404040 secret          db 0E8h                 ; DATA XREF: main+A8↑o
.data:0000000000404040                                         ; main+BC↑o ...
.data:0000000000404041                 db 0E5h
.data:0000000000404042                 db 0A5h
.data:0000000000404043                 db 0F7h
.data:0000000000404044                 db  1Ch
.data:0000000000404045                 db  79h ; y
.data:0000000000404046                 db 0B2h
.data:0000000000404047                 db  22h ; "
.data:0000000000404048                 db  43h ; C
.data:0000000000404049                 db 0F6h
.data:000000000040404A                 db 0C4h
.data:000000000040404B                 db 0B1h
.data:000000000040404C                 db  39h ; 9
.data:000000000040404D                 db  67h ; g
.data:000000000040404E                 db  34h ; 4
.data:000000000040404F                 db 0FFh
.data:0000000000404050                 db 0B6h
.data:0000000000404051                 db  7Fh ; 
.data:0000000000404052                 db  3Eh ; >
.data:0000000000404053                 db  2Bh ; +
.data:0000000000404054                 db  85h
.data:0000000000404055                 db 0EFh
.data:0000000000404056                 db  82h
.data:0000000000404057                 db  70h ; p
.data:0000000000404058                 db 0E9h
.data:0000000000404059                 db 0E2h
.data:000000000040405A                 db  67h ; g
.data:000000000040405B                 db 0CCh
.data:000000000040405C                 db  2Ah ; *
.data:000000000040405D                 db 0FEh
.data:000000000040405E                 db  2Eh ; .
.data:000000000040405F                 db    8
.data:0000000000404060                 db  41h ; A
.data:0000000000404061                 db 0C0h
.data:0000000000404062                 db  40h ; @
.data:0000000000404063                 db 0B0h
.data:0000000000404064                 db    7
.data:0000000000404065                 db 0A1h
.data:0000000000404066                 db 0D4h
.data:0000000000404067                 db 0F5h
.data:0000000000404068                 db 0A0h
.data:0000000000404069                 db 0E6h
.data:000000000040406A                 db  37h ; 7
.data:000000000040406B                 db  5Fh ; _
.data:000000000040406C                 db  92h
.data:000000000040406D                 db  90h
.data:000000000040406E                 db  39h ; 9
.data:000000000040406F                 db  70h ; p
.data:0000000000404070                 db 0D4h
.data:0000000000404071                 db  14h
.data:0000000000404072                 db  20h
.data:0000000000404073                 db 0E4h
.data:0000000000404074                 db  2Eh ; .
.data:0000000000404075                 db 0F3h
.data:0000000000404076                 db  7Bh ; {
.data:0000000000404077                 db 0BAh
.data:0000000000404078                 db    0
```

Code giải mã sẽ là: 
```
secret = [
    0xE8,
    0xE5,
    0xA5,
    0xF7,
    0x1C,
    0x79,
    0xB2,
    0x22,
    0x43,
    0xF6,
    0xC4,
    0xB1,
    0x39,
    0x67,
    0x34,
    0xFF,
    0xB6,
    0x7F,
    0x3E,
    0x2B,
    0x85,
    0xEF,
    0x82,
    0x70,
    0xE9,
    0xE2,
    0x67,
    0xCC,
    0x2A,
    0xFE,
    0x2E,
    0x08,
    0x41,
    0xC0,
    0x40,
    0xB0,
    0x07,
    0xA1,
    0xD4,
    0xF5,
    0xA0,
    0xE6,
    0x37,
    0x5F,
    0x92,
    0x90,
    0x39,
    0x70,
    0xD4,
    0x14,
    0x20,
    0xE4,
    0x2E,
    0xF3,
    0x7B,
    0xBA,
]

v4 = 6
flag = []

for i in range(len(secret)):  
  v4 = (1103515245 * v4 + 12345) & 0xFFFFFFFF
  byte2 = (v4 >> 16) & 0xFF
  flag.append(secret[i] ^ byte2)

print(bytes(flag).decode("latin-1"))
```
Output:
![image](https://hackmd.io/_uploads/rkR9n3adfg.png)
Check lại thử:
![image](https://hackmd.io/_uploads/Hy4Cnnadze.png)


Vậy flag bài sẽ là:
```
NNS{n0_str1ngs_1n_7h3_b1n4ry_bu7_ltr4c3_s4w_7h3_c0mp4r3}
```
> 3.Open Secret

+ Đề bài:
![image](https://hackmd.io/_uploads/BkJQfp6_fg.png)
+ Phân tích:
![image](https://hackmd.io/_uploads/BkmNz6p_zx.png)
Thử chạy file nhé:
![image](https://hackmd.io/_uploads/BkYbG6Tdfx.png)

Đọc file bằng IDA xem có gì nhé:
```
void __noreturn start()
{
  _BYTE *v0; // rax
  int v1; // [rsp+Ch] [rbp-4h]

  if ( (unsigned int)(time(0LL) / 86400) == 2932532 )
  {
    v1 = 1303732158;
    v0 = &flag;
    do
    {
      v1 = 22695477 * v1 + 1;
      *v0++ ^= BYTE2(v1);
    }
    while ( (char *)&flag + 46 != v0 );
    write(1, &flag, 0x2EuLL);
    _exit(0);
  }
  write(1, "sealed\n", 7uLL);
  _exit(1);
}
```
Chương trình có thể gói gọn như sau: Đầu tiên nó sẽ lấy mốc thời gian `Unix timestamp` hiện tại (tính bằng giây): `time(0LL)` rồi chia cho số giây trong một ngày (86400) để lấy số ngày tính từ kỷ nguyên Unix (1/1/1970). Điều kiện kích hoạt là `time(0LL) / 86400 == 2932532` . 2932532 x 86400 sẽ sấp sỉ 253370764800, tương ứng với khoảng năm 10000 trong tương lai. Nếu chạy bình thường ở thời điểm hiện tại, điều kiện luôn sai nên sẽ luôn in ra `sealed` và thoát . Nếu điều kiện thời gian thỏa mãn thì thuật toán sẽ giải mã với seed ban đầu: `v1 = 1303732158` , độ dài flag sẽ là 46 bytes và áp dụng thuật toán LCG như bài trước: `v1 = 22695477 * v1 + 1`, sau đó XOR với byte thứ 2 của trạng thái `*v0++ ^= BYTE2(v1)` để in kết quả ra màn hình

Vậy giờ ta chỉ cần lấy dữ liệu từ `flag` là đã có thể giải được bài này rồi:
```
.data:0000000000404020 flag            db 0CAh                 ; DATA XREF: _start+42↑o
.data:0000000000404021                 db 0D0h
.data:0000000000404022                 db  1Bh
.data:0000000000404023                 db  6Eh ; n
.data:0000000000404024                 db 0C3h
.data:0000000000404025                 db 0AEh
.data:0000000000404026                 db  20h
.data:0000000000404027                 db 0E4h
.data:0000000000404028                 db 0E9h
.data:0000000000404029                 db 0FFh
.data:000000000040402A                 db  98h
.data:000000000040402B                 db  8Eh
.data:000000000040402C                 db  97h
.data:000000000040402D                 db  53h ; S
.data:000000000040402E                 db  81h
.data:000000000040402F                 db 0AAh
.data:0000000000404030                 db  58h ; X
.data:0000000000404031                 db    9
.data:0000000000404032                 db  15h
.data:0000000000404033                 db  66h ; f
.data:0000000000404034                 db  2Eh ; .
.data:0000000000404035                 db  8Bh
.data:0000000000404036                 db  55h ; U
.data:0000000000404037                 db  31h ; 1
.data:0000000000404038                 db 0A7h
.data:0000000000404039                 db 0D0h
.data:000000000040403A                 db  35h ; 5
.data:000000000040403B                 db 0CFh
.data:000000000040403C                 db 0C2h
.data:000000000040403D                 db  4Dh ; M
.data:000000000040403E                 db 0E3h
.data:000000000040403F                 db    1
.data:0000000000404040                 db  3Ah ; :
.data:0000000000404041                 db  8Bh
.data:0000000000404042                 db  96h
.data:0000000000404043                 db  24h ; $
.data:0000000000404044                 db  5Ch ; \
.data:0000000000404045                 db 0B8h
.data:0000000000404046                 db 0C1h
.data:0000000000404047                 db  2Fh ; /
.data:0000000000404048                 db 0D5h
.data:0000000000404049                 db    0
.data:000000000040404A                 db  8Ch
.data:000000000040404B                 db 0FBh
.data:000000000040404C                 db 0D1h
.data:000000000040404D                 db 0A8h
.data:000000000040404E                 db    0
```

Code giải mã : 
```
secret = [
    0xCA, 0xD0, 0x1B, 0x6E, 0xC3, 0xAE, 0x20, 0xE4,
    0xE9, 0xFF, 0x98, 0x8E, 0x97, 0x53, 0x81, 0xAA,
    0x58, 0x09, 0x15, 0x66, 0x2E, 0x8B, 0x55, 0x31,
    0xA7, 0xD0, 0x35, 0xCF, 0xC2, 0x4D, 0xE3, 0x01,
    0x3A, 0x8B, 0x96, 0x24, 0x5C, 0xB8, 0xC1, 0x2F,
    0xD5, 0x00, 0x8C, 0xFB, 0xD1, 0xA8
]

v1 = 1303732158
flag = []

for b in secret:
    v1 = (22695477 * v1 + 1) & 0xFFFFFFFF
    flag.append(b ^ ((v1 >> 16) & 0xFF))

print(bytes(flag).decode())
```
Output:
![image](https://hackmd.io/_uploads/SJSHB6aOGg.png)
Vậy flag bài này sẽ là : 
```
NNS{y0u_c4n_l13_70_4_pr0gr4m_w17h_ld_pr3l04d}
```
