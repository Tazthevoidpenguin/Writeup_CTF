# WU BKISC_2026 + THCON_2026

# BKISC RE:

## Boring APK

![image.png](Images/image.png)

ban đầu cho vào jadx chẳng thấy gì nên mình có tra cứu AI thử, sau đấy đổi thành đuôi zip giải nén ra thì ra file mới

![image.png](Images/image%201.png)

lần này cho vào jadx thì thấy nội dung code rồi

![image.png](Images/image%202.png)

→ Vẫn chỉ là packer

![image.png](Images/image%203.png)

Trong packer này nó load nội dung 2 file .tmp để mã hóa AES-GCM-128 rồi nén bằng GZIP

![image.png](Images/image%204.png)

Lại đổi tên file thành .zip 1 lần nữa rồi giải nén ra, vào assets sẽ thấy 2 file .tmp mà ta cần tìm

![image.png](Images/image%205.png)

![image.png](Images/image%206.png)

Gen code unpack:

```python
import gzip
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def unpack_dex(input_file, output_file):
    # 1. Chuyển đổi Key (từ mảng số nguyên có dấu sang byte)
    key_signed = [120, -11, 67, -64, 3, -120, 71, -96, 55, 54, -72, 106, -58, 113, -128, -110, 94, -1, 17, -73, -100, 95, -113, 28, 66, 13, 10, 15, -119, 103, 43, -116]
    key_bytes = bytes([b & 0xFF for b in key_signed])

    # 2. Giải mã AAD (Dựa vào hàm d() và XOR_KEY = 90)
    xor_key = 90
    aad_data = [56, 49, 51, 41, 57, 106, 107]
    aad_bytes = bytes([b ^ xor_key for b in aad_data]) # Kết quả sẽ là b'bkisc !'

    with open(input_file, 'rb') as f:
        data = f.read()

    # Kiểm tra xem file đã là dex chuẩn chưa
    if data[:4] == b"dex\n":
        print(f"[!] File {input_file} đã là file Dex không bị mã hóa.")
        with open(output_file, 'wb') as out:
            out.write(data)
        return

    # 3. Tách cấu trúc file: 12 bytes đầu là Nonce (IV), phần còn lại là Ciphertext + Tag
    if len(data) < 28:
        print("File quá nhỏ, không hợp lệ.")
        return
        
    nonce = data[:12]
    ciphertext_and_tag = data[12:]

    # 4. Giải mã AES-GCM
    try:
        aesgcm = AESGCM(key_bytes)
        compressed_data = aesgcm.decrypt(nonce, ciphertext_and_tag, aad_bytes)
    except Exception as e:
        print(f"[-] Lỗi giải mã AES: {e}")
        return

    # 5. Giải nén GZIP
    try:
        dex_data = gzip.decompress(compressed_data)
        with open(output_file, 'wb') as out:
            out.write(dex_data)
        print(f"[+] Đã giải mã thành công: {output_file}")
    except Exception as e:
        print(f"[-] Lỗi giải nén GZIP: {e}")

# Chạy thử nghiệm với 2 file giấu trong thư mục assets
# Lấy 2 file này từ trong APK gốc ra cùng thư mục với script
unpack_dex('hidden-main-application.tmp', 'real_app.dex')
unpack_dex('hidden-main-activity.tmp', 'real_activity.dex')
```

ném vào JADX thì thấy nội dung 2 code thật như sau:

![image.png](Images/image%207.png)

![image.png](Images/image%208.png)

Tại đây thấy được hàm checkflag được load từ libchecker.so

```python
public native boolean checkFlag(String str);

private static final String CHECKER_LIB_NAME = "libchecker.so";
```

here it is

![image.png](Images/image%209.png)

mở bằng IDA ta được

![image.png](Images/image%2010.png)

![image.png](Images/image%2011.png)

còn hơi dài bên dưới nhưng mình chưa hiểu mấy cái này nên cho AI đọc

1. Hàm `checkFlag_native(JNIEnv*, jobject*, jstring*)` được gọi từ Java/JNI.
2. Đầu hàm lưu stack canary và các tham số JNI:
    - `X0 = JNIEnv*`
    - `X1 = jobject`
    - `X2 = jstring input`
3. Sau đó gọi `loc_2D1DC`.
4. `loc_2D1DC` giải mã một vùng code/data khác:
    - start: `vk15_start`
    - end: `vk15_end`
    - key: `"v2Mn6JrS9kWp3Dx"`
5. Quay lại `checkFlag_native`, nó tiếp tục giải mã vùng:
    - start: `xr16_start`
    - end: `xr16_end`
    - key: `"k4Pt8XsQ1mZv6Hd"`
6. Vùng `xr16_start..xr16_end` ban đầu nhìn như data/instruction rác. Thực tế đây là code đã bị mã hóa. Sau khi gọi decrypt function, vùng này mới trở thành code thật để chạy logic tiếp theo.
7. Hàm decrypt chính là `zk9vPq4Lm2(start, end, key)`:
    - Tính độ dài vùng cần giải mã: `length = end - start`
    - Sinh state 16 byte từ `key` và `length`
    - Gọi `mprotect(..., PROT_READ | PROT_WRITE | PROT_EXEC)` để cho phép sửa code trong `.text`
    - Với từng byte trong vùng mã hóa:
        - Sinh 1 byte keystream
        - XOR byte hiện tại với keystream
    - Flush instruction cache bằng `sub_60B1C`
    - Gọi lại `mprotect(..., PROT_READ | PROT_EXEC)` để trả vùng code về trạng thái executable/read-only
8. Hàm `sub_2B69C(key, length)` là key schedule:
    - Khởi tạo 4 biến 32-bit bằng các hằng:
        - `0x243F6A88`
        - `0x85A308D3`
        - `0x13198A2E`
        - `0x03707344 ^ length`
    - Duyệt từng byte của key string.
    - Trộn state bằng cộng, XOR, nhân, rotate.
    - Sau đó chạy thêm 6 vòng mixing để tạo state cuối.
9. Hàm `sub_2B968(state, index)` sinh 1 byte keystream:
    - Dùng state 4 số 32-bit.
    - Trộn với index hiện tại.
    - Lấy checksum dạng `v ^ (v >> 8) ^ (v >> 16) ^ (v >> 24)`.
    - Byte thấp nhất là byte keystream.
    - Sau đó update state để sinh byte tiếp theo.
10. Vì decrypt là XOR stream cipher, cùng một hàm có thể dùng để decrypt hoặc encrypt:
    - `cipher[i] ^= keystream[i]`
    - chạy lại lần nữa sẽ ra dữ liệu ban đầu.

Lưu ý: trong đoạn bạn gửi không có body của `sub_2CB0C`, nhưng dựa vào cách dùng với các tham số `3, 5, 7, 9, 11, 13, 17, 23`, nó gần như chắc là hàm rotate-left 32-bit.

→ Script giải mã vùng xr16 và vk15:

```python
#!/usr/bin/env python3
import argparse
from pathlib import Path

MASK32 = 0xFFFFFFFF

def u32(x):
    return x & MASK32

def rol32(x, r):
    x &= MASK32
    r &= 31
    return ((x << r) | (x >> (32 - r))) & MASK32

def key_schedule(key: bytes, length: int):
    s0 = 0x243F6A88
    s1 = 0x85A308D3
    s2 = 0x13198A2E
    s3 = 0x03707344 ^ length

    for i, c in enumerate(key):
        s0 = u32(rol32(s0 ^ u32(c + s3), 5) + 0x9E3779B9)
        s1 = u32(rol32(u32(s1 + (s0 ^ u32(c * 0x45))), 7) ^ 0xA5A5A5A5)
        s2 = u32((s2 ^ u32(s1 + c + i)) * 0x27D4EB2D)
        s3 = u32(rol32(u32(s3 + s2 + (c << 1)), 13) ^ s0)

    s0 = u32(s0 ^ u32(length * 0x9E3779B1))
    s1 = u32(s1 + rol32(length ^ 0xA55AA55A, 11))
    s2 = u32(s2 ^ rol32(u32(s0 + s3), 17))
    s3 = u32(s3 + rol32(s1 ^ s2, 3))

    for i in range(6):
        mixed = s0
        mixed ^= rol32(s1, 9)
        mixed ^= rol32(s2, 17)
        mixed ^= rol32(s3, 23)
        mixed = u32(mixed)

        old_s1 = s1
        old_s2 = s2
        old_s3 = s3

        s0 = u32(old_s1 + 0x9E3779B9 + i)
        s1 = u32(old_s2 ^ rol32(mixed, 3))
        s2 = u32(old_s3 + rol32(s0, 7))
        s3 = u32(mixed ^ rol32(s2, 11))

    return [s0, s1, s2, s3]

def next_byte(state, index):
    s0, s1, s2, s3 = state

    a = u32(s0 + rol32(s1, 3))
    b = u32(s2 + rol32(s3, 11))
    v = u32(a ^ b ^ u32(index * 0x9E3779B9))

    out = v ^ (v >> 8) ^ (v >> 16) ^ (v >> 24)
    out &= 0xFF

    state[0] = u32(rol32(u32(s0 + s2 + 0x7F4A7C15), 5) ^ s3)
    state[1] = u32(rol32(u32(s1 ^ state[0] ^ 0x6A09E667), 9))
    state[2] = u32(rol32(u32(s2 + state[1] + index), 13) ^ 0xBB67AE85)
    state[3] = u32(rol32(u32((s3 ^ state[2]) ^ u32(v + 0x3C6EF372)), 17))

    return out

def decrypt_region(data: bytes, key: str):
    buf = bytearray(data)
    key_bytes = key.encode("ascii")
    state = key_schedule(key_bytes, len(buf))

    for i in range(len(buf)):
        buf[i] ^= next_byte(state, i)

    return bytes(buf)

def main():
    parser = argparse.ArgumentParser(
        description="Decrypt region used by zk9vPq4Lm2 self-modifying stub"
    )
    parser.add_argument("input", help="Input binary file, for example libnative.so")
    parser.add_argument("-o", "--output", default="decrypted_region.bin")
    parser.add_argument("--start", required=True, help="Start file offset, hex allowed")
    parser.add_argument("--end", required=True, help="End file offset, hex allowed")
    parser.add_argument(
        "--key",
        default="k4Pt8XsQ1mZv6Hd",
        help="Decrypt key. Default is xr16 key",
    )
    args = parser.parse_args()

    input_path = Path(args.input)
    raw = input_path.read_bytes()

    start = int(args.start, 0)
    end = int(args.end, 0)

    if start < 0 or end <= start or end > len(raw):
        raise ValueError("Invalid start/end file offsets")

    encrypted = raw[start:end]
    decrypted = decrypt_region(encrypted, args.key)

    Path(args.output).write_bytes(decrypted)

    print(f"[+] input    : {input_path}")
    print(f"[+] key      : {args.key}")
    print(f"[+] start    : 0x{start:X}")
    print(f"[+] end      : 0x{end:X}")
    print(f"[+] length   : {len(encrypted)} bytes")
    print(f"[+] output   : {args.output}")
    print("[+] first 64 decrypted bytes:")
    print(decrypted[:64].hex(" "))

if __name__ == "__main__":
    main()
    
    """
    lệnh chạy cho xr16
    python3 decrypt_zk9v.py libchecker.so \
  --start 0x2D0CC \
  --end 0x2D164 \
  --key k4Pt8XsQ1mZv6Hd \
  -o xr16_decrypted.bin
  
  vk15
  python3 decrypt_zk9v.py libchecker.so \
  --start 0x2D200 \
  --end 0x2D234 \
  --key v2Mn6JrS9kWp3Dx \
  -o vk15_decrypted.bin
  
    """
```

→ Patch lại vào IDA [libchecker.so](http://libchecker.so) 

Code patch:

```python
from pathlib import Path

base_dir = Path(r"...")#thay duong dan file vao

input_so = base_dir / "libchecker.so"
output_so = base_dir / "libchecker_patched.so"

patches = [
    {
        "name": "xr16",
        "start": 0x2D0CC,
        "end": 0x2D164,
        "file": base_dir / "xr16_decrypted.bin",
    },
    {
        "name": "vk15",
        "start": 0x2D200,
        "end": 0x2D234,
        "file": base_dir / "vk15_decrypted.bin",
    },
]

so_data = bytearray(input_so.read_bytes())

print(f"[+] Input : {input_so}")
print(f"[+] Output: {output_so}")

for p in patches:
    name = p["name"]
    start = p["start"]
    end = p["end"]
    patch_file = p["file"]

    patch_data = patch_file.read_bytes()
    expected_size = end - start

    print(f"\n[+] Patching {name}")
    print(f"    file   : {patch_file}")
    print(f"    offset : 0x{start:X} -> 0x{end:X}")
    print(f"    size   : {len(patch_data)} bytes")

    if len(patch_data) != expected_size:
        raise ValueError(
            f"{name}: size mismatch, expected {expected_size} bytes, "
            f"got {len(patch_data)} bytes"
        )

    so_data[start:end] = patch_data

output_so.write_bytes(so_data)

print("\n[+] Done")
print(f"[+] Patched SO saved to: {output_so}")
```

Đến bước này thì đi lượm nhặt các đoạn sau để AI phân tích thôi

```python
verify_flag thunk  : không cần phân tích
verify_flag thật   : 0x2CD90
encrypted body     : 0x2CDC8 -> 0x2CF80
key address        : 0x18E98
```

patch thêm nf34 (vùng chứa code thật)

```python
from pathlib import Path

MASK32 = 0xFFFFFFFF

def u32(x):
    return x & MASK32

def rol32(x, r):
    x &= MASK32
    r &= 31
    return ((x << r) | (x >> (32 - r))) & MASK32

def key_schedule(key: bytes, length: int):
    s0 = 0x243F6A88
    s1 = 0x85A308D3
    s2 = 0x13198A2E
    s3 = 0x03707344 ^ length

    for i, c in enumerate(key):
        s0 = u32(rol32(s0 ^ u32(c + s3), 5) + 0x9E3779B9)
        s1 = u32(rol32(u32(s1 + (s0 ^ u32(c * 0x45))), 7) ^ 0xA5A5A5A5)
        s2 = u32((s2 ^ u32(s1 + c + i)) * 0x27D4EB2D)
        s3 = u32(rol32(u32(s3 + s2 + (c << 1)), 13) ^ s0)

    s0 = u32(s0 ^ u32(length * 0x9E3779B1))
    s1 = u32(s1 + rol32(length ^ 0xA55AA55A, 11))
    s2 = u32(s2 ^ rol32(u32(s0 + s3), 17))
    s3 = u32(s3 + rol32(s1 ^ s2, 3))

    for i in range(6):
        mixed = u32(s0 ^ rol32(s1, 9) ^ rol32(s2, 17) ^ rol32(s3, 23))

        old_s1 = s1
        old_s2 = s2
        old_s3 = s3

        s0 = u32(old_s1 + 0x9E3779B9 + i)
        s1 = u32(old_s2 ^ rol32(mixed, 3))
        s2 = u32(old_s3 + rol32(s0, 7))
        s3 = u32(mixed ^ rol32(s2, 11))

    return [s0, s1, s2, s3]

def next_byte(state, index):
    s0, s1, s2, s3 = state

    a = u32(s0 + rol32(s1, 3))
    b = u32(s2 + rol32(s3, 11))
    v = u32(a ^ b ^ u32(index * 0x9E3779B9))

    out = v ^ (v >> 8) ^ (v >> 16) ^ (v >> 24)
    out &= 0xFF

    state[0] = u32(rol32(u32(s0 + s2 + 0x7F4A7C15), 5) ^ s3)
    state[1] = u32(rol32(u32(s1 ^ state[0] ^ 0x6A09E667), 9))
    state[2] = u32(rol32(u32(s2 + state[1] + index), 13) ^ 0xBB67AE85)
    state[3] = u32(rol32(u32((s3 ^ state[2]) ^ u32(v + 0x3C6EF372)), 17))

    return out

def decrypt_region(data: bytes, key: str):
    buf = bytearray(data)
    state = key_schedule(key.encode("ascii"), len(buf))

    for i in range(len(buf)):
        buf[i] ^= next_byte(state, i)

    return bytes(buf)

base_dir = Path(r"...")

input_so = base_dir / "libchecker_patched.so"
output_so = base_dir / "libchecker_patched_nf34.so"

start = 0x2CDC8
end = 0x2CF80
key = "ue7HpQRbn0a30Ic"

so = bytearray(input_so.read_bytes())

enc = bytes(so[start:end])
dec = decrypt_region(enc, key)

if len(dec) != end - start:
    raise ValueError("bad decrypted size")

so[start:end] = dec
output_so.write_bytes(so)

print("[+] patched nf34")
print(f"[+] input : {input_so}")
print(f"[+] output: {output_so}")
print(f"[+] range : 0x{start:X} -> 0x{end:X}")
print(f"[+] size  : 0x{end - start:X}")
print("[+] first 32 decrypted bytes:")
print(dec[:32].hex(" "))
```

Jump tới 0x2CDC8 để tìm nf34 → Đây rồi

![image.png](Images/image%2012.png)

“Tra cứu” thì được logic:

```python

1. Input bắt buộc dài đúng 27 ký tự.

2. Chương trình lấy 3 bảng chính:
   - maze_path_nodes()
   - maze_required_moves()
   - maze_next_table()

3. Khởi tạo runtime:
   - current_node = path_nodes[0]
   - state1 = 0x762509D3
   - state2 = 0x4023CC45
   - state3 = 0

4. Với từng ký tự input[i]:
   - Lấy char = input[i]
   - Tính move = maze_compute_move(char, current_node, state1, i)
   - Lấy next_node = next_table[current_node * 8 + move]

5. Một bước chỉ hợp lệ nếu:
   - current_node == path_nodes[i]
   - move == required_moves[i]
   - next_node == path_nodes[i + 1]

6. Nếu sai bất kỳ điều kiện nào thì return false.

7. Nếu đúng, chương trình gọi:
   maze_update_runtime(runtime, char, next_node, i)

8. Sau 27 ký tự, gọi maze_verify_final(runtime).

9. Flag đúng nếu runtime cuối thỏa:
   - runtime.current_node == 0x22
   - runtime.state1 == 0xF9882DBC
   - runtime.state2 == 0xFD1A9600
   - runtime.state3 == 0x24F218AE
```

→ code solve

```python
#include <bits/stdc++.h>
using namespace std;

typedef unsigned int u32;
typedef unsigned long long u64;

const int TARGET_LEN = 27;
const int SPLIT = 14; // forward brute 0..13, backward brute 14..26

string ALLOWED = "abcdefghijklmnopqrstuvwxyz0123456789_";
string PREFIX = "BKISC{";

int pathv[] = {
    50, 29, 43, 28, 57, 47, 42, 59, 51,
    22, 25, 58, 55, 49, 46, 35, 40, 31,
    62, 7, 61, 15, 19, 32, 38, 10, 30, 34
};

int reqv[] = {
    5, 6, 1, 3, 4, 2, 6, 3, 6,
    5, 1, 1, 0, 3, 6, 0, 2, 5,
    5, 4, 0, 0, 1, 4, 2, 1, 6
};

int ta[] = {
    245, 70, 17, 76, 185, 190, 165, 173,
    250, 197, 99, 181, 103, 85, 1, 219
};

int tb[] = {
    101,108,62,43,200,31,244,102,
    143,114,19,41,228,36,239,138,
    226,170,152,27,147,193,255,150,
    164,131,168,76,222,133,158,250
};

int tc[] = {
    53,207,245,189,131,244,74,66,
    36,177,117,192,224,177,137,116
};

int checkpoint_nodes[] = {43, 42, 59, 35, 40, 19};

u32 checkpoint_tags[] = {
    0x5DF78399u,
    0x3547A1ABu,
    0xCE733EC9u,
    0x57B5AEF9u,
    0xE968D43Fu,
    0x479139C9u
};

const u32 INIT_STATE1  = 0x762509D3u;
const u32 INIT_STATE2  = 0x4023CC45u;
const u32 FINAL_STATE1 = 0xF9882DBCu;
const u32 FINAL_STATE2 = 0xFD1A9600u;
const u32 FINAL_STATE3 = 0x24F218AEu;
const int FINAL_NODE   = 0x22;

struct FwdEntry {
    u64 key;
    u64 pack;
};

bool entry_less(const FwdEntry &a, const FwdEntry &b) {
    if (a.key != b.key) return a.key < b.key;
    return a.pack < b.pack;
}

static inline unsigned char rol8(unsigned char x, int r) {
    return (unsigned char)((x << r) | (x >> (8 - r)));
}

static inline u32 rol32(u32 x, int r) {
    r &= 31;
    return (u32)((x << r) | (x >> (32 - r)));
}

static inline u32 ror32(u32 x, int r) {
    r &= 31;
    return (u32)((x >> r) | (x << (32 - r)));
}

static inline int move_calc(int ch, int cur, u32 s1, int i) {
    unsigned char x = (unsigned char)(
        (ch ^ ta[(cur + i) & 15])
        + ((s1 >> ((i & 3) * 8)) & 255)
        + tb[cur & 31]
    );

    return rol8(x, 3) & 7;
}

static inline u32 upd1(u32 s1, int ch, int nxt, int i) {
    return (u32)(
        (u32)(s1 * 0x83u)
        ^ (u32)(ch + tc[(nxt + i) & 15] + i)
    );
}

static inline u32 upd2(u32 s2, int ch, int nxt, int i) {
    u32 v = (u32)(
        s2
        ^ (u32)(nxt * 0x045D9F3Bu)
        ^ (u32)((ch + i) * 0x9E37u)
    );

    return rol32(v, (ch & 7) + 1);
}

static inline u32 upd3(u32 s3, int nxt, int i) {
    for (int k = 0; k < 6; k++) {
        if (checkpoint_nodes[k] == nxt) {
            return (u32)(s3 ^ rol32(checkpoint_tags[k], i & 7));
        }
    }

    return s3;
}

u32 inv83;

u32 invmod_odd32(u32 a) {
    u64 x = 1;

    for (int i = 0; i < 6; i++) {
        x = x * (2 - (u64)a * x);
    }

    return (u32)x;
}

static inline u32 prev1(u32 s1_next, int ch, int nxt, int i) {
    u32 t = (u32)(ch + tc[(nxt + i) & 15] + i);
    return (u32)((u64)(s1_next ^ t) * inv83);
}

static inline u32 prev2(u32 s2_next, int ch, int nxt, int i) {
    u32 v = ror32(s2_next, (ch & 7) + 1);

    v ^= (u32)(nxt * 0x045D9F3Bu);
    v ^= (u32)((ch + i) * 0x9E37u);

    return v;
}

static inline u64 keypair(u32 s1, u32 s2) {
    return (((u64)s1) << 32) | (u64)s2;
}

vector<int> chars_at(int i) {
    vector<int> out;

    if (i < 6) {
        out.push_back((unsigned char)PREFIX[i]);
        return out;
    }

    if (i == 26) {
        out.push_back((unsigned char)'}');
        return out;
    }

    for (int j = 0; j < (int)ALLOWED.size(); j++) {
        out.push_back((unsigned char)ALLOWED[j]);
    }

    return out;
}

struct FState {
    u32 s1;
    u32 s2;
    u64 pack;
};

vector<FwdEntry> front;

void build_front() {
    vector<FState> cur;
    vector<FState> nxt;

    FState init;
    init.s1 = INIT_STATE1;
    init.s2 = INIT_STATE2;
    init.pack = 0;
    cur.push_back(init);

    for (int i = 0; i < SPLIT; i++) {
        nxt.clear();

        vector<int> cs = chars_at(i);
        int cur_node = pathv[i];
        int next_node = pathv[i + 1];

        for (size_t si = 0; si < cur.size(); si++) {
            u32 s1 = cur[si].s1;
            u32 s2 = cur[si].s2;
            u64 pack = cur[si].pack;

            for (int ci = 0; ci < (int)cs.size(); ci++) {
                int ch = cs[ci];

                if (move_calc(ch, cur_node, s1, i) != reqv[i]) {
                    continue;
                }

                u64 npack = pack;

                if (i >= 6) {
                    npack |= ((u64)ci) << (6 * (i - 6));
                }

                FState ns;
                ns.s1 = upd1(s1, ch, next_node, i);
                ns.s2 = upd2(s2, ch, next_node, i);
                ns.pack = npack;

                nxt.push_back(ns);
            }
        }

        cerr << "front " << setw(2) << (i + 1)
             << " states=" << nxt.size() << "\n";

        cur.swap(nxt);
    }

    front.reserve(cur.size());

    for (size_t i = 0; i < cur.size(); i++) {
        FwdEntry e;
        e.key = keypair(cur[i].s1, cur[i].s2);
        e.pack = cur[i].pack;
        front.push_back(e);
    }

    cerr << "[+] sorting front...\n";
    sort(front.begin(), front.end(), entry_less);
    cerr << "[+] front total=" << front.size() << "\n";
}

string make_front_string(u64 pack) {
    string s = "BKISC{";

    for (int pos = 6; pos < SPLIT; pos++) {
        int idx = (int)((pack >> (6 * (pos - 6))) & 63);
        s.push_back(ALLOWED[idx]);
    }

    return s;
}

bool verify_full(const string &flag, bool verbose) {
    if ((int)flag.size() != TARGET_LEN) {
        if (verbose) cout << "bad len\n";
        return false;
    }

    u32 s1 = INIT_STATE1;
    u32 s2 = INIT_STATE2;
    u32 s3 = 0;
    int cur = pathv[0];

    for (int i = 0; i < TARGET_LEN; i++) {
        int ch = (unsigned char)flag[i];

        int mv = move_calc(ch, cur, s1, i);

        if (mv != reqv[i]) {
            if (verbose) {
                cout << "move fail i=" << i
                     << " ch=" << flag[i]
                     << " got=" << mv
                     << " expected=" << reqv[i] << "\n";
            }
            return false;
        }

        int nxt = pathv[i + 1];

        s1 = upd1(s1, ch, nxt, i);
        s2 = upd2(s2, ch, nxt, i);
        s3 = upd3(s3, nxt, i);
        cur = nxt;
    }

    if (verbose) {
        cout << "node   = 0x" << hex << uppercase << cur << dec << "\n";
        cout << "state1 = 0x" << hex << uppercase << s1 << dec << "\n";
        cout << "state2 = 0x" << hex << uppercase << s2 << dec << "\n";
        cout << "state3 = 0x" << hex << uppercase << s3 << dec << "\n";
    }

    return (
        cur == FINAL_NODE
        && s1 == FINAL_STATE1
        && s2 == FINAL_STATE2
        && s3 == FINAL_STATE3
    );
}

bool found = false;
long long back_nodes = 0;

void try_meet(u32 s1, u32 s2, const string &suffix) {
    u64 k = keypair(s1, s2);

    FwdEntry target;
    target.key = k;
    target.pack = 0;

    vector<FwdEntry>::iterator it = lower_bound(
        front.begin(),
        front.end(),
        target,
        entry_less
    );

    while (it != front.end() && it->key == k) {
        string cand = make_front_string(it->pack) + suffix;

        if (verify_full(cand, false)) {
            cout << "\nFOUND " << cand << "\n";
            verify_full(cand, true);
            found = true;
            return;
        }

        ++it;
    }
}

void dfs_back(int i, u32 s1_next, u32 s2_next, string suffix) {
    if (found) return;

    back_nodes++;

    if ((back_nodes % 10000000LL) == 0) {
        cerr << "[+] back nodes=" << back_nodes
             << " i=" << i
             << " suffix_len=" << suffix.size() << "\n";
    }

    if (i < SPLIT) {
        try_meet(s1_next, s2_next, suffix);
        return;
    }

    vector<int> cs = chars_at(i);

    int cur_node = pathv[i];
    int next_node = pathv[i + 1];

    for (int ci = 0; ci < (int)cs.size(); ci++) {
        int ch = cs[ci];

        u32 ps1 = prev1(s1_next, ch, next_node, i);

        if (move_calc(ch, cur_node, ps1, i) != reqv[i]) {
            continue;
        }

        u32 ps2 = prev2(s2_next, ch, next_node, i);

        string nsuffix;
        nsuffix.reserve(suffix.size() + 1);
        nsuffix.push_back((char)ch);
        nsuffix += suffix;

        dfs_back(i - 1, ps1, ps2, nsuffix);

        if (found) return;
    }
}

u32 compute_state3_only() {
    u32 s3 = 0;

    for (int i = 0; i < TARGET_LEN; i++) {
        int nxt = pathv[i + 1];
        s3 = upd3(s3, nxt, i);
    }

    return s3;
}

int main() {
    inv83 = invmod_odd32(0x83u);

    cout << "[+] checking state3 path-only\n";
    u32 s3 = compute_state3_only();
    cout << "state3 = 0x" << hex << uppercase << s3 << dec << "\n";

    if (s3 != FINAL_STATE3) {
        cout << "[-] state3 mismatch, checkpoint tables/final constants wrong\n";
        return 0;
    }

    cout << "[+] building front split=" << SPLIT << "\n";
    build_front();

    cout << "[+] backward search\n";
    dfs_back(TARGET_LEN - 1, FINAL_STATE1, FINAL_STATE2, "");

    if (!found) {
        cout << "not found\n";
        cout << "[!] N?u không ra, th? d?i SPLIT = 13 ho?c 15.\n";
        cout << "[!] Nhung b?n này không hardcode flag và dã s?a l?i pack suffix.\n";
    }

    return 0;
}
```

![image.png](Images/image%2013.png)

<aside>
💡

Flag: BKISC{4nd0rid_m4z3_s0lving}

</aside>

# THCON

## OSint:

1. THC{7h47_br1d63_15_50_5k1b1d1} - Pont d'Aquitaine

3. THC{h16hw4y5_4r3_50_0h10}

## RE:

### Silent signed:

S.N.A.F.U. agents recovered sst-fwsign from a compromised workstation inside the SST Dynamics factory. It appears to be part of the firmware signing pipeline that M4terM4xima uses to flash compromised firmware onto the robots. Our field analysts tried attaching a debugger: each time, the validation fails. Reverse the binary and recover the signing token it accepts.

N.B.: The binary requires root privileges but is harmless. If you're not comfortable running it as root, use a VM.

đề cho 1 file elf

![image.png](Images/image%2014.png)

![image.png](Images/image%2015.png)

Vào hàm main ta thấy nó chạy sub403E70 trước để check input.

Vào đó ta thấy độ dài flag là 48, chia thành 6 block 8 bytes để thực hiện xor

nhưng lại thấy trong hàm mà tưởng là verify giá trị thì lại không thực hiện mà chỉ là trap

![image.png](Images/image%2016.png)

→ Không hề thay đổi giá trị của v1 nên lúc đầu mình nghĩ là vô hạn. Tra AI thì biết mấu chốt là ở cái debugbreak() kia:

<aside>
💡

Nó tạo breakpoint `int3`. Khi child trap, parent process bắt bằng `ptrace`.

Vì vậy attach debugger ngoài sẽ fail hoặc phá flow, vì binary tự debug chính nó

</aside>

Nhìn trước hàm main có hàm tạo VM (mình tra AI)

![image.png](Images/image%2017.png)

Nó có đoạn code sau:

```python
for ( i = 0; ; i = BYTE1(v27) )
          {
            ptrace(PTRACE_CONT, v7, 0, i);
            if ( waitpid(v7, &v27, 0) <= 0 || (v27 & 0x7F) == 0 || (char)((v27 & 0x7F) + 1) > 1 )
            {
              waitpid(v7, 0, 0);
              sub_411F30(v4);
              exit(0);
            }
            if ( (_BYTE)v27 != 127 )
              goto LABEL_15;
            if ( BYTE1(v27) == 5 )
              break;
          }
          ptrace(PTRACE_GETREGS, v7, 0, v39);
          v28 = 0;
          v32[0] = v41;
          v32[1] = v43;
          v32[2] = v44;
          sub_405360(v15, &v28, v32, 0);
          nullsub_1(v16, &v28, &v30);
          v30 = 0;
          sub_4053E0();
          ptrace(PTRACE_POKEDATA, v7, &qword_45E218, v30);
        }
      }
```

dịch ra là lấy giá trị thanh ghi từ tiến trình con: 

```python
ptrace(PTRACE_GETREGS, child, 0, regs);
...
v32[0] = regs->rax;   // rsi value được copy vào rax trong sub_403E60
v32[1] = regs->r12;   // block index / command
v32[2] = regs->rdx;   // accumulator trước đó
```

rồi ghi vào eBPF map

```python
bpf_map_update_elem(fw_inbox, &key, v32, 0);
```

sau đấy đọc output:

```python
bpf_map_lookup_elem(fw_outbox, &key, &v30);
```

và ghi ngược lại vào child process:

```python
ptrace(PTRACE_POKEDATA, child, &qword_45E218, v30);
```

dumb byte có dữ liệu ebp bị xor

![image.png](Images/image%2018.png)

mình dumb xong cop hết ra txt rồi dùng code này (đừng như mình, cách này rất dốt)

có thể dùng code dưới đây vào ida:

```python
import re
from pathlib import Path

XOR_KEY = 0xAA21E1B24B0BCDEF.to_bytes(8, "little")

def parse_num(x):
    x = x.strip()
    if x.endswith("h"):
        return int(x[:-1], 16)
    return int(x, 0)

def parse_ida_db(text):
    out = bytearray()

    for line in text.splitlines():
        if " db " not in line:
            continue

        data = line.split(" db ", 1)[1].split(";", 1)[0]

        for part in data.split(","):
            part = part.strip()
            if not part:
                continue

            m = re.fullmatch(r"(\d+)\s+dup\(([^)]+)\)", part)
            if m:
                out.extend([parse_num(m.group(2))] * int(m.group(1)))
            else:
                out.append(parse_num(part))

    return bytes(out)

raw = parse_ida_db(Path("byte_4553C0.txt").read_text())
decoded = bytes(b ^ XOR_KEY[i & 7] for i, b in enumerate(raw))

Path("fw.o").write_bytes(decoded)
print(decoded[:4])
```

xem nội dung file fw.o thấy hàm chính cần quan tâm là fw_verify, có intergrity_watch để tránh hook syscall ptrace vào (anti_debug)

![image.png](Images/image%2019.png)

disasm cái fw.o ra

```python
llvm-objdump -d -r fw.o > fw_disasm.txt
```

![image.png](Images/image%2020.png)

pseudo và giải thích do Mr.GPT cung cấp:

```python
int fw_verify()
{
    in  = map_lookup(fw_inbox, 0);
    out = map_lookup(fw_outbox, 0);
    seq = map_lookup(fw_seq, 0);

    val  = in[0];   // ROL64(token_qword ^ key[i], 7)
    cmd  = in[1];   // block index, hoặc 0xff
    prev = in[2];   // accumulator

    if (cmd == 0xff) {
        if (val == 0xaaf62074aad3ee0e && seq[0] == 6)
            out[0] = 1;
        else
            out[0] = 0;

        return 0;
    }

    if (cmd > 5) {
        out[0] = 0;
        return 0;
    }

    kdf = map_lookup(fw_kdf, cmd);

    result = ROL64(kdf[0] * (prev ^ val), 13);

    expected[0] = 0x66185fcb3af43c42;
    expected[1] = 0xfb9181fc9d741ac9;
    expected[2] = 0xf6f76d94d5f19c7c;
    expected[3] = 0x9623be0fa7985447;
    expected[4] = 0xc801d5b2ee724650;
    expected[5] = 0x9faaf86a914846ee;

    if (result == expected[cmd]) {
        out[0] = expected[cmd];
        seq[0]++;
    } else {
        out[0] = 0;
    }

    return 0;
}
/*
fw_verify không trực tiếp check token ASCII.
Nó chỉ check giá trị đã được native transform:

    val = ROL64(token_qword ^ qword_448940[i], 7)

Sau đó dùng KDF:

    result = ROL64(fw_kdf[i] * (prev ^ val), 13)

Nếu result khớp target[i], verifier trả target[i].
Child XOR các target lại thành accumulator.
Final check yêu cầu accumulator == 0xaaf62074aad3ee0e.

*/
```

Code solve:

```python
import struct

MASK64 = 0xFFFFFFFFFFFFFFFF

def rol64(x: int, n: int) -> int:
    n &= 63
    return ((x << n) | (x >> (64 - n))) & MASK64

def ror64(x: int, n: int) -> int:
    n &= 63
    return ((x >> n) | (x << (64 - n))) & MASK64

def qwords(hex_string: str) -> tuple[int, ...]:
    return struct.unpack("<6Q", bytes.fromhex(hex_string))

key_hex = """
72 F3 6E 3C 3A F5 4F A5
7F 52 0E 51 8C 68 05 9B
19 CD E0 5B AB D9 83 1F
67 E6 09 6A 85 AE 67 BB
1B 09 B1 58 A5 DB B5 E9
98 2F 8A 42 91 44 37 71
"""

kdf_hex = """
43 01 BB 07 2E 27 62 6C
7D 47 F8 69 C0 9A 3D 29
6D 0C E9 34 CF 66 54 BE
89 6C 4E EC 98 FA 2E 08
77 13 D0 38 E6 21 28 45
1B FB 79 89 D9 D5 16 92
"""

keys = qwords(key_hex)
kdfs = qwords(kdf_hex)

targets = [
    0x66185fcb3af43c42,
    0xfb9181fc9d741ac9,
    0xf6f76d94d5f19c7c,
    0x9623be0fa7985447,
    0xc801d5b2ee724650,
    0x9faaf86a914846ee,
]

acc = 0
token = bytearray()

for i in range(6):
    inv = pow(kdfs[i], -1, 1 << 64)
    x = (ror64(targets[i], 13) * inv) & MASK64
    rsi = acc ^ x
    block = ror64(rsi, 7) ^ keys[i]
    token += struct.pack("<Q", block)
    acc ^= targets[i]

print(token.decode())
```

<aside>
💡

Flag: THC{int3_s3nt_u_h3r3_3bpf_t00k_1t_fr0m_th3r3!!!}

</aside>

### neo_pwned_you

Dùng AI vào hàm main đọc thì thấy hai phần đáng chú ý là đây

![image.png](Images/image%2021.png)

![image.png](Images/image%2022.png)

Để vào được nhánh thật kia thì cần đổi tên file thành thcity.exe và có thêm file matrix.txt nội dung “neo”

Nhờ AI dump VM .NET của nhánh chính ra (cheat tí tại x64dbg không ra =)))) )

Mình dump bằng cách tái tạo đoạn decrypt trong `sub_140003980`: lấy blob từ `unk_140027B80`, sinh key 32 byte bằng LCG, rồi XOR tuần hoàn 32 byte để ra PE bắt đầu bằng `MZ`. Phần loader CLR/.NET đúng như đoạn decompile đã chỉ ra ở `Src = v16; Size = 128000; sub_140003560();`

![image.png](Images/image%2023.png)

đọc bằng dnSpy ta được

![image.png](Images/image%2024.png)

→ có 2 hàm validator rất khả nghi

Trong `Program.Main`, chương trình đọc input từ console rồi gọi trực tiếp: Program.ShowResult(PayloadEncoder.EncodePayload(text), num);

→ Nghĩa là validator thật nằm ở `PayloadEncoder.EncodePayload`, không phải ở native nữa. `Program.Main()` đọc input rồi truyền thẳng sang `PayloadEncoder.EncodePayload(text)`

À lưu ý là phải patch Selfdelete() trong main để nó không tự xóa file.

Trong `PayloadEncoder.EncodePayload`, điều kiện đầu tiên là input_len=31

```python
if (input == null || Encoding.UTF8.GetByteCount(input) != 31)
{
    return false;
}

```

DÙng AI đọc thì thấy phần hàm cryptovalidation chủ yếu là anti-analysis/noise. Logic thật nằm ở đoạn tạo `_chain`:

```python
PayloadEncoder._chain = SignalProcessor.DecryptBlock(PayloadEncoder.GenerateChecksum());
result = PayloadEncoder._chain(bytes);
```

Check GenerateChecksum() thì thấy nó có nhiều hàm setup môi trường, patch hết về return 0

```python
MeasureEntropy()
InputValidator.ProbeIntegrity()
CalibrateEncoder()
InputValidator.MeasureGcmThroughput()
InputValidator.PrefetchRoundKeys()
IntegrityBridge.MeasureL1DWarmup()
```

patch tiếp hàm main để nó in ra giá trị của Generate đấy luôn ra được file bin dưới

```python
byte[] sig = (byte[])typeof(PayloadEncoder).GetMethod(
    "GenerateChecksum",
    System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic
).Invoke(null, null);

System.IO.File.WriteAllBytes("signalData.bin", sig);
```

![image.png](Images/image%2025.png)

Lại dùng AI đọc thì thấy hàm DecryptBlock là VM Runtime (logic chính của ctrinh)

![image.png](Images/image%2026.png)

patch để hàm đó:

- Copy `signalData`.
- Pre-scan label target của `OPS_NOP`.
- Chạy từng opcode như VM gốc.
- Log `STORE`, `EQ`, `local`, `expected`, `local2`.
- Bypass `OPS_TRAP` để không fail khi debug.
- Ghi ra `vmtrace.txt`

cuối cùng prompt code để brute các kí tự từ 0→255 (31 kí tự) (Code dưới có gộp cả nội dung file bin nên dài nhé)

```python
#!/usr/bin/env python3
"""
Clean SignalProcessor VM solver for NethereumVM.

Usage with a dumped signalData.bin:
  python vm_solve_clean.py --signal signalData.bin --signal-cs "Pasted text(54).txt" --auto-bias --full-byte

Usage rebuilding GenerateChecksum() from the dumped .NET assembly:
  python vm_solve_clean.py --bin NethereumVM_dump.exe --signal-cs "Pasted text(54).txt" --probe 0 --auto-bias --full-byte
  python vm_solve_clean.py --bin NethereumVM_dump.exe --signal-cs "Pasted text(54).txt" --all-probes --auto-bias --full-byte

What it does:
- Parses _sMatrix, _rMatrix and _scratchInit from the decompiled SignalProcessor text.
- Optionally extracts PayloadEncoder._coefficients from the .NET dump and rebuilds GenerateChecksum().
- Parses and emulates SignalProcessor.DecryptBlock() bytecode.
- Solves the byte constraints created by OPS_STORE ... OPS_EQ using DFS/backtracking.
"""
from __future__ import annotations
import argparse, re, struct, string
from pathlib import Path
from collections import Counter

OPS = {
 'OPS_ADD':0x00,'OPS_MOV':0x01,'OPS_SHR':0x02,'OPS_AND':0x03,'OPS_OR':0x04,'OPS_INC':0x05,'OPS_NEG':0x06,'OPS_DEC':0x07,
 'OPS_ROR':0x08,'OPS_DIV':0x09,'OPS_MOD':0x0A,'OPS_ADDC':0x0B,'OPS_ROL':0x0C,'OPS_SUBC':0x0D,'OPS_SUB':0x0E,'OPS_REV_BITS':0x0F,
 'OPS_POP':0x10,'OPS_PUSH':0x11,'OPS_RAND':0x12,'OPS_HASH':0x13,'OPS_XOR_55':0x14,'OPS_ADD_AA':0x15,'OPS_ROL3':0x16,'OPS_NOP':0x17,
 'OPS_NOP_DBG':0x18,'OPS_BREAK':0x19,'OPS_CALL':0x1A,'OPS_RET':0x1B,'OPS_TRAP':0x1C,'OPS_LOOP':0x1D,'OPS_FAULT':0x1E,'OPS_ADDI':0x1F,
 'OPS_STORE':0x20,'OPS_AND_IMM':0x21,'OPS_SUB_IMM':0x22,'OPS_ROL_2':0x23,'OPS_INV_SBOX_ADD':0x24,'OPS_INV_SBOX_XOR':0x25,
 'OPS_FWD_SBOX':0x26,'OPS_INV_SBOX':0x27,'OPS_ADD_DERIVED':0x28,'OPS_RBIT':0x29,'OPS_SBOX_ALT':0x2A,'OPS_ADD_K':0x2B,
 'OPS_SUB_K':0x2C,'OPS_XOR_K':0x2D,'OPS_KDF':0x2E,'OPS_DECRYPT':0x2F,'OPS_ENCRYPT':0x30,'OPS_ADD_XOR':0x31,
 'OPS_DIV_XOR':0x32,'OPS_TEST':0x33,'OPS_EQ':0x34,'OPS_LT':0x35,'OPS_DIV_XOR_13':0x36,'OPS_VERIFY':0x37,'OPS_DIV11':0x38,
 'OPS_ID':0x39,'OPS_NEG_ID':0x3A,'OPS_SUBI':0x3B,'OPS_ROLI':0x3C,'OPS_HALT':0x3D,'OPS_YIELD':0x3E,
}
NAMES = {v:k for k,v in OPS.items()}
SBOX=[]; RBOX=[]; SCRATCH_INIT=[]; COEFF=[]

def parse_array(src: str, name: str) -> list[int]:
    m = re.search(r'%s\s*=\s*new byte\[\]\s*\{(.*?)\};' % re.escape(name), src, re.S)
    if not m: raise SystemExit(f'cannot find {name}')
    out=[]
    for tok in re.findall(r'byte\.MaxValue|\b\d+\b', m.group(1)):
        v = 255 if tok == 'byte.MaxValue' else int(tok)
        if 0 <= v <= 255: out.append(v)
    return out

def rd32(data: bytes, off: int) -> int:
    return struct.unpack_from('<i', data, off)[0]

def imm_size(op: int) -> int:
    # Execution-time immediates, from each switch case that calls ReadCiphertext().
    return 4 if op in {
        0,1,2,3,4,8,11,12,13,14,23,24,25,26,29,31,32,33,34,35,
        36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,
        55,56,59,60
    } else 0

def scan_size(op: int) -> int:
    # Port of SignalProcessor.GetBlockSize(); used only to predefine NOP branch labels.
    if op in {5,6,7,9,10,15,16,17,18,19,20,21,22,27,28,30}: return 0
    if op in {8,11,12,13,14,23,24,25,26,29}: return 4
    if (op - 57 > 1) and (op - 61 > 1): return 4
    return 0

def parse_instrs(sig: bytes):
    out=[]; j=0
    while j < len(sig):
        off=j; op=sig[j]; j+=1; arg=None
        if imm_size(op):
            if j+4>len(sig): break
            arg=rd32(sig,j); j+=4
        out.append((off,op,arg))
    return out

def trace_path(sig: bytes):
    instrs=parse_instrs(sig)
    by_off={off:(off,op,arg) for off,op,arg in instrs}
    next_off={a[0]:b[0] for a,b in zip(instrs,instrs[1:])}
    labels=set(); i=0
    while i < len(sig):
        b=sig[i]; i += 1; bs=scan_size(b)
        if b == OPS['OPS_NOP'] and bs == 4 and i+3 < len(sig): labels.add(rd32(sig,i))
        i += bs
    path=[]; pc=0
    for _ in range(300000):
        if pc not in by_off: break
        off,op,arg=by_off[pc]; path.append((off,op,arg))
        if op == OPS['OPS_YIELD']: break
        if op == OPS['OPS_NOP'] and arg in labels: pc=arg
        else: pc=next_off.get(pc,-1)
    return path

def ror8(x,n): n &= 7; return ((x>>n)|(x<<(8-n)))&255 if n else x&255
def rol8(x,n): n &= 7; return ((x<<n)|(x>>(8-n)))&255 if n else x&255

def apply_op(op,arg,st,inp):
    local,local2,local3,scratch,signal_bias=st; a=0 if arg is None else arg; O=OPS
    if op==O['OPS_ADD']: local=(local-a)&255
    elif op==O['OPS_MOV']: local=(local^a)&255
    elif op==O['OPS_SHR']: n=a&7; local=rol8(local, 2 if n==0 else n)
    elif op==O['OPS_AND']: local=(local^((a*55+185)&255))&255
    elif op==O['OPS_OR']: local=(local+((a*19+127)&255))&255
    elif op==O['OPS_INC']: local=(local-1)&255
    elif op==O['OPS_NEG']: local=(~local)&255
    elif op==O['OPS_DEC']: local=(local+1)&255
    elif op==O['OPS_ROR']: n=a&7; local=rol8(local, 1 if n==0 else n)
    elif op==O['OPS_DIV']: local=(local*(3+signal_bias))&255
    elif op==O['OPS_MOD']: local=(local*7)&255
    elif op==O['OPS_ADDC']: local=(local-((a*91+35)&255))&255
    elif op==O['OPS_ROL']: n=a&7; local=ror8(local, 1 if n==0 else n)
    elif op==O['OPS_SUBC']: local=(local+((a*158+71)&255))&255
    elif op==O['OPS_SUB']: local=(local+a)&255
    elif op==O['OPS_REV_BITS']: local=((local>>4)|(local<<4))&255
    elif op==O['OPS_POP']: local3=local
    elif op==O['OPS_PUSH']: local=(local^local3)&255
    elif op==O['OPS_RAND']: local=(local*5)&255
    elif op==O['OPS_HASH']: local=(local*9)&255
    elif op==O['OPS_XOR_55']: local=(local+85)&255
    elif op==O['OPS_ADD_AA']: local=(local^170)&255
    elif op==O['OPS_ROL3']: local=ror8(local,3)
    elif op==O['OPS_NOP']: pass
    elif op==O['OPS_NOP_DBG']:
        idx=(local^(a&255))&255; v=scratch[idx]; local=(local+v)&255; scratch[idx]=(v^local)&255
    elif op==O['OPS_BREAK']:
        idx=(local^(a&255))&255; v=scratch[idx]; local=(local^v)&255; scratch[(idx+1)&255]=(v+local+1)&255
    elif op in (O['OPS_CALL'],O['OPS_LOOP'],O['OPS_VERIFY'],O['OPS_TEST'],O['OPS_HALT'],O['OPS_TRAP']): pass
    elif op==O['OPS_RET']: local=(local+local3)&255
    elif op==O['OPS_FAULT']: local=((local^local3)^255)&255
    elif op==O['OPS_ADDI']: local=(local-(a&255))&255
    elif op==O['OPS_STORE']:
        if not 0 <= a < len(inp): raise IndexError(f'input[{a}]')
        local=inp[a]
    elif op==O['OPS_AND_IMM']: local=(local^((a*3+7)&255))&255
    elif op==O['OPS_SUB_IMM']: local=(local+((a^165)&255))&255
    elif op==O['OPS_ROL_2']:
        n=a&7; local=ror8(local, 2 if n==0 else n)
    elif op==O['OPS_INV_SBOX_ADD']: local=SBOX[(local+(a&255))&255]
    elif op==O['OPS_INV_SBOX_XOR']: local=SBOX[(local^(a&255))&255]
    elif op==O['OPS_FWD_SBOX']: local=RBOX[local&255]
    elif op==O['OPS_INV_SBOX']: local=SBOX[local&255]
    elif op==O['OPS_ADD_DERIVED']: local=(local^((a*158)&255))&255
    elif op==O['OPS_RBIT']: local=(((local>>4)|(local<<4))&255)^(a&255)
    elif op==O['OPS_SBOX_ALT']: local=(ror8(local,1)+(a&255))&255
    elif op==O['OPS_ADD_K']: local=(local-((a*55)&255))&255
    elif op==O['OPS_SUB_K']: local=(local^((a*158+183)&255))&255
    elif op==O['OPS_XOR_K']: local=(local+((a^54)&255))&255
    elif op==O['OPS_KDF']: local=(local*19+(a&255))&255
    elif op==O['OPS_DECRYPT']: local=SBOX[(local+(a&255))&255]
    elif op==O['OPS_ENCRYPT']: local=RBOX[(local^(a&255))&255]
    elif op==O['OPS_ADD_XOR']: local=((local-a)^90)&255
    elif op==O['OPS_DIV_XOR']: local=(((local^a)&255)*11)&255
    elif op==O['OPS_EQ']: local2 |= (local^a)  # arg is expected to be 0..255; no low-byte truncation in real IL
    elif op==O['OPS_LT']: local=(local+a)&255
    elif op==O['OPS_DIV_XOR_13']: local=(((local^a)&255)*13)&255
    elif op==O['OPS_DIV11']: local=((local+(local3&15))^(a&255))&255
    elif op==O['OPS_ID']: local=(local*11+7)&255
    elif op==O['OPS_NEG_ID']: local=(local^255)&255
    elif op==O['OPS_SUBI']: local=(local+(a&63))&255
    elif op==O['OPS_ROLI']: local=ror8(local,(a&3)+1)
    elif op==O['OPS_YIELD']: pass
    else: pass
    return [local,local2,local3,scratch,signal_bias]

def crc8_step(b):
    for _ in range(8): b=((b>>1)^0x8c)&255 if b&1 else (b>>1)&255
    return b

def extract_coefficients(pe: bytes, length=12065):
    sig=bytes([147,236,179,46,203,14,189,214,94,161,42,234,6,251,6,180])
    off=pe.find(sig)
    if off<0: raise SystemExit('cannot find _coefficients blob')
    return list(pe[off:off+length])

def generate_signal(probe_xor):
    b7=255
    for i in range(34): b7=crc8_step(b7^COEFF[i])
    b9=b7^(probe_xor&255)
    arr=[]; b10=b9
    for c in COEFF:
        arr.append((c^b10)&255); b10=(b10*3+23)&255
    num=0xDEAD
    for i,x in enumerate(arr):
        b11=(x^((num>>8)&255))&255; arr[i]=b11; num=((num+b11)*34661+17185)&0xffff
    return bytes(arr)

def stats(sig):
    path=trace_path(sig); stores=[a for _,op,a in path if op==OPS['OPS_STORE']]; eqs=[a for _,op,a in path if op==OPS['OPS_EQ']]
    c=Counter(NAMES.get(op,hex(op)) for _,op,_ in path)
    print(f'  signal={len(sig)} bytes path={len(path)} last={NAMES.get(path[-1][1],hex(path[-1][1])) if path else None} STORE={len(stores)} EQ={len(eqs)}')
    bad=[x for x in stores if x is None or not 0<=x<31]
    if bad: print('  bad STORE indexes:', bad[:8])
    print('  top ops:', ', '.join(f'{k}:{v}' for k,v in c.most_common(10)))

def solve(sig, input_len, charset, signal_bias, verbose=False):
    path=trace_path(sig); assign=[None]*input_len; init=[0,0,0,SCRATCH_INIT[:],signal_bias]; calls=0; maxdepth=0
    def cur(a): return bytes(x if x is not None else 0 for x in a)
    def rec(ip,st,a,depth):
        nonlocal calls,maxdepth
        calls+=1; maxdepth=max(maxdepth,depth)
        while ip < len(path):
            off,op,arg=path[ip]
            if op==OPS['OPS_YIELD']:
                return bytes(x if x is not None else ord('?') for x in a) if st[1]==0 else None
            if op==OPS['OPS_EQ']:
                if st[0] != arg: return None
                ip += 1; continue
            if op==OPS['OPS_STORE']:
                idx=arg
                if not 0 <= idx < input_len: return None
                if a[idx] is not None:
                    st=apply_op(op,arg,st,cur(a)); ip+=1; continue
                for ch in charset:
                    na=a[:]; na[idx]=ch
                    ns=[st[0],st[1],st[2],st[3][:],st[4]]
                    ns=apply_op(op,arg,ns,cur(na))
                    out=rec(ip+1,ns,na,depth+1)
                    if out is not None: return out
                return None
            try: st=apply_op(op,arg,st,cur(a))
            except Exception: return None
            ip += 1
        return None
    res=rec(0,init,assign,0)
    if verbose: print(f'  dfs calls={calls} maxdepth={maxdepth}')
    return res

def verify(sig,candidate,bias):
    st=[0,0,0,SCRATCH_INIT[:],bias]
    for _,op,arg in trace_path(sig):
        if op==OPS['OPS_YIELD']: return st[1]==0
        st=apply_op(op,arg,st,candidate)
    return False

# ===== Embedded clean VM data; no external signal/cs files needed =====
import base64, zlib
EMBEDDED_SIGNAL_SHA256 = '9256c5f82a4e3e5687092ce2ea1ab43fae8966db3f3ac11154939c639d76d82a'
EMBEDDED_SIGNAL_ZLIB_B64 = (
    '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'
)

EMBEDDED_SBOX = [99,
 124,
 119,
 123,
 242,
 107,
 111,
 197,
 48,
 1,
 103,
 43,
 254,
 215,
 171,
 118,
 202,
 130,
 201,
 125,
 250,
 89,
 71,
 240,
 173,
 212,
 162,
 175,
 156,
 164,
 114,
 192,
 183,
 253,
 147,
 38,
 54,
 63,
 247,
 204,
 52,
 165,
 229,
 241,
 113,
 216,
 49,
 21,
 4,
 199,
 35,
 195,
 24,
 150,
 5,
 154,
 7,
 18,
 128,
 226,
 235,
 39,
 178,
 117,
 9,
 131,
 44,
 26,
 27,
 110,
 90,
 160,
 82,
 59,
 214,
 179,
 41,
 227,
 47,
 132,
 83,
 209,
 0,
 237,
 32,
 252,
 177,
 91,
 106,
 203,
 190,
 57,
 74,
 76,
 88,
 207,
 208,
 239,
 170,
 251,
 67,
 77,
 51,
 133,
 69,
 249,
 2,
 127,
 80,
 60,
 159,
 168,
 81,
 163,
 64,
 143,
 146,
 157,
 56,
 245,
 188,
 182,
 218,
 33,
 16,
 255,
 243,
 210,
 205,
 12,
 19,
 236,
 95,
 151,
 68,
 23,
 196,
 167,
 126,
 61,
 100,
 93,
 25,
 115,
 96,
 129,
 79,
 220,
 34,
 42,
 144,
 136,
 70,
 238,
 184,
 20,
 222,
 94,
 11,
 219,
 224,
 50,
 58,
 10,
 73,
 6,
 36,
 92,
 194,
 211,
 172,
 98,
 145,
 149,
 228,
 121,
 231,
 200,
 55,
 109,
 141,
 213,
 78,
 169,
 108,
 86,
 244,
 234,
 101,
 122,
 174,
 8,
 186,
 120,
 37,
 46,
 28,
 166,
 180,
 198,
 232,
 221,
 116,
 31,
 75,
 189,
 139,
 138,
 112,
 62,
 181,
 102,
 72,
 3,
 246,
 14,
 97,
 53,
 87,
 185,
 134,
 193,
 29,
 158,
 225,
 248,
 152,
 17,
 105,
 217,
 142,
 148,
 155,
 30,
 135,
 233,
 206,
 85,
 40,
 223,
 140,
 161,
 137,
 13,
 191,
 230,
 66,
 104,
 65,
 153,
 45,
 15,
 176,
 84,
 187,
 22]

EMBEDDED_RBOX = [82,
 9,
 106,
 213,
 48,
 54,
 165,
 56,
 191,
 64,
 163,
 158,
 129,
 243,
 215,
 251,
 124,
 227,
 57,
 130,
 155,
 47,
 255,
 135,
 52,
 142,
 67,
 68,
 196,
 222,
 233,
 203,
 84,
 123,
 148,
 50,
 166,
 194,
 35,
 61,
 238,
 76,
 149,
 11,
 66,
 250,
 195,
 78,
 8,
 46,
 161,
 102,
 40,
 217,
 36,
 178,
 118,
 91,
 162,
 73,
 109,
 139,
 209,
 37,
 114,
 248,
 246,
 100,
 134,
 104,
 152,
 22,
 212,
 164,
 92,
 204,
 93,
 101,
 182,
 146,
 108,
 112,
 72,
 80,
 253,
 237,
 185,
 218,
 94,
 21,
 70,
 87,
 167,
 141,
 157,
 132,
 144,
 216,
 171,
 0,
 140,
 188,
 211,
 10,
 247,
 228,
 88,
 5,
 184,
 179,
 69,
 6,
 208,
 44,
 30,
 143,
 202,
 63,
 15,
 2,
 193,
 175,
 189,
 3,
 1,
 19,
 138,
 107,
 58,
 145,
 17,
 65,
 79,
 103,
 220,
 234,
 151,
 242,
 207,
 206,
 240,
 180,
 230,
 115,
 150,
 172,
 116,
 34,
 231,
 173,
 53,
 133,
 226,
 249,
 55,
 232,
 28,
 117,
 223,
 110,
 71,
 241,
 26,
 113,
 29,
 41,
 197,
 137,
 111,
 183,
 98,
 14,
 170,
 24,
 190,
 27,
 252,
 86,
 62,
 75,
 198,
 210,
 121,
 32,
 154,
 219,
 192,
 254,
 120,
 205,
 90,
 244,
 31,
 221,
 168,
 51,
 136,
 7,
 199,
 49,
 177,
 18,
 16,
 89,
 39,
 128,
 236,
 95,
 96,
 81,
 127,
 169,
 25,
 181,
 74,
 13,
 45,
 229,
 122,
 159,
 147,
 201,
 156,
 239,
 160,
 224,
 59,
 77,
 174,
 42,
 245,
 176,
 200,
 235,
 187,
 60,
 131,
 83,
 153,
 97,
 23,
 43,
 4,
 126,
 186,
 119,
 214,
 38,
 225,
 105,
 20,
 99,
 85,
 33,
 12,
 125]

EMBEDDED_SCRATCH_INIT = [55,
 213,
 115,
 17,
 175,
 77,
 235,
 137,
 39,
 197,
 99,
 1,
 159,
 61,
 219,
 121,
 23,
 181,
 83,
 241,
 143,
 45,
 203,
 105,
 7,
 165,
 67,
 225,
 127,
 29,
 187,
 89,
 247,
 149,
 51,
 209,
 111,
 13,
 171,
 73,
 231,
 133,
 35,
 193,
 95,
 253,
 155,
 57,
 215,
 117,
 19,
 177,
 79,
 237,
 139,
 41,
 199,
 101,
 3,
 161,
 63,
 221,
 123,
 25,
 183,
 85,
 243,
 145,
 47,
 205,
 107,
 9,
 167,
 69,
 227,
 129,
 31,
 189,
 91,
 249,
 151,
 53,
 211,
 113,
 15,
 173,
 75,
 233,
 135,
 37,
 195,
 97,
 255,
 157,
 59,
 217,
 119,
 21,
 179,
 81,
 239,
 141,
 43,
 201,
 103,
 5,
 163,
 65,
 223,
 125,
 27,
 185,
 87,
 245,
 147,
 49,
 207,
 109,
 11,
 169,
 71,
 229,
 131,
 33,
 191,
 93,
 251,
 153,
 55,
 213,
 115,
 17,
 175,
 77,
 235,
 137,
 39,
 197,
 99,
 1,
 159,
 61,
 219,
 121,
 23,
 181,
 83,
 241,
 143,
 45,
 203,
 105,
 7,
 165,
 67,
 225,
 127,
 29,
 187,
 89,
 247,
 149,
 51,
 209,
 111,
 13,
 171,
 73,
 231,
 133,
 35,
 193,
 95,
 253,
 155,
 57,
 215,
 117,
 19,
 177,
 79,
 237,
 139,
 41,
 199,
 101,
 3,
 161,
 63,
 221,
 123,
 25,
 183,
 85,
 243,
 145,
 47,
 205,
 107,
 9,
 167,
 69,
 227,
 129,
 31,
 189,
 91,
 249,
 151,
 53,
 211,
 113,
 15,
 173,
 75,
 233,
 135,
 37,
 195,
 97,
 255,
 157,
 59,
 217,
 119,
 21,
 179,
 81,
 239,
 141,
 43,
 201,
 103,
 5,
 163,
 65,
 223,
 125,
 27,
 185,
 87,
 245,
 147,
 49,
 207,
 109,
 11,
 169,
 71,
 229,
 131,
 33,
 191,
 93,
 251,
 153]

def main():
    global SBOX, RBOX, SCRATCH_INIT
    SBOX = EMBEDDED_SBOX[:]
    RBOX = EMBEDDED_RBOX[:]
    SCRATCH_INIT = EMBEDDED_SCRATCH_INIT[:]
    sig = zlib.decompress(base64.b64decode(EMBEDDED_SIGNAL_ZLIB_B64))

    import hashlib, string
    h = hashlib.sha256(sig).hexdigest()
    print(f"embedded signal size   : {len(sig)} bytes")
    print(f"embedded signal sha256 : {h}")
    if h != EMBEDDED_SIGNAL_SHA256:
        raise SystemExit("Embedded signal corrupted")

    # Put likely characters first for speed, but -- not a dictionary attack.
    # The solver still falls back to every byte 0..255.
    preferred = (
        b"R3al1ty_D3plnd1_0ncy0ur_Ch01c3s"
        b"THC{thc_flagNEOneoMATRIXmatrix_0123456789"
        b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_:}"
    )
    charset = list(dict.fromkeys(list(preferred) + list(range(256))))

    print()
    stats(sig)
    print("solving...")
    key = solve(sig, input_len=31, charset=charset, signal_bias=0, verbose=True)
    if key is None:
        raise SystemExit("No solution")

    print()
    print("key bytes:", key)
    print("key text :", key.decode("ascii"))
    print("verify   :", verify(sig, key, 0))

if __name__ == "__main__":
    main()

```

![image.png](Images/image%2027.png)

<aside>
💡

Flag: R3al1ty_D3p3nd1_0n_y0ur_Ch01c3s

</aside>

### M4terM4xima’s HINT (1/2)

First of all, fck this chal, cost too much of time.

S.N.A.F.U. agents have recovered this mysterious yet seemingly inoffensive binary... or is it really ?

![image.png](Images/image%2028.png)

Challenge cho một RISC-V ELF tên HINT.elf. Mô tả ctrinh có flag ẩn (chỗ làm t mất thời gian vì nó là part 2 mà giải còn ko ra). Khi phân tích ta thấy main đơn giản chỉ là call vô hạn maybe_HINT:

```python
main:
    addi sp, sp, -0x10
    sw   ra, 0xc(sp)

loop:
    addi a0, sp, 0xb
    call maybe_HINT
    j    loop
```

Trong .rotdata ta thấy chuỗi prompt Are you sure that you are looking for HINT?
và một mảng 20 byte sau:

<aside>
💡

01 1C 0B 38 17 19 1C 49 5A 1F 17 1D 43 0C 4F 17 49 03 01 4E

</aside>

trong maybe_HINT, chươgn trình đọc input rồi áp dụng phép XOR-chain:

```python
prev = 0x55;

for each byte cur in input:
    buf[i] = prev ^ cur;
    prev = cur;
```

sau đấy kiểm tra:

```python
if len(input) == 20 && memcmp(buf, target, 20) == 0:
    print("Congratulation, you just found a HINT");
else:
    print("Are you sure this is a HINT?");
```

Vậy mảng 20 byte kia là output sau khi input bị xor-chain.

Vậy chỉ cần xor ngược lại là được input:

```python
#!/usr/bin/env python3

target = bytes([
    0x01, 0x1c, 0x0b, 0x38, 0x17,
    0x19, 0x1c, 0x49, 0x5a, 0x1f,
    0x17, 0x1d, 0x43, 0x0c, 0x4f,
    0x17, 0x49, 0x03, 0x01, 0x4e,
])

prev = 0x55
out = []

for b in target:
    c = b ^ prev
    out.append(c)
    prev = c

flag = bytes(out)

print(flag)
print(flag.decode())
```

<aside>
💡

Flag: THC{lui zero, ox123}

</aside>