# BÁO CÁO THỰC NGHIỆM PHÂN TÍCH ĐỘNG MÃ ĐỘC (MẪU 1: 123.exe)

**Môn học:** An Toàn Thông Tin / Phân Tích Mã Độc  
**Phương pháp:** Dynamic Analysis kết hợp In-Memory Debugging  
**Đối tượng phân tích:** `123.exe` (APT10 RedLeaves Dropper) và các thành phần liên quan  
**Môi trường thực nghiệm:** Windows 10 x64, VirtualBox Lab cô lập mạng  
**Công cụ sử dụng:** Process Monitor, Sysinternals Autoruns, x32dbg-unsigned, FakeNet-NG 3.5, Wireshark 4.6.9  

---

## 1. SƠ ĐỒ CHUỖI TẤN CÔNG THỰC TẾ (KILL-CHAIN ĐÃ XÁC MINH)

Dựa trên 100% dữ liệu thực nghiệm đã chụp lại trên máy ảo, toàn bộ vòng đời thực thi của Mẫu 1 diễn ra như sau:

```mermaid
flowchart TD
    A["123.exe (Dropper thực thi)"] -->|ProcMon: CreateFile & WriteFile| B["Thả 3 file vào %TEMP%:<br/>- obedience.exe (Host sạch Tsingsoft)<br/>- StarBurn.dll (Proxy DLL mồi)<br/>- handkerchief.dat (Shellcode mã hóa)"]
    A -->|Tạo Persistence| C["Tạo shortcut persuasion.lnk<br/>trong thư mục Startup"]
    A -->|Gọi Sleep 2.1s & Exit| D["123.exe tự kết thúc tiến trình"]

    C -->|Khi Windows khởi động lại| E["Kích hoạt C:\...\Temp\obedience.exe"]
    E -->|DLL Search Order Hijacking| F["Tự nạp StarBurn.dll nằm cùng thư mục"]
    F -->|Thực thi StarBurn_UpStartEx| G["Kiểm tra con trỏ RAM: IsBadWritePtr, IsBadReadPtr"]
    G -->|Cấp phát bộ nhớ ảo| H["Tạo 2 vùng nhớ ERW/RWX:<br/>0x00770000 (4 KB) & 0x02710000 (256 KB)"]
    H -->|Giải mã XOR handkerchief.dat| I["Bung Shellcode nạp hàm Socket mạng (WSARecv)"]
    I -->|Mạng C2 không phản hồi| J["Tiến trình tự hủy (Fail-fast Termination)"]
```

---

## 2. CHI TIẾT BẰNG CHỨNG PHÁP Y THU THẬP ĐƯỢC

### 2.1. Hành vi Dropper (Thả 3 file con vào hệ thống)
* **Công cụ ghi nhận:** Process Monitor (ProcMon)
* **Tiến trình thực hiện:** `123.exe` (PID: 4368)
* **Quan sát thực nghiệm:**
  - `123.exe` liên tục thực hiện các thao tác `CreateFile` với cờ `Generic Write`, sau đó dùng `WriteFile` để đổ các khối dữ liệu nhị phân xuống thư mục tạm `%LOCALAPPDATA%\Temp\`:
    1. `obedience.exe` (Kích thước: 1,579 KB)
    2. `StarBurn.dll` (Kích thước: 132 KB)
    3. `handkerchief.dat` (Kích thước: 249 KB)

![ProcMon ghi nhận 123.exe tạo file obedience.exe](Hinh_01_ProcMon_obedience.png)  
*Hình 1: Tiến trình 123.exe thực hiện CreateFile tạo obedience.exe trong thư mục Temp.*

![ProcMon ghi nhận 123.exe tạo file StarBurn.dll](Hinh_02_ProcMon_StarBurn_dll.png)  
*Hình 2: Tiến trình 123.exe tạo tiếp StarBurn.dll (Proxy DLL).*

* **Kiểm tra thực tế trong File Explorer:**  
  Mở thư mục `C:\Users\phamh\AppData\Local\Temp\`, cả 3 file đều xuất hiện đúng thời điểm `123.exe` kích hoạt:

![File Explorer hiển thị 3 file trong Temp](Hinh_03_Explorer_Temp_3files.png)  
*Hình 3: Ba file độc hại con nằm trong thư mục Temp.*

---

### 2.2. Cơ chế duy trì sự hiện diện & Giải mã file `persuasion.lnk`
* **Công cụ ghi nhận:** Sysinternals Autoruns (Tab `Logon`)
* **Vị trí phát hiện:** Thư mục khởi động người dùng:  
  `C:\Users\phamh\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\persuasion.lnk`
* **Target trỏ tới:** `C:\Users\phamh\AppData\Local\Temp\obedience.exe`

![Autoruns ghi nhận persuasion.lnk](Hinh_04_Autoruns_persuasion_lnk.jpg)  
*Hình 4: Autoruns ghi nhận shortcut persuasion.lnk tự khởi động obedience.exe.*

![Cận cảnh persuasion.lnk trong Startup](Hinh_05_persuasion_lnk_Startup.png)  
*Hình 5: Chi tiết mục khởi động persuasion.lnk trong thư mục Startup.*

#### Phân tích cơ chế hiển thị của Autoruns và nguồn gốc tên `persuasion.lnk`:

1. **Bản chất định dạng file `.lnk`:**
   - Đuôi `.lnk` (Link) là định dạng Windows Shell Shortcut (lối tắt). Bản thân file `.lnk` không phải là một file nhị phân thực thi độc lập mà là một cấu trúc dữ liệu nhị phân chứa con trỏ dẫn tới một tệp thực thi khác trên đĩa cứng.
   - Bên trong file `persuasion.lnk`, trường **Target Path** được thiết lập trỏ thẳng tới `C:\Users\phamh\AppData\Local\Temp\obedience.exe`.

2. **Cách thức công cụ Autoruns phân giải và hiển thị thông tin:**
   - Khi quét tab `Logon`, Autoruns kiểm tra thư mục Startup hệ thống tại:  
     `C:\Users\<User>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\`
   - **Cột "Autoruns Entry":** Hiển thị tên của chính tệp tin lối tắt nằm trong thư mục Startup, cụ thể là `persuasion.lnk`.
   - **Cột "Image Path":** Autoruns tự động đọc cấu trúc bên trong của shortcut để tìm ra đường dẫn thực tế của tệp đích sẽ được kích hoạt khi mở máy, đó là `C:\Users\phamh\AppData\Local\Temp\obedience.exe`.
   - **Cột "Publisher":** Autoruns kiểm tra chữ ký số của file thực thi đích (`obedience.exe`), phát hiện chữ ký hợp lệ và hiển thị `(Verified) Tsingsoft Imagination Information Technology Co., Ltd.`.
   - **Biểu tượng (Icon):** Autoruns trích xuất icon từ Resource section của file `obedience.exe` (biểu tượng chiếc đĩa CD màu tím của phần mềm StarBurn) để gắn vào dòng hiển thị.

3. **Mục đích của kẻ tấn công khi tách biệt hai cái tên `persuasion.lnk` và `obedience.exe`:**
   - **Ngụy trang từ ngữ (Lexical Camouflage) của nhóm APT10:** Kẻ tấn công sử dụng các danh từ tiếng Anh mang nghĩa trừu tượng (`obedience` = sự vâng lời, `persuasion` = sự thuyết phục, `handkerchief` = chiếc khăn tay) nhằm loại bỏ hoàn toàn các từ khóa đáng ngờ (`update`, `svchost`, `patch`, `loader`).
   - **Tạo sự bất nhất để đánh lạc hướng điều tra thủ công:** Nếu một quản trị viên phát hiện tiến trình lạ `obedience.exe` đang chạy trong Task Manager và tiến hành kiểm tra thư mục Startup, họ sẽ tìm kiếm một file có tên `obedience`. Việc kẻ tấn công đặt tên shortcut là `persuasion.lnk` khiến việc tìm kiếm theo tên tệp bị vô hiệu hóa.
   - **Đặc điểm ẩn phần mở rộng của Windows Explorer:** Mặc định Windows luôn ẩn phần mở rộng `.lnk`. Trong giao diện đồ họa, người dùng chỉ nhìn thấy một biểu tượng đĩa CD mang tên `persuasion`, trông hoàn toàn giống như một lối tắt của ứng dụng ghi đĩa thông thường.
   - **Né tránh các bộ lọc giám sát Registry:** Thay vì ghi trực tiếp vào các khóa Registry Run (`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`) vốn bị các phần mềm EDR/Antivirus giám sát rất chặt, việc thả một file `.lnk` vào thư mục Startup người dùng (`shell:startup`) ít kích hoạt cảnh báo hành vi hơn.

---

### 2.3. Bằng chứng Chữ ký số & Phân tích kỹ thuật DLL Sideloading

#### Bằng chứng Chữ ký số chính gốc:
Kiểm tra thuộc tính file `obedience.exe` xác nhận sự hiện diện của chữ ký số hợp lệ:

![Thuộc tính file obedience.exe](Hinh_06_obedience_Properties.jpg)  
*Hình 6: Thuộc tính file obedience.exe được xác nhận là phần mềm hợp pháp.*

![Chi tiết Chữ ký số Digital Signature](Hinh_07_Digital_Signature_Tsingsoft.png)  
*Hình 7: Chữ ký số của hãng Tsingsoft Imagination Information Technology Co., Ltd. chứng nhận bởi GlobalSign.*

- **Signer Name:** `Imagination Information Technology Co., Ltd.` (Tsingsoft)
- **Signing Time:** Thứ Bảy, 28/05/2011 (4:45:24 AM)
- **Countersignature:** `GlobalSign Time Stamping Services`
- **Trạng thái xác thực:** `This digital signature is OK.` (Hợp lệ)

---

#### Phân tích chuyên sâu: Cơ chế nạp DLL và lý do `StarBurn.dll` không bị phát hiện

Đây là kỹ thuật tinh vi của chiến dịch APT10: **DLL Search Order Hijacking (DLL Sideloading - MITRE ATT&CK: T1574.002)**.

1. **Cơ chế tìm kiếm DLL mặc định của hệ điều hành Windows:**
   Khi một phần mềm (ở đây là `obedience.exe`) khởi chạy và yêu cầu nạp thư viện liên kết động `StarBurn.dll`, Windows PE Loader sẽ tìm kiếm theo thứ tự ưu tiên:
   - Thư mục chứa chính file thực thi (`Application Directory`) -> Chính là thư mục `%TEMP%`.
   - Thư mục hệ thống (`C:\Windows\System32`).
   - Thư mục Windows (`C:\Windows`).
   - Thư mục làm việc hiện hành.
   - Các đường dẫn định nghĩa trong biến môi trường `PATH`.

   Do kẻ tấn công đã đặt file `StarBurn.dll` độc hại nằm cùng thư mục `%TEMP%` với `obedience.exe`, hệ điều hành sẽ dừng ngay ở bước tìm kiếm đầu tiên và nạp file DLL độc hại này vào không gian bộ nhớ của tiến trình.

2. **Lý do file `StarBurn.dll` độc hại không bị Antivirus phát hiện:**
   - **Giả lập cấu trúc Export (Proxy DLL):** File `StarBurn.dll` độc hại được biên dịch với đầy đủ bảng xuất khẩu hàm (Export Table) giống hệt DLL nguyên bản của hãng Tsingsoft, bao gồm các hàm: `StarBurn_Create`, `StarBurn_Destroy`, `StarBurn_UpStartEx`. Khi Antivirus phân tích tĩnh cấu trúc PE Header, file này thể hiện cấu trúc hoàn toàn chuẩn mực.
   - **Tách rời Payload (Payload Decoupling):** File `StarBurn.dll` (132 KB) hoàn toàn không chứa bất kỳ đoạn Shellcode hay chuỗi lệnh độc hại nào trong các phân vùng mã máy (.text). File này thuần túy chỉ là một đoạn mã nạp trung gian (Stub Loader). Toàn bộ nội dung độc hại thực sự được lưu riêng biệt tại file thứ ba là `handkerchief.dat` dưới dạng mã hóa XOR. Khi Antivirus quét tĩnh file DLL trên đĩa cứng:
     - Không khớp chữ ký nhận diện mã độc (Signature Match Fail).
     - Không tìm thấy địa chỉ IP/Domain C2 dạng văn bản rõ.
     - Không phát hiện các mẫu chuỗi Shellcode nguy hiểm.
   - **Kế thừa độ tin cậy từ tiến trình sạch (Reputation Piggybacking):** Tiến trình cha thực thi là `obedience.exe` có chữ ký số hợp lệ của Tsingsoft. Các giải pháp EDR và cơ chế bảo vệ theo hành vi (Heuristic Engine) thường gán mức độ rủi ro thấp cho các tiến trình có chữ ký số tin cậy, giúp mã độc vượt qua các bài kiểm tra giám sát ban đầu.

---

### 2.4. Bóc tách mã nguồn gốc Dropper trong x32dbg
* **Công cụ ghi nhận:** `x32dbg-unsigned.exe`
* **Địa chỉ hàm Dropper:** `0x00F744C6` (trong module `123.exe`)

![Đoạn mã Dropper gọi 3 file và Sleep trong x32dbg](Hinh_08_x32dbg_Dropper_Sleep_Exit.jpg)  
*Hình 8: Mã Assembly trong x32dbg chứng minh 123.exe thả 3 file, gọi Sleep(0x834) rồi exit.*

* **Các lệnh Assembly quan sát được:**
  ```assembly
  00F744C6 | 68 E4720A01   | push 123.10A72E4            | "handkerchief.dat"
  00F744CB | 68 D4720A01   | push 123.10A72D4            | "StarBurn.dll"
  00F744D0 | 68 C4720A01   | push 123.10A72C4            | "obedience.exe"
  00F744D5 | B9 54E02D01   | mov ecx,123.12DE054         | ecx:EntryPoint
  00F744DA | E8 11F9FFFF   | call 123.F73DF0             | ; Bung 3 file ra %TEMP%
  00F744DF | 68 34080000   | push 834                    | ; 0x834 = 2100 ms (~2.1 giây)
  00F744E4 | FF15 7C640A01 | call dword ptr ds:[<Sleep>] | ; Ngủ 2.1 giây
  00F744EA | 6A 00         | push 0                      |
  00F744EC | E8 EB861000   | call 123.107CBDC            | ; Thoát tiến trình (_exit)
  ```
* **Kết luận:** `123.exe` chỉ đóng vai trò là Dropper ban đầu. Sau khi giải nén 3 file con ra đĩa, nó gọi hàm `Sleep(2100)` rồi gọi `exit` để kết thúc tiến trình, xóa sạch dấu vết đang chạy trong danh sách tiến trình.

---

### 2.5. Bằng chứng nạp bộ nhớ bất thường `ERW` (RWX) trong RAM
* **Công cụ ghi nhận:** `x32dbg` (Tab `Memory Map` khi nạp `obedience.exe`)

![Vùng nhớ ERW trong x32dbg Memory Map](Hinh_09_x32dbg_MemoryMap_ERW_RWX.png)  
*Hình 9: Hai vùng nhớ cấp phát bất thường ERW-- trong tiến trình obedience.exe.*

* **Chi tiết 2 vùng nhớ:**
  1. `0x00770000` (Kích thước: `0x00001000` = **4 KB**): Quyền `ERW--` (Chứa Shellcode bốc dỡ Stage 1).
  2. `0x02710000` (Kích thước: `0x00040000` = **256 KB**): Quyền `ERW--` (Chứa toàn bộ dữ liệu file `handkerchief.dat` 249 KB sau khi được giải mã XOR).
* **Ý nghĩa:** Quyền **`ERW`** (**E**xecute - **R**ead - **W**rite) tương đương với quyền **`RWX`** trong Process Hacker. Đây là dấu hiệu của kỹ thuật **In-Memory Injection** (thực thi nhị phân trực tiếp trên bộ nhớ mà không ghi file đã giải mã ra đĩa).

---

### 2.6. Bóc tách luồng kiểm tra con trỏ bộ nhớ của `StarBurn.dll`
Khi phân tích luồng thực thi bên trong `StarBurn.dll` tại hàm `StarBurn_UpStartEx+301E`, phát hiện mã độc gọi chuỗi hàm kiểm tra bộ nhớ của Windows trước khi giải mã:

![Đoạn mã IsBadWritePtr trong x32dbg](Hinh_10_x32dbg_IsBadWritePtr.png)  
*Hình 10: Hàm IsBadWritePtr kiểm tra ghi bộ nhớ (ghi chú: [ebp-08]: StarBurn_UpStartEx+301E).*

![Đoạn mã IsBadReadPtr trong x32dbg](Hinh_11_x32dbg_IsBadReadPtr.jpg)  
*Hình 11: Hàm IsBadReadPtr kiểm tra quyền đọc bộ nhớ.*

* **Mã giả C tương đương:**
  ```c
  // StarBurn_UpStartEx kiểm tra an toàn vùng nhớ trước khi giải mã
  if (IsBadWritePtr(lpBuffer, dwSize) || IsBadReadPtr(lpBuffer, dwSize)) {
      ExitProcess(0); // Vùng nhớ không hợp lệ -> Thoát ngay để tránh crash phần mềm
  }
  // Vùng nhớ hợp lệ -> Kích hoạt vòng lặp giải mã XOR file handkerchief.dat
  ```

---

### 2.7. Dấu vết mạng Socket và Trinh sát địa lý trong vùng nhớ giải mã
Truy cập vào danh sách String References tại vùng nhớ đã giải mã `0x0274xxxx`:

![Chuỗi mạng Socket và NLS Locale trong RAM](Hinh_12_x32dbg_Strings_Socket_Locale.png)  
*Hình 12: Các chuỗi ký tự bên trong vùng nhớ 256 KB của handkerchief.dat.*

* **Bằng chứng thu thập được:**
  1. `"receive buffer has been supplied in a synchronous request.\r\n"`: Chuỗi thông báo lỗi của hàm mạng **`WSARecv`** trong `ws2_32.dll`, chứng minh mã độc đã liên kết với thư viện socket để chuẩn bị giao tiếp mạng đồng bộ với C2.
  2. `L"(United Kingdom)"`: Chuỗi trong bảng kiểm tra múi giờ, ngôn ngữ (NLS / Locale Detection) nhằm xác định vị trí địa lý của máy nạn nhân.

---

### 2.8. Phân tích mạng bằng FakeNet-NG & Wireshark (Kỹ thuật lọc bỏ nhiễu nền)

* **FakeNet-NG:** Hoạt động bình thường, lắng nghe cổng và chặn các truy vấn DNS ngầm của Windows:

![Cửa sổ FakeNet-NG ghi nhận DNS](Hinh_13_FakeNet_NG_DNS_Console.png)  
*Hình 13: FakeNet-NG chặn bắt các truy vấn DNS hệ thống.*

* **Wireshark:** Bắt được các gói tin `SSDP M-SEARCH` gửi tới địa chỉ `239.255.255.250:1900`:

![Wireshark Follow UDP Stream gói tin SSDP](Hinh_14_Wireshark_SSDP_Filter.png)  
*Hình 14: Wireshark nhận diện gói tin SSDP của trình duyệt Chromium (Nhiễu nền).*

- Dòng `USER-AGENT: Chromium/126...` xác nhận đây là tính năng quét tìm Smart TV trong mạng LAN của trình duyệt Microsoft Edge/Chrome, không phải gói tin của mã độc.

---

## 3. KẾT LUẬN & ĐÁNH GIÁ KHOA HỌC

1. **Những hành vi ĐÃ ĐƯỢC CHỨNG MINH 100% bằng chứng thực nghiệm:**
   - Hành vi **Dropper** giải nén 3 file vào `%TEMP%` và tự hủy sau 2.1 giây.
   - Hành vi **Persistence** thông qua shortcut ngụy trang `persuasion.lnk` trong thư mục Startup.
   - Kỹ thuật **DLL Sideloading** mượn file có chữ ký số hợp lệ của Tsingsoft để né Antivirus.
   - Kỹ thuật **In-Memory Injection** tạo vùng nhớ `ERW` (RWX) 4 KB và 256 KB.
   - Kỹ thuật **Memory Probe** dùng `IsBadWritePtr` để kiểm tra an toàn trước khi giải mã.
   - Module Socket mạng đồng bộ và bảng trinh sát địa lý trong RAM.

2. **Những hành vi KHÔNG THỂ kích hoạt trong môi trường lab động:**
   - Các hành vi thứ cấp (như trích xuất mật khẩu Firefox/DPAPI hay gửi dữ liệu về C2) không xuất hiện trên luồng mạng thực nghiệm.
   - **Lý do khoa học:** Mã độc được lập trình với cơ chế **Fail-fast**. Khi kiểm tra kết nối Socket mà không nhận được tín hiệu phản hồi từ máy chủ C2 của kẻ tấn công ngoài đời thực, mã độc lập tức gọi lệnh thoát (`ExitProcess`) để tự bảo vệ, không chạy tiếp nhánh mã độc ăn cắp dữ liệu. Đây là giới hạn tự nhiên của phương pháp Phân tích Động (Dynamic Analysis) khi phân tích các dòng mã độc APT có phụ thuộc chặt chẽ vào hạ tầng C2.

---
*Báo cáo được hoàn thành dựa trên 100% bằng chứng ảnh chụp thực nghiệm và phân tích dịch ngược trực tiếp.*
