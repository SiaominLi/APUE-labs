---

# UP25 HW1: 系統呼叫掛鉤與日誌記錄 (zpoline-inspired)

本專案為 UP25 HW1 作業的實作，旨在建立一個受 USENIX ATC 2023 最佳論文獎 [zpoline](https://www.usenix.org/conference/atc23/presentation/lu) 啟發的系統呼叫掛鉤 (hook) 機制。專案目標是攔截並記錄任意 x86-64 Linux 執行檔與檔案存取相關的系統呼叫。

專案主要分為兩大部分：
1.  **`libzpoline.so` (初始化共享函式庫)**: 透過 `LD_PRELOAD` 注入目標程式，負責設定掛鉤環境，包括在虛擬記憶體位址 `0x0` 建立跳板 (trampoline)，並在記憶體中重寫 `syscall` 指令。
2.  **`logger.so` (日誌共享函式庫)**: 由 `libzpoline.so` 載入，實作具體的攔截邏輯，將 `openat`, `read`, `write`, `connect`, `execve` 等系統呼叫的資訊，依照指定格式記錄到 `stderr`。

## 核心概念

此掛鉤機制的運作流程如下：

1.  **跳板設定 (Trampoline Setup)**: 透過 `mmap` 在虛擬記憶體位址 `0x0` 映射一個可執行的記憶體頁面。頁面的前 512 bytes 被填充為 `NOP` 指令 (構成一個 "NOP sled")，其後緊跟著我們真正的跳板組合語言程式碼。此步驟需要先執行 `sudo sh -c "echo 0 > /proc/sys/vm/mmap_min_addr"`。
2.  **二進位重寫 (Binary Rewriting)**: 掃描程式的可執行記憶體區段，尋找 `syscall` 指令 (`0x0F 0x05`)。每找到一個，就地將其替換為 `call *%rax` 指令 (`0xFF 0xD0`)。
3.  **重新導向 (Redirection)**: 當被掛鉤的程式要執行系統呼叫時，系統呼叫編號會放在 `%rax` 暫存器中。此時，被替換後的 `call *%rax` 指令會跳轉到一個極低的記憶體位址 (例如 `write` 的呼叫號為 1，就會跳到 `0x1`)，正好落在 NOP sled 的範圍內。CPU 會沿著 NOP 指令一路「滑行」，最終執行到我們真正的跳板程式碼。
4.  **掛鉤邏輯 (Hooking Logic)**: 跳板組合語言程式碼負責保存當前的機器狀態 (暫存器)，將系統呼叫的參數傳遞給一個 C 語言的處理函式 (handler)，並呼叫它。這個 C handler 可以執行自訂邏輯（如 Leetspeak 解碼或日誌記錄），然後再執行原始的系統呼叫，並將結果返回。
5.  **避免遞迴 (Recursion Avoidance)**: 為了防止無限遞迴（例如：`hook -> printf -> write (再次觸發 hook)`），最終的 `logger.so` 會被 `dlmopen(LM_ID_NEWLM, ...)` 載入到一個獨立的連結器命名空間 (linker namespace)，使其內部對 libc 的呼叫不會受到我們的 `syscall` patch 影響。

## 編譯與使用

### 編譯

專案提供了一個 `Makefile`，只需執行：

```bash
make
```

此命令會產生所需的共享函式庫，如 `libzpoline.so.2` 和 `logger.so`。

### 使用

**Part 1 - Leetspeak 解碼器測試 (`libzpoline.so.2`)**
```bash
$ LD_PRELOAD=./libzpoline.so.2 /usr/bin/echo '7h15 15 4 l337 73x7'
this is a leet text
```

**Part 2 - 系統呼叫日誌記錄器 (`libzpoline.so` + `logger.so`)**
```bash
$ LD_PRELOAD=./libzpoline.so LIBZPHOOK=./logger.so <command> [args...]
# 範例:
$ LD_PRELOAD=./libzpoline.so LIBZPHOOK=./logger.so cat /etc/hosts
```
此命令會將 `cat` 程式執行時與檔案相關的系統呼叫日誌輸出到 `stderr`。

## 技術挑戰與解決方案

這個專案涉及了多個底層的技術挑戰，解決這些問題是學習的核心。

### 1. 組合語言與 C 語言的呼叫慣例轉換

-   **難題**: x86-64 Linux 的系統呼叫慣例（參數在 `rdi, rsi, rdx, r10, r8, r9`）與 System V C 函式呼叫慣例（參數在 `rdi, rsi, rdx, rcx, r8, r9`）不同。跳板的組合語言必須在呼叫 C handler 前，正確地轉換這些參數。
-   **解決方案**: 在組合語言跳板中，我們必須先保存所有來自 `syscall` 上下文的重要暫存器。接著，在 `call` C handler 之前，手動將參數從系統呼叫慣例的暫存器，移動到 C 呼叫慣例對應的暫存器或堆疊位置。例如，系統呼叫的第 4 個參數在 `%r10`，必須被移動到 `%rcx` 以作為 C 函式的第 4 個參數。

### 2. 精確的堆疊管理與對齊

-   **難題**: 損壞或未對齊的堆疊是造成 Segmentation Fault 的主因。`call *%rax` 指令、跳板自己的 `push`/`pop` 操作、以及對 C handler 的 `call` 都會修改堆疊指標 (`%rsp`)。x86-64 ABI 嚴格要求在 `call` 指令執行前，`%rsp` 必須是 16 位元組對齊的。
-   **解決方案**: 跳板組合語言 meticulously 地保存了所有必要的暫存器，計算了堆疊指標的狀態，並在需要時插入 `subq $8, %rsp` 等指令，以確保在呼叫 C handler 前達到 16 位元組對齊。在 C 呼叫返回後，所有堆疊修改都被小心地逆向操作，以將堆疊恢復到進入跳板前的原始狀態。

### 3. C Handler 回傳值的保存

-   **難題**: C handler 執行完畢後，會將系統呼叫的結果放在 `%rax` 中返回。但我們的跳板程式在進入時也保存了原始的 `%rax` 值（即系統呼叫編號）。如果天真地用 `popq %rax` 來恢復暫存器，就會覆蓋掉寶貴的執行結果。
-   **解決方案**: 跳板的暫存器恢復序列經過特殊設計。我們不將保存的原始 `%rax` 值 `pop` 回 `%rax`。取而代之，我們使用 `addq $8, %rsp` 直接將堆疊指標跳過該保存位置，這樣 C handler 的回傳結果就能完好無損地保留在 `%rax` 中，以供最終的 `retq` 指令使用。

### 4. 記憶體區段掃描與段錯誤 (Segmentation Fault)

-   **難題**: 在 `rewrite_executable_segments` 函式中，我們需要讀取 `/proc/self/maps` 來遍歷所有可執行的記憶體區段。在 GDB 除錯過程中發現，`for (uintptr_t i = start; ...)` 迴圈在掃描記憶體時發生了段錯誤。
-   **解決方案**: 透過 GDB 追蹤，發現問題出在對記憶體區段的存取上。原因可能是 `sscanf` 解析 `/proc/self/maps` 的某一行時，得到了一個無效或極大的 `start` 或 `end` 位址，導致迴圈變數 `i` 指向了未映射或不可讀的記憶體。解決方案是強化程式碼的防禦性，例如在 `sscanf` 後檢查 `start` 和 `end` 的合理性，並在 GDB 中仔細觀察是哪一個記憶體區段 (`line_buf` 的內容) 觸發了問題，從而修正掃描邏輯。

### 5. 內聯組合語言的約束與除錯

-   **難題**: 最初嘗試在 C 程式碼中使用 GCC 的內聯組合語言 (`__asm__ volatile`) 來實作 `perform_real_syscall`。然而，由於對輸入/輸出約束 (`"r"`, `"a"`, `"D"`, `"S"`) 和 clobber list 的設定不當，導致編譯器產生了 `"impossible constraints"` 錯誤。
-   **解決方案**: 深入理解了 GCC inline assembly 的語法。對於需要固定暫存器的 `syscall` 指令，必須使用特定的約束，例如用 `"=a"(result)` 表示輸出在 `%rax`，用 `"D"(arg1)` 表示輸入在 `%rdi`。對於沒有單字母約束的暫存器（如 `%r10`），則在組合語言內部明確使用 `movq` 指令，並將這些暫存器加入 clobber list，告知編譯器它們的值會被改變。

### 6. 程式碼分離與可維護性

-   **難題**: 將複雜的組合語言邏輯以十六進制 byte array 的形式硬編碼在 C 程式碼中，不僅極易出錯，而且幾乎無法除錯和維護。
-   **解決方案**: 最終將核心的跳板邏輯分離到一個獨立的 `.S` 組合語言檔案中。C 程式碼的職責簡化為在跳板位址 (`0x0 + 512`) 放置一條 `jmp` 指令，跳轉到這個已編譯好的組合語言函式。這種模組化的方法極大地提高了程式碼的可讀性和可維護性，並使得 GDB 的除錯工作（如在組合語言函式中設定斷點）變得直觀有效。