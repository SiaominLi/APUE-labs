---

# UP25 HW2: Simple Instruction Level Debugger (sdb)

## 實驗概述 (Project Overview)

本專案旨在實作一個簡易的 x86-64 指令級除錯器 (sdb)，功能類似於 GDB 的基礎操作。使用者可以透過命令列介面，載入並互動式地除錯靜態/動態連結的執行檔，包括支援 ASLR/PIE 的程式。

此除錯器使用 C 語言和 `ptrace` 系統呼叫介面來追蹤、控制子行程的執行、讀寫其記憶體與暫存器。此外，專案整合了 [Capstone](https://www.capstone-engine.org/) 函式庫來進行指令的反組譯。

### 主要功能 (Key Features)

*   **載入程式 (`load`, `[program]`)**: 載入目標程式並停在入口點。
*   **單步執行 (`si`)**: 執行單一指令。
*   **繼續執行 (`cont`)**: 執行直到遇到斷點或程式結束。
*   **斷點管理 (`break`, `breakrva`, `info break`, `delete`)**: 在絕對或相對位址設定/移除斷點。
*   **狀態檢視 (`info reg`)**: 顯示所有通用暫存器的值。
*   **記憶體修改 (`patch`)**: 在指定位址修改記憶體內容。
*   **系統呼叫追蹤 (`syscall`)**: 追蹤程式進出系統呼叫的事件。

## 核心實作與難點 (Core Implementation & Challenges)

這個專案涉及了許多系統層面的挑戰，需要對行程控制、記憶體管理和 ELF 格式有深入的理解。以下是開發過程中遇到的主要難題及解決方案：

### 1. 程式載入與入口點定位 (Program Loading & Entry Point)

*   **難題**: 對於動態連結和 PIE 程式，`execvp` 後的第一個停止點通常在動態連結器 (`ld.so`) 中，而非主程式的 `_start` 或 `main`。如何找到並停在真正的入口點？
*   **解決方案**:
    1.  **區分靜態與動態資訊**:
        *   **`get_elf_entry_from_file`**: 從靜態 ELF 檔案頭部讀取 `e_entry`，並透過 `e_type` 判斷是否為 PIE (`ET_DYN`) 或非 PIE (`ET_EXEC`)。這提供了程式的**相對進入點 (RVA)** 或**期望的虛擬位址 (VMA)**。
        *   **`get_at_entry_from_auxv`**: 從執行中行程的 `/proc/[pid]/auxv` 檔案中讀取 `AT_ENTRY`。這是由作業系統載入器確定的**最終、真實的程式入口點 VMA**，無論程式是否為 PIE 或動態連結，這個值都是準確的。
    2.  **跳轉至真實入口點**:
        *   在 `handle_load` 中，比較子行程初始停止時的 `RIP` 和從 `AT_ENTRY` 獲取的 `g_entry_point_vma`。
        *   如果兩者不符，就在 `g_entry_point_vma` 位址設定一個**暫時的軟中斷 (`0xcc`)**。
        *   使用 `ptrace(PTRACE_CONT, ...)` 讓動態連結器完成其工作並跳轉到主程式入口，觸發我們的暫時斷點。
        *   命中後，恢復該位址的原始指令 byte，並將 `RIP` 校正回該位址，完成精準定位。

### 2. **斷點狀態管理與命令協調 (Breakpoint State Management & Command Coordination)**

*   **難題**: `si`, `cont`, `syscall` 等命令在遇到斷點時的行為各不相同。如何設計一個統一的狀態管理機制，避免「重複命中同一斷點」、「`si` 越過斷點後未命中下一條指令的斷點」或「`si` 卡在斷點處無法前進」等問題？
*   **解決方案**:
    1.  **軟中斷 (`0xcc`) 與狀態結構**: 使用 `0xcc` 實現斷點，並在 `Breakpoint` 結構中用 `is_enabled` 旗標追蹤記憶體中是否為 `0xcc`。
    2.  **引入「待越過斷點」狀態**:
        *   使用全域旗標 `g_is_stepping_over_breakpoint` 和 `g_stepped_over_breakpoint_addr`。
        *   當任何命令 (`si`, `cont`) 命中一個已啟用的斷點 `X` 時，統一執行以下操作：
            a. 報告命中。
            b. 校正 `RIP` 到 `X`。
            c. `disable_breakpoint(X)` (恢復原始指令)。
            d. **設定 `g_is_stepping_over_breakpoint = 1`**，並記錄 `g_stepped_over_breakpoint_addr = X`。
            e. 從 `X` 開始反組譯，然後等待下一個用戶命令。
    3.  **在命令處理函式開頭處理狀態**:
        *   在 `handle_si`, `handle_cont`, `handle_syscall_cmd` 的**函式開頭**，都檢查 `if (g_is_stepping_over_breakpoint)`。
        *   如果為真，則該命令的首要任務是**完成越過操作**：
            a. `PTRACE_SINGLESTEP` 執行已恢復的原始指令。
            b. `waitpid`。
            c. `enable_breakpoint()` **立即**重新啟用剛剛越過的斷點。
            d. 清除 `g_is_stepping_over_breakpoint` 旗標。
            e. **然後才繼續**該命令本身的主要邏輯。例如，`cont` 會繼續執行 `PTRACE_CONT`，而 `si` 則檢查這次越過操作是否又命中了新斷點。
    *   這個統一的狀態處理模型確保了不同命令間的協調一致，是整個專案最核心且最棘手的邏輯。

### 3. **非對齊記憶體訪問 (`PTRACE_PEEKTEXT` 限制)**

*   **難題**: 在 `anon` 範例中，設定斷點於 `0x700000000ffa` 時，`PTRACE_PEEKTEXT` 會因位址非 8-byte 對齊且接近記憶體區域邊界而失敗 (`errno = EIO`)。
*   **解決方案**:
    1.  **放棄字組讀寫**: 不再直接使用 `PTRACE_PEEKTEXT/POKETEXT` 讀寫 `long`。
    2.  **實作逐 byte 存取**:
        *   **`ptrace_peek_byte`**: 內部計算包含目標 byte 的對齊位址，使用 `PTRACE_PEEKTEXT` 讀取整個 8-byte 字組，然後透過指標操作和偏移量從中提取所需的單個 byte。
        *   **`ptrace_poke_byte`**: 類似地，先讀取對齊的字組，在記憶體中修改目標 byte，然後使用 `PTRACE_POKETEXT` 將修改後的整個字組寫回去。
    3.  **全面替換**: 將程式中所有直接讀寫記憶體的地方（如 `enable/disable_breakpoint`, `patch`, `disassemble_and_print`）都改為使用這兩個安全的逐 byte 輔助函式。這雖然效率較低，但極大地提高了健壯性，能處理任意位址。

### 4. **動態記憶體區域處理 (`anon` 範例)**

*   **難題**: `anon` 程式會透過 `mmap` 動態分配並跳轉到新的可執行記憶體區域。初始載入時掃描的記憶體映射表 (`g_exec_regions`) 會因此失效，導致 `break` 失敗或反組譯報錯。
*   **解決方案**:
    1.  **更通用的位址有效性檢查**:
        *   實作 `is_address_in_any_mapped_region` 輔助函式。此函式在需要時**即時**讀取 `/proc/[pid]/maps`，檢查目標位址是否落在**任何**已映射的區域內，而不僅僅是初始的可執行區域。
        *   在 `handle_break` 和 `handle_patch` 中使用這個函式來判斷使用者輸入的位址是否有效。
    2.  **動態更新可執行區域列表**:
        *   在 `disassemble_and_print` 函式中，當發現要反組譯的位址不在已知的 `g_exec_regions` 中時，不立即報錯，而是先嘗試呼叫一次 `update_executable_regions()` 來重新掃描 maps。
        *   如果刷新後該位址仍然無效，才報告 `** the address is out of the range of the executable region.`。這使得除錯器能適應程式執行過程中記憶體佈局的變化。

### 5. **`syscall` 指令的精準定位與顯示**

*   **難題**: `PTRACE_SYSCALL` 停止時，`RIP` 指向的是 `syscall` 指令**之後**的位址。直接使用該 `RIP` 會導致輸出和反組譯的位址不準確。
*   **解決方案**:
    1.  **回退 RIP**: 當 `handle_syscall_cmd` 檢測到是 `PTRACE_SYSCALL` 停止時，計算 `syscall_instruction_address = current_rip - 2` (因為 `syscall` 指令 `0f 05` 長度為 2 bytes)。
    2.  **統一顯示與反組譯**: 在 `printf` 輸出 `enter/leave` 訊息和呼叫 `disassemble_and_print` 時，都使用這個計算出的 `syscall_instruction_address`，確保顯示的位址和反組譯的內容都從 `syscall` 指令本身開始。
    3.  **修改 `disassemble_and_print`**: 確保該函式使用傳入的位址參數作為反組譯的基準，而不是用 `ptrace(PTRACE_GETREGS, ...)` 獲取的 `g_regs.rip` 來覆蓋它。

### 6. **`patch` 與斷點的複雜交互**

*   **難題**: 如果 `patch` 的範圍覆蓋了現有斷點，該如何處理？規格要求「斷點應該仍然存在，但原始指令被 patch」。
*   **解決方案**:
    1.  在 `handle_patch` 中，遍歷所有活動斷點。
    2.  如果一個斷點 `BP_X` 的位址落在 patch 範圍內：
        *   如果 `BP_X` 之前是啟用的 (`0xcc`)，則 patch 操作會覆蓋它，因此 `BP_X->is_enabled` 必須被設為 `false`。
        *   如果 patch 的**起始位址**正好是 `BP_X->address`，則 `BP_X->original_byte` 應更新為 patch 的第一個 byte。
    3.  patch 操作完成後，**不自動重新啟用**被影響的斷點。斷點的定義（ID, 位址, 更新後的 `original_byte`）仍然存在於除錯器中，但它在記憶體中不再是 `0xcc`。這符合規格的要求，將重新激活斷點的權力留給使用者。