
---

# UP25 Lab04：組合語言實踐 — 擴展 `libmini`

---

## 實驗目的

本次 Lab04 的主要目標是**實踐組合語言程式設計**。我需要擴展課程中介紹的 `libmini` 函式庫，為其增加一系列指定的新功能。所有新增的功能都必須使用 **x86-64 組合語言**，並以 `yasm` 語法實現。

## 實驗內容與重點

在這個實驗中，我將專注於以下函式的組合語言實作：

1.  **時間相關函式**
    * `time(time_t * unused)`：實作獲取當前時間戳的功能。
    * `srand(unsigned int seed)`：實作設定亂數種子的功能。
    * `grand()`：實作返回當前亂數種子的功能。
    * `rand()`：根據指定演算法實作亂數生成器。

2.  **信號集操作函式**
    * `sigemptyset(sigset_t *set)`：將信號集清空。
    * `sigfillset(sigset_t *set)`：將信號集填滿所有有效信號。
    * `sigaddset(sigset_t *set, int signum)`：向信號集中添加指定信號。
    * `sigdelset(sigset_t *set, int signum)`：從信號集中移除指定信號。
    * `sigismember(const sigset_t *set, int signum)`：檢查指定信號是否為信號集成員。

3.  **信號遮罩管理**
    * `sigprocmask(int how, const sigset_t *newset, sigset_t *oldset)`：實作標準的信號遮罩管理功能，可設定、查詢或替換行程的信號遮罩。

4.  **非局部跳轉函式**
    * `setjmp(jmp_buf env)`：實作標準的 `sigsetjmp` 功能，用於保存呼叫環境（包括信號遮罩）。
    * `longjmp(jmp_buf env, int val)`：實作標準的 `siglongjmp` 功能，用於恢復之前保存的呼叫環境，並恢復信號遮罩。

## 環境與開發細節

* 所有的實作都將放置在單一的組合語言檔案 `libmini64-ext.asm` 中。
* 我將利用課程提供的 `chals.tbz` 基本套件來進行組譯、運行和測試。
* 對於系統呼叫，我會參考 Linux x86-64 的系統呼叫表。
* 在組合語言中，我會特別注意如何存取全域變數（包括本地定義和 `libmini` 中定義的），以及如何呼叫其他函式庫中的函式，這涉及相對位址和 PLT 表的使用。
* 對於 `setjmp` 和 `longjmp`，需要確保正確保存和恢復必要的暫存器（`rbx`、`rbp`、`rsp`、`r12`、`r13`、`r14`、`r15`）和返回位址。
* 本次實驗沒有挑戰伺服器，所有測試都在本地環境進行。
