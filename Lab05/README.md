---

# UP25 Lab05：併發問題探索 — 競爭條件與可重入性

---

## 實驗目的

本次 Lab05 的主要目的是**調查多執行緒程式中可能存在的競爭條件（Race Condition）和可重入性（Reentrancy）問題**。我將透過分析三個挑戰伺服器的原始碼，並嘗試利用這些漏洞來解決挑戰。

## 實驗內容與重點

本次實驗包含三個獨立的挑戰，每個挑戰都要求我找到並利用特定的併發相關弱點：

1.  **挑戰 #1**
    * 我需要連接至挑戰伺服器 #1 (`nc up.zoolab.org 10931`)。
    * 目標是**傾印伺服器上的 `flag` 檔案內容**。
    * 我將分析伺服器提供的原始碼，理解可能存在的競爭條件，並利用其獲取 `flag`。
    * 最終目標是編寫一個 **`pwntools` 腳本**，能夠以單一指令自動完成這個挑戰。

2.  **挑戰 #2**
    * 我需要連接至挑戰伺服器 #2 (`nc up.zoolab.org 10932`)。
    * 目標是**要求挑戰伺服器從 `localhost:10000` 擷取機密（secret）**。這通常暗示著伺服器在處理外部請求時可能存在的內部資源競爭或錯誤處理。
    * 我將分析伺服器提供的原始碼，找出可利用的漏洞點。
    * 同樣，我需要編寫一個 **`pwntools` 腳本**，實現自動化解題。

3.  **挑戰 #3**
    * 挑戰伺服器 #3 (`nc up.zoolab.org 10933`) 是一個簡單的網頁伺服器。
    * 目標是**從 `http://up.zoolab.org:10933/secret/FLAG.txt` 讀取 `flag`**。這通常涉及到對網頁伺服器處理併發請求的弱點進行利用。
    * 我將分析網頁伺服器的原始碼，找出可能導致資訊洩露或訪問控制繞過的問題。
    * 我會開發一個 **`pwntools` 腳本**來自動化這個複雜的網頁互動和漏洞利用過程。

---