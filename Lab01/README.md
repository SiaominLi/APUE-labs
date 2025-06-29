# UP25 Lab01：建構課程環境

## 目的

本實驗（Lab01）旨在為UP25課程建構所需的運行環境。學生需透過本次實驗熟悉 `docker`、`python` 以及 `pwntools` 的基本操作與應用。

## 完成事項

本實驗室成功完成了以下目標與挑戰：

1.  **環境建置**：
    * 成功在個人設備上準備並設定了 Docker 環境（支援 Docker Desktop 或 Linux 上的 docker.io）。
    * 從課程提供的 GitHub 倉庫克隆了運行環境，並依照指示正確設定了使用者名稱及使用者家目錄。
    * 確保了 `pwntools` 函式庫的成功安裝，並驗證了其基本功能（例如：執行 `from pwn import *` 及 `r = process('read Z; echo You got $Z', shell=True); r.sendline(b'AAA'); r.interactive()` 等指令）。

2.  **簡易 HTTP 挑戰**：
    * 實現了一個基於 `pwntools` 的 Python 腳本，該腳本能夠訪問 `http://ipinfo.io/ip` 這個 URL，並成功擷取遠端伺服器的 IP 位址。
    * 此腳本的輸出與使用 `curl http://ipinfo.io/ip` 命令的輸出結果一致，且未調用外部程式（如 `wget` 或 `curl`）或使用其他高階函式庫完成此任務。

3.  **挑戰伺服器互動與解題**：
    * 編寫了能夠與課程挑戰伺服器（`nc up.zoolab.org 10155`）進行互動的解題器（solver）。
    * 成功處理了挑戰伺服器上的 PoW (Proof-of-Work) 驗證機制。
    * 解題器能夠正確地解碼並顯示從伺服器接收到的訊息。
    * 實現了一個全自動化的解題器，該解題器能夠無需人工介入，自主地與遊戲互動並解決挑戰伺服器上的互動式遊戲。解題過程參考了提供的 `guess.dist.py` 模擬伺服器原始碼及 `solver_simple.py` 範例腳本。

## 使用技術

* **Docker**：用於容器化課程運行環境。
* **Python 3**：主要的程式語言，用於編寫解題腳本。
* **pwntools**：功能強大的 CTF (Capture The Flag) 框架，用於網路通訊、資料處理及自動化交互。
* **Netcat (nc)**：用於與遠端挑戰伺服器建立基本網路連線。
* **UNIX-like 環境**：如 WSL 或 macOS，作為執行腳本的宿主機操作系統。

## 如何運行

1.  **設定 Docker 環境**：
    * 請確保您的系統已安裝 Docker Desktop 或 `docker.io`。
2.  **克隆課程倉庫**：
    * `git clone [課程運行環境 GitHub 倉庫連結]`
    * 依照倉庫中的指示設定您的使用者名稱及環境。
3.  **執行解題腳本**：
    * `cd [您的Lab01工作目錄]`
    * 執行 HTTP 挑戰腳本：`python3 http_solver.py`
    * 執行挑戰伺服器解題腳本：`python3 game_solver.py` (假設您的腳本名稱為 `game_solver.py`，並且 `solpow.py` 放置在相同目錄下以解決 PoW。)

