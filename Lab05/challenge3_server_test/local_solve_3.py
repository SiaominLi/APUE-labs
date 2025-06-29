#!/usr/bin/env python3
from pwn import *
import time
import re

context.log_level = 'info'

# 本地伺服器配置
SERVER_COMMAND = ['./server_executable', '.'] # 假設都在當前目錄

def send_and_receive(p_tube, request_path_bytes, request_name):
    """發送一個GET請求並接收完整回應（頭+體）"""
    log.info(f"--- {request_name}: Sending GET {request_path_bytes.decode()} ---")
    request_data = (
        f"GET {request_path_bytes.decode()} HTTP/1.1\r\n"
        f"Host: localhost\r\n" # 本地測試時 Host 不太重要
        f"\r\n" # 重要：標頭後的空行
    ).encode()
    
    try:
        p_tube.send(request_data)
        
        # 嘗試接收完整的 HTTP 回應
        # 伺服器在發送完一個回應後，會等待下一個請求的輸入 (fgets)
        # 我們需要確保 recvuntil 消耗掉剛好一個回應
        
        headers = p_tube.recvuntil(b"\r\n\r\n", timeout=2.0, drop=True)
        if not headers:
            log.error(f"{request_name}: Did not receive headers.")
            return False, None, None

        log.info(f"{request_name}: Received Headers:\n{headers.decode(errors='ignore')}")
        
        body = b""
        content_length_match = re.search(br'Content-Length: (\d+)', headers)
        if content_length_match:
            length = int(content_length_match.group(1))
            log.info(f"{request_name}: Expecting body length: {length}")
            if length > 0:
                body = p_tube.recvn(length, timeout=2.0)
            log.info(f"{request_name}: Received Body ({len(body)} bytes):\n{body.decode(errors='ignore')}")
        elif b"200 OK" in headers: # 如果是200 OK但沒有Content-Length，嘗試讀取
            log.warning(f"{request_name}: No Content-Length, trying to recvall for 200 OK.")
            body = p_tube.recvall(timeout=1.0)
            log.info(f"{request_name}: Received Body (recvall, {len(body)} bytes):\n{body.decode(errors='ignore')}")
        
        if b"HTTP/1.1" not in headers: # 基本檢查
             log.error(f"{request_name}: Invalid HTTP response (no status line).")
             return False, headers, body

        return True, headers, body

    except PwnlibException as e:
        log.error(f"{request_name}: PwnlibException: {e}")
        return False, None, None
    except Exception as e:
        log.error(f"{request_name}: Generic Exception: {e}")
        return False, None, None

# --- 主邏輯 ---
log.info("Starting local server process for Multi-Request Test...")
p = process(SERVER_COMMAND)

requests_to_make = [
    (b"/index.html", "Request 1 (index.html)"),
    (b"/page1.html", "Request 2 (page1.html)"),
    (b"/page2.html", "Request 3 (page2.html)"),
    # 讓我們嘗試一個會返回 401 的，看看之後是否還能發請求
    (b"/secret/FLAG.txt", "Request 4 (FLAG.txt - no auth)"), 
    (b"/index.html", "Request 5 (index.html again)"),
]

all_successful = True
for path, name in requests_to_make:
    time.sleep(0.1) # 在請求之間加入非常小的延遲，模擬思考時間，也給伺服器喘息
    success, _, _ = send_and_receive(p, path, name)
    if not success:
        all_successful = False
        log.error(f"{name} FAILED. Aborting further requests on this connection.")
        break # 如果一個請求失敗（例如 EOF），後續的通常也會失敗
    log.info(f"{name} completed on the same connection.\n")

if all_successful:
    log.success("All requests in the sequence were processed successfully on the same connection.")
else:
    log.error("One or more requests in the sequence failed.")

p.wait_for_close()
log.info("Local server process for Multi-Request Test finished.")