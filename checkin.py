#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Trae 每日签到脚本（GitHub Actions 加固版）
原理（与上游一致）：
  Trae 网页端的 JWT 只有 8 小时有效期，但真正的会话凭证是 HttpOnly Cookie
  `X-Cloudide-Session`（约 14 天有效）。本脚本通过该 Cookie 调用
  `GetUserToken` 接口换取全新 JWT，再用新 JWT 执行每日签到。

依赖：仅标准库（urllib），无需第三方库；workflow 里安装 requests 仅用于兼容旧版脚本。

环境变量：
  TRAE_SESSION        账号 1 的 X-Cloudide-Session Cookie（必填）
  TRAE_DEVICE_ID      账号 1 的 x-device-id，必须是 16 位数字（建议必填，缺省随机）
  TRAE_SESSION_N      第 N(N>=2) 个账号的会话 Cookie；缺失即停止读取更多账号
  TRAE_DEVICE_ID_N    第 N 个账号的 x-device-id（选填，缺省随机）
  FEISHU_WEBHOOK      选填，签到后推送一条汇总
  TRAE_DEBUG          选填，设为 1 时打印逐请求详细日志（含响应体片段，不含任何敏感原值）

退出码：0 = 全部账号成功；1 = 存在失败 / 配置错误 / 未捕获异常（保证 GitHub 不"静默死亡"）

用法：
  python -u checkin.py 2>&1
"""
import datetime
import json
import os
import random
import sys
import time
import traceback
import urllib.error
import urllib.request

BASE = "https://api.trae.cn"
DEBUG = os.environ.get("TRAE_DEBUG", "").strip().lower() not in ("", "0", "false", "no")

def _redact(text):
    """把环境变量中的会话值替换成 ***（GitHub 日志本身会对 secret 打码，这里再兜一层底）。"""
    for key, value in os.environ.items():
        if key != "TRAE_SESSION" and not key.startswith("TRAE_SESSION_"):
            continue
        value = (value or "").strip()
        if len(value) >= 8 and value in text:
            text = text.replace(value, "***")
    return text

def _snippet(text, limit=300):
    """截取响应文本片段用于报错，先脱敏再压平换行，避免刷屏。"""
    if not text:
        return "(空响应)"
    text = _redact(text)[:limit]
    return text.replace("\r", " ").replace("\n", " ")

def _mask_device_id(device_id):
    """设备号只打印首尾各 4 位，避免完整值进入日志。"""
    if len(device_id) > 8:
        return "%s****%s (len=%d)" % (device_id[:4], device_id[-4:], len(device_id))
    return "****"

def _debug(msg):
    if DEBUG:
        print("[debug] " + _redact(str(msg)))

def _post(path, headers, body="", retries=3, tag=""):
    """POST 请求。非 2xx 不抛 HTTPError，而是以 (status, body) 正常返回，便于上层判断原因；
    网络层错误（DNS/连接/超时/TLS）自动重试，仍失败才抛异常（由上层打印 traceback）。"""
    last_err = None
    for attempt in range(1, retries + 1):
        req = urllib.request.Request(BASE + path, data=body.encode("utf-8"), headers=headers, method="POST")
        started = time.time()
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                text = resp.read().decode("utf-8", errors="replace")
                _debug("%s POST %s -> HTTP %s（%d 字节，%.1fs）"
                       % (tag, path, resp.status, len(text), time.time() - started))
                if DEBUG:
                    _debug("%s 响应体前 500 字符: %s" % (tag, _snippet(text, 500)))
                return resp.status, text
        except urllib.error.HTTPError as e:
            text = e.read().decode("utf-8", errors="replace")
            _debug("%s POST %s -> HTTP %s（%d 字节，%.1fs）"
                   % (tag, path, e.code, len(text), time.time() - started))
            if DEBUG:
                _debug("%s 响应体前 500 字符: %s" % (tag, _snippet(text, 500)))
            return e.code, text
        except Exception as e:  # URLError / TimeoutError / ssl 等网络层错误
            last_err = e
            print("[网络错误] %s POST %s 第 %d/%d 次失败：%s: %s"
                  % (tag, path, attempt, retries, type(e).__name__, e))
            if attempt < retries:
                time.sleep(2 ** attempt)  # 2s、4s 指数退避
    raise RuntimeError("网络请求失败（已重试 %d 次）：%s: %s"
                       % (retries, type(last_err).__name__, last_err))

def get_token(session):
    """用 X-Cloudide-Session Cookie 换取全新 JWT。失败时抛出带完整原因（HTTP 状态 + 响应片段）的异常。"""
    headers = {
        "Cookie": "X-Cloudide-Session=" + session,
        "Referer": "https://www.trae.cn/",
        "Origin": "https://www.trae.cn",
        "User-Agent": "TraeCheckin/1.0",
        "Accept": "application/json, text/plain, */*",
    }
    status, text = _post("/cloudide/api/v3/common/GetUserToken", headers, tag="GetUserToken")
    if status == 401:
        raise RuntimeError(
            "会话已失效（HTTP 401）：X-Cloudide-Session 已过期（约 14 天有效期）。"
            "请重新登录 trae.cn 复制新的 Cookie 并更新 TRAE_SESSION。原始返回: " + _snippet(text))
    if status == 403:
        raise RuntimeError(
            "被拒绝（HTTP 403）：常见于出口 IP 被风控 / 网关拦截（GitHub runner 为海外共享 IP）。"
            "原始返回: " + _snippet(text))
    if status == 429:
        raise RuntimeError("请求过于频繁（HTTP 429）：账号/设备/网络维度触发频率限制。原始返回: " + _snippet(text))
    if status != 200:
        raise RuntimeError("GetUserToken 失败：HTTP %s %s" % (status, _snippet(text)))
    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        raise RuntimeError(
            "GetUserToken 返回非法 JSON（可能是 WAF/网关拦截页或接口改版）：HTTP %s，解析错误 %s，原始返回: %s"
            % (status, e, _snippet(text)))
    token = (data.get("Result") or {}).get("Token")
    if not token:
        raise RuntimeError("GetUserToken 响应缺少 Result.Token：HTTP %s 原始返回: %s" % (status, _snippet(text)))
    return token

def checkin(token, device_id):
    """执行每日签到（claim）。无论成败都返回 http 与解析后的 body，便于上层统一诊断。"""
    headers = {
        "Authorization": "Cloud-IDE-JWT " + token,
        "X-User-Region": "cn",
        "x-device-id": device_id,
        "Content-Type": "application/json",
        "User-Agent": "TraeCheckin/1.0",
    }
    status, text = _post("/trae/api/v2/ug/checkin_credits/claim", headers, "{}", tag="checkin")
    try:
        body = json.loads(text)
    except json.JSONDecodeError:
        body = {"raw": _snippet(text)}
        print("[警告] 签到接口返回非 JSON（HTTP %s）：%s" % (status, body["raw"]))
    return {"http": status, "body": body}

def notify_feishu(webhook, text):
    """向飞书机器人推送一条文本消息；webhook 为空则跳过。返回 HTTP 状态码，失败返回 None。"""
    if not webhook:
        return None
    try:
        payload = json.dumps({"msg_type": "text", "content": {"text": text}}).encode("utf-8")
        req = urllib.request.Request(webhook, data=payload, headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status
    except Exception as e:
        print("[飞书] 推送失败：%s: %s" % (type(e).__name__, e))
        return None

def beijing_now_str():
    """返回北京时间字符串（runner 在 UTC，需 +8 小时；用 timezone-aware 写法避免 3.12 废弃告警）。"""
    return (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=8)).strftime("%Y-%m-%d %H:%M:%S")

def iter_sessions():
    """按顺序产出 (账号序号, session, device_id)。账号 1 读 TRAE_SESSION；
    之后依次读 TRAE_SESSION_2, TRAE_SESSION_3… 直到缺空为止。"""
    s = os.environ.get("TRAE_SESSION", "").strip()
    if s:
        yield 1, s, os.environ.get("TRAE_DEVICE_ID", "").strip()
    n = 2
    while True:
        s = os.environ.get("TRAE_SESSION_%d" % n, "").strip()
        if not s:
            break
        yield n, s, os.environ.get("TRAE_DEVICE_ID_%d" % n, "").strip()
        n += 1

def random_device_id():
    """随机生成 16 位数字风控设备号（仅缺省时兜底；必须是纯数字，UUID/字母会触发 9074）。"""
    return str(random.randint(10 ** 15, 10 ** 16 - 1))

def main():
    accounts = list(iter_sessions())
    if not accounts:
        print("错误：缺少环境变量 TRAE_SESSION")
        print("请在 GitHub 仓库 Settings -> Secrets and variables -> Actions 中添加 TRAE_SESSION（值 = 登录 trae.cn 后的 X-Cloudide-Session Cookie）")
        sys.exit(1)

    webhook = os.environ.get("FEISHU_WEBHOOK", "").strip()
    ok_names, fail_names, diagnostics = [], [], []
    all_ok = True

    for index, session, device_id in accounts:
        # 多账号之间错开 3~6 秒随机间隔，降低请求密度，规避 9074「参与用户太多」风控
        if index > 1:
            time.sleep(random.uniform(3, 6))
        name = "账号 %d" % index
        if not device_id:
            device_id = random_device_id()
            print("[%s] 未提供 TRAE_DEVICE_ID，已随机生成 16 位设备号（建议在 Secrets 中固定一个，成功率更稳）" % name)
        http, code, message = -1, -1, ""

        try:
            print("[%s] device_id=%s" % (name, _mask_device_id(device_id)))
            token = get_token(session)
            print("[%s] 已换取新 JWT，长度=%d" % (name, len(token)))

            result = checkin(token, device_id)
            body = result["body"]
            http = result["http"]
            code = body.get("code", -1)

            # 9074「参与用户太多」= 设备号被风控标记；换全新设备号自动重试（最多 5 次）
            attempt = 1
            while code == 9074 and attempt < 5:
                device_id = random_device_id()
                attempt += 1
                print("[%s] 命中风控 9074，换新设备号重试（第 %d 次）device_id=%s"
                      % (name, attempt, _mask_device_id(device_id)))
                time.sleep(random.uniform(0.8, 1.5))
                result = checkin(token, device_id)
                body = result["body"]
                http = result["http"]
                code = body.get("code", -1)

            checked = body.get("checked_in", False)
            ok = (http == 200) and (code == 0 or checked)
            credits = body.get("credits", 0)
            message = body.get("message") or ""
            if ok:
                print("[%s] 签到成功，本次获得：%s 积分" % (name, credits))
                ok_names.append(name)
            else:
                reason = message or ("HTTP %s" % http)
                print("[%s] 签到失败：%s" % (name, reason))
                print("[%s] 失败详情：HTTP=%s，完整响应=%s"
                      % (name, http, _snippet(json.dumps(body, ensure_ascii=False), 500)))
                fail_names.append(name)
                all_ok = False

        except RuntimeError as e:
            # 预期内的失败（401/403/429/接口异常），异常信息里已带完整原因，直接打印
            print("[%s] 签到失败：%s" % (name, e))
            message = str(e)[:120]
            fail_names.append(name)
            all_ok = False
        except Exception as e:
            # 未预期异常：打印完整 traceback，绝不静默死亡
            print("[%s] 签到异常：%s: %s" % (name, type(e).__name__, e))
            traceback.print_exc()
            message = "%s: %s" % (type(e).__name__, str(e)[:100])
            fail_names.append(name)
            all_ok = False

        diag = "  - %s: HTTP=%s, code=%s" % (name, http, code)
        if message:
            diag += ", message=%s" % message
        diagnostics.append(diag)

    print("================ 诊断摘要 ================")
    for line in diagnostics:
        print(line)
    if ok_names:
        print("成功：%s" % "、".join(ok_names))
    if fail_names:
        print("失败：%s" % "、".join(fail_names))

    # 汇总一条飞书推送（无论成功/失败都汇总，webhook 为空则跳过）
    summary = ["Trae 多账号签到结果", "时间：%s" % beijing_now_str()]
    if ok_names:
        summary.append("成功：" + "、".join(ok_names))
    if fail_names:
        summary.append("失败：" + "、".join(fail_names))
    if webhook and (ok_names or fail_names):
        status = notify_feishu(webhook, "\n".join(summary))
        print("飞书推送：%s" % ("HTTP %s" % status if status else "失败（见上方 [飞书] 提示）"))

    if not all_ok:
        sys.exit(1)
    print("全部账号签到完成")

if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception:
        # 兜底：任何未捕获异常都要带着完整堆栈打出来，保证 GitHub 日志可诊断
        print("脚本发生未捕获异常，完整堆栈如下：")
        traceback.print_exc()
        sys.exit(1)
