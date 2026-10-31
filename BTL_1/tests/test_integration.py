"""
Test tích hợp end-to-end qua socket thật: server/MitM chạy như tiến trình riêng, client chạy trong tiến trình test.
Mỗi test dùng thư mục khóa, thư mục tải về và cổng riêng.
"""
import base64
import hashlib
import json
import os
import socket
import subprocess
import sys
import threading
import time
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import client
from config import CHUNK_SIZE
from protocol import send_msg

SRC = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
NAMES = ["Alice", "Bob", "Dave", "Mallory"]


# --------------------------------------------------------------------------- #
# Hạ tầng
# --------------------------------------------------------------------------- #
def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_for(cond, timeout=5.0):
    end = time.time() + timeout
    while time.time() < end:
        if cond():
            return True
        time.sleep(0.02)
    return cond()


def read_log(path):
    return path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""


def wait_port(port):
    assert wait_for(lambda: _can_connect(port), 20), "tiến trình server không lên (xem file .log trong thư mục tạm)"


def _can_connect(port):
    try:
        socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
        return True
    except OSError:
        return False


@pytest.fixture
def env(tmp_path, monkeypatch):
    keys = tmp_path / "keys"
    keys.mkdir()
    for n in NAMES:
        priv = Ed25519PrivateKey.generate()
        (keys / f"{n}.priv").write_bytes(priv.private_bytes(
            serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()))
        (keys / f"{n}.pub").write_bytes(priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw))
    downloads = tmp_path / "downloads"
    monkeypatch.setattr(client, "KEYS_DIR", str(keys))
    monkeypatch.setattr(client, "DOWNLOAD_DIR", str(downloads))
    monkeypatch.setattr(client, "HANDSHAKE_TIMEOUT", 4.0)

    procs, clients = [], []

    def start(script, *args):
        port = free_port()
        penv = dict(os.environ, CHAT_PORT=str(port), CHAT_KEYS_DIR=str(keys),
                    PYTHONIOENCODING="utf-8", PYTHONUTF8="1")
        log_path = tmp_path / f"{script}_{port}.log"
        log = open(log_path, "w", encoding="utf-8")
        p = subprocess.Popen([sys.executable, "-u", os.path.join(SRC, script), *args] +
                             (["--port", str(port)] if script == "mitm_server.py" else []),
                             cwd=str(tmp_path), env=penv, stdout=log, stderr=subprocess.STDOUT)
        log.close()                      # tiến trình con đã giữ handle riêng
        procs.append(p)
        try:
            wait_port(port)
        except AssertionError:
            raise AssertionError(f"Server/MitM không khởi động. Log:\n{read_log(log_path)}") from None
        return port, log_path

    def mk(name, port, **kw):
        c = client.ChatClient(name, "127.0.0.1", port, **kw)
        clients.append(c)
        return c

    yield SimpleNamespace(start=start, mk=mk, tmp=tmp_path, keys=keys, downloads=downloads)

    for c in clients:
        try:
            c.sock.close()
        except OSError:
            pass
    for p in procs:
        p.terminate()
        try:
            p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            p.kill()
            p.wait(timeout=5)


@pytest.fixture
def pair(env):
    port, _ = env.start("server.py")
    a, b = env.mk("Alice", port), env.mk("Bob", port)
    time.sleep(0.2)
    return env, port, a, b


def spy(c):
    """Ghi lại mọi gói client gửi ra; trả về (danh sách, hàm gửi gốc)."""
    sent, orig = [], c.send_packet

    def wrapped(p):
        sent.append(p)
        orig(p)
    c.send_packet = wrapped
    return sent, orig


# --------------------------------------------------------------------------- #
# Chat
# --------------------------------------------------------------------------- #
def test_chat_both_directions_unicode(pair):
    _, _, a, b = pair
    a.send_chat("Bob", "Xin chào Bob ✓")
    assert wait_for(lambda: ("Alice", "Xin chào Bob ✓") in b.inbox)
    b.send_chat("Alice", "Chào lại 🙂")
    assert wait_for(lambda: ("Bob", "Chào lại 🙂") in a.inbox)


def test_wire_has_no_plaintext(pair):
    _, _, a, b = pair
    sent, _ = spy(a)
    a.send_chat("Bob", "mat-khau-123456")
    assert wait_for(lambda: b.inbox)
    blob = json.dumps([p for p in sent if p["type"] == "chat"])
    assert "mat-khau-123456" not in blob
    assert "mat-khau-123456" not in base64.b64decode(sent[-1]["ct"]).decode("latin-1")


def test_chat_replay_rejected(pair):
    _, _, a, b = pair
    sent, orig = spy(a)
    a.send_chat("Bob", "chuyen 100 dong")
    assert wait_for(lambda: len(b.inbox) == 1)
    pkt = [p for p in sent if p["type"] == "chat"][-1]
    orig(pkt)
    orig(pkt)
    time.sleep(0.5)
    assert b.inbox == [("Alice", "chuyen 100 dong")]


def test_tampered_chat_rejected_then_recovers(pair):
    _, _, a, b = pair
    a.send_chat("Bob", "dau tien")
    assert wait_for(lambda: len(b.inbox) == 1)
    sent, orig = spy(a)
    a.send_packet = lambda p: orig(dict(p, ct=base64.b64encode(
        bytes([base64.b64decode(p["ct"])[0] ^ 1]) + base64.b64decode(p["ct"])[1:]).decode()))
    a.send_chat("Bob", "bi sua")
    time.sleep(0.4)
    assert len(b.inbox) == 1
    a.send_packet = orig
    a.send_chat("Bob", "van nhan duoc")
    assert wait_for(lambda: ("Alice", "van nhan duoc") in b.inbox)


# --------------------------------------------------------------------------- #
# Độ bền của client
# --------------------------------------------------------------------------- #
def test_unknown_sender_hello_does_not_kill_receiver(pair):
    env, port, a, b = pair
    eve = env.mk("Eve", port, use_crypto=False)
    hello = bytes([1, 1]) + b"x" * 128                      # role = initiator, nội dung rác
    send_msg(eve.sock, {"type": "hs_hello", "from": "Eve", "to": "Bob",
                        "hello": base64.b64encode(hello).decode(), "confirm": None})
    time.sleep(0.4)
    assert b.receiver.is_alive()
    a.send_chat("Bob", "van song")
    assert wait_for(lambda: ("Alice", "van song") in b.inbox)


def test_hello_with_path_traversal_name_ignored(pair):
    env, port, a, b = pair
    eve = env.mk("Eve", port, use_crypto=False)
    hello = bytes([1, 1]) + b"x" * 128
    send_msg(eve.sock, {"type": "hs_hello", "from": "../keys/Alice", "to": "Bob",
                        "hello": base64.b64encode(hello).decode(), "confirm": None})
    time.sleep(0.4)
    assert b.receiver.is_alive() and "../keys/Alice" not in b.peer_states


def test_typo_recipient_does_not_exit(pair, capsys):
    _, _, a, b = pair
    a.send_chat("Bobb", "x")                                   # không ném SystemExit
    assert "[HANDSHAKE]" in capsys.readouterr().out
    a.send_chat("Bob", "van chat duoc")
    assert wait_for(lambda: ("Alice", "van chat duoc") in b.inbox)


def test_retry_after_offline_peer(env):
    port, _ = env.start("server.py")
    client.HANDSHAKE_TIMEOUT = 1.0
    a = env.mk("Alice", port)
    a.send_chat("Dave", "dave oi")                             # Dave offline -> timeout
    assert "Dave" not in a.peer_states
    d = env.mk("Dave", port)
    time.sleep(0.2)
    client.HANDSHAKE_TIMEOUT = 4.0
    a.send_chat("Dave", "dave oi lan 2")
    assert wait_for(lambda: ("Alice", "dave oi lan 2") in d.inbox)


def test_peer_restart_recovers(pair):
    env, port, a, b = pair
    a.send_chat("Bob", "truoc restart")
    assert wait_for(lambda: len(b.inbox) == 1)
    b.sock.shutdown(socket.SHUT_RDWR)   # đóng thật kết nối để server gỡ tên Bob
    b.sock.close()
    time.sleep(0.5)
    b2 = env.mk("Bob", port)
    time.sleep(0.2)
    a.send_chat("Bob", "mat phien")                            # Bob mới chưa có phiên -> báo no_session
    assert wait_for(lambda: "Bob" not in a.peer_states, 3)
    a.send_chat("Bob", "sau khi bat tay lai")
    assert wait_for(lambda: ("Alice", "sau khi bat tay lai") in b2.inbox)


def test_simultaneous_initiation(pair):
    _, _, a, b = pair
    t1 = threading.Thread(target=a.send_chat, args=("Bob", "tu Alice"))
    t2 = threading.Thread(target=b.send_chat, args=("Alice", "tu Bob"))
    t1.start(); t2.start(); t1.join(8); t2.join(8)
    assert wait_for(lambda: ("Alice", "tu Alice") in b.inbox)
    assert wait_for(lambda: ("Bob", "tu Bob") in a.inbox)


def test_server_overrides_spoofed_from(pair):
    env, port, a, b = pair
    eve = env.mk("Eve", port, use_crypto=False)
    send_msg(eve.sock, {"type": "chat", "from": "Alice", "to": "Bob", "hdr": "00", "ct": "AAAA"})
    time.sleep(0.4)
    assert b.inbox == []
    assert "Alice" not in b.peer_states


# --------------------------------------------------------------------------- #
# Truyền tệp
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("size", [0, 1, CHUNK_SIZE, CHUNK_SIZE + 1, 3 * CHUNK_SIZE + 17])
def test_file_roundtrip(pair, size):
    env, _, a, b = pair
    data = os.urandom(size)
    src = env.tmp / "in.bin"
    src.write_bytes(data)
    a.send_file("Bob", str(src))
    assert wait_for(lambda: b.files_ok, 8)
    out = b.files_ok[0]
    assert hashlib.sha256(open(out, "rb").read()).digest() == hashlib.sha256(data).digest()
    assert os.path.dirname(os.path.realpath(out)) == os.path.realpath(env.downloads)


def test_file_meta_is_encrypted(pair):
    env, _, a, b = pair
    sent, _ = spy(a)
    src = env.tmp / "tai-lieu-mat.txt"
    src.write_text("noi dung", encoding="utf-8")
    a.send_file("Bob", str(src))
    assert wait_for(lambda: b.files_ok)
    meta = [p for p in sent if p["type"] == "file_meta"][0]
    assert "name" not in meta and "sha256" not in meta and "size" not in meta
    assert "tai-lieu-mat" not in json.dumps(meta)


def test_tampered_file_meta_rejected(pair):
    env, _, a, b = pair
    sent, orig = spy(a)

    def tamper(p):
        if p["type"] == "file_meta":
            raw = bytearray(base64.b64decode(p["ct"]))
            raw[0] ^= 1
            p = dict(p, ct=base64.b64encode(bytes(raw)).decode())
        orig(p)
    a.send_packet = tamper
    src = env.tmp / "f.txt"
    src.write_text("abc", encoding="utf-8")
    a.send_file("Bob", str(src))
    time.sleep(0.8)
    assert b.files_ok == []
    assert not env.downloads.exists() or os.listdir(env.downloads) == []


def test_tampered_file_chunk_aborts(pair):
    env, _, a, b = pair
    sent, orig = spy(a)

    def tamper(p):
        if p["type"] == "file_chunk" and p["index"] == 1:
            raw = bytearray(base64.b64decode(p["ct"]))
            raw[5] ^= 1
            p = dict(p, ct=base64.b64encode(bytes(raw)).decode())
        orig(p)
    a.send_packet = tamper
    src = env.tmp / "big.bin"
    src.write_bytes(os.urandom(3 * CHUNK_SIZE))
    a.send_file("Bob", str(src))
    time.sleep(1.0)
    assert b.files_ok == []
    assert not any(n.endswith(".part") for n in os.listdir(env.downloads))


def test_malicious_file_name_stays_inside_downloads(pair):
    env, _, a, b = pair
    session = a.ensure_session("Bob")
    content = b"abc"
    fid = "ab" * 16
    meta = json.dumps({"name": "../../evil.txt", "size": 3, "total": 1,
                       "sha256": hashlib.sha256(content).hexdigest()}).encode()
    a._send_secure("Bob", session, "file_meta", meta, b"file_meta:" + fid.encode(), file_id=fid)
    a._send_secure("Bob", session, "file_chunk", content, f"{fid}:0:1".encode(), file_id=fid, index=0)
    a._send_secure("Bob", session, "file_end", b"end", b"file_end:" + fid.encode(), file_id=fid)
    assert wait_for(lambda: b.files_ok)
    assert os.path.basename(b.files_ok[0]) == "evil.txt"
    assert os.path.dirname(os.path.realpath(b.files_ok[0])) == os.path.realpath(env.downloads)
    assert not (env.tmp / "evil.txt").exists() and not (env.tmp.parent / "evil.txt").exists()


# --------------------------------------------------------------------------- #
# Kịch bản MitM qua proxy
# --------------------------------------------------------------------------- #
def test_mitm_passive_sees_plaintext_without_crypto(env):
    port, log = env.start("mitm_server.py", "--attack", "passive")
    a, b = env.mk("Alice", port, use_crypto=False), env.mk("Bob", port, use_crypto=False)
    time.sleep(0.2)
    a.send_chat("Bob", "Tai khoan 123456")
    assert wait_for(lambda: "Tai khoan 123456" in read_log(log))


def test_mitm_passive_sees_only_ciphertext_with_crypto(env):
    port, log = env.start("mitm_server.py", "--attack", "passive")
    a, b = env.mk("Alice", port), env.mk("Bob", port)
    time.sleep(0.2)
    a.send_chat("Bob", "Tai khoan 123456")
    assert wait_for(lambda: b.inbox)
    text = read_log(log)
    assert "Tai khoan 123456" not in text and "CIPHERTEXT" in text


@pytest.mark.parametrize("attack", ["tamper-hello", "swap-eph", "impersonate"])
def test_mitm_handshake_attacks_blocked(env, attack, capsys):
    port, log = env.start("mitm_server.py", "--attack", attack)
    a, b = env.mk("Alice", port), env.mk("Bob", port)
    time.sleep(0.2)
    a.send_chat("Bob", "thu tan cong")
    time.sleep(0.5)
    assert b.inbox == []
    assert "Bob" not in a.peer_states and "Alice" not in b.peer_states
    assert "Từ chối" in capsys.readouterr().out


def test_mitm_impersonate_message_is_signature_failure(env, capsys):
    port, _ = env.start("mitm_server.py", "--attack", "impersonate")
    a, b = env.mk("Alice", port), env.mk("Bob", port)
    time.sleep(0.2)
    a.send_chat("Bob", "x")
    time.sleep(0.5)
    assert "Chữ ký không hợp lệ" in capsys.readouterr().out


def test_mitm_tamper_ciphertext_rejected(env):
    port, _ = env.start("mitm_server.py", "--attack", "tamper-ct")
    a, b = env.mk("Alice", port), env.mk("Bob", port)
    time.sleep(0.2)
    a.send_chat("Bob", "bi sua tren duong")
    time.sleep(0.6)
    assert b.inbox == []


def test_mitm_replay_delivered_once(env):
    port, _ = env.start("mitm_server.py", "--attack", "replay")
    a, b = env.mk("Alice", port), env.mk("Bob", port)
    time.sleep(0.2)
    a.send_chat("Bob", "chuyen 100 dong")
    assert wait_for(lambda: b.inbox)
    time.sleep(0.6)
    assert b.inbox == [("Alice", "chuyen 100 dong")]
