import ctypes
import logging
import platform
import subprocess
import sys
import uuid
from datetime import datetime

logger = logging.getLogger(__name__)

_OS = platform.system()


def _is_admin() -> bool:
    """Check for elevated privileges using two methods for reliability."""
    try:
        if _OS == "Windows":
            if ctypes.windll.shell32.IsUserAnAdmin() != 0:
                return True
            # Fallback: net session fails with code 2 if not elevated
            r = subprocess.run(["net", "session"], capture_output=True)
            return r.returncode == 0
        return False
    except Exception:
        return False


def _run(cmd: list[str]) -> tuple[bool, str]:
    """Run a subprocess command, return (success, output/error message)."""
    try:
        result = subprocess.run(
            cmd, check=True, capture_output=True,
            text=True, encoding='oem', errors='replace',
        )
        return True, result.stdout.strip()
    except subprocess.CalledProcessError as e:
        # netsh sometimes writes errors to stdout, sometimes stderr
        msg = (e.stderr.strip() or e.stdout.strip() or f'exit code {e.returncode}')
        return False, msg
    except FileNotFoundError as e:
        return False, str(e)


def _simulate(label: str, ip: str, detail: str = "") -> str:
    return f"[SIMULATE] {label} {ip}" + (f" — {detail}" if detail else "")


def _windows_block(ip: str) -> tuple[bool, str]:
    # No spaces in rule name — spaces cause quoting issues with CreateProcess + netsh
    rule_name = f"NNNIDS_Block_{ip}"
    ok, out = _run([
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={rule_name}", "dir=in", "action=block",
        f"remoteip={ip}", "protocol=any", "enable=yes",
    ])
    if ok:
        return True, f"[Windows] Firewall rule added: {rule_name}"
    return False, f"[Windows] netsh failed: {out or 'Unknown error — check Windows Firewall permissions'}"


def _windows_unblock(ip: str) -> tuple[bool, str]:
    rule_name = f"NNNIDS_Block_{ip}"
    ok, out = _run([
        "netsh", "advfirewall", "firewall", "delete", "rule",
        f"name={rule_name}",
    ])
    if ok:
        return True, f"[Windows] Firewall rule removed: {rule_name}"
    return False, f"[Windows] Rule not found or failed: {out}"


def _linux_block(ip: str) -> tuple[bool, str]:
    ok, out = _run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
    if ok:
        return True, f"[Linux] iptables DROP rule added for {ip}"
    return False, f"[Linux] iptables failed: {out}"


def _linux_unblock(ip: str) -> tuple[bool, str]:
    ok, out = _run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])
    if ok:
        return True, f"[Linux] iptables DROP rule removed for {ip}"
    return False, f"[Linux] iptables failed: {out}"


class ResponseEngine:
    """
    Executes real mitigation actions on the host OS.

    mode='live'     — executes real firewall commands (requires admin/root).
    mode='simulate' — logs what would happen, no system changes.
    """

    def __init__(self, mode: str = "live", rate_limit_iface: str = "eth0"):
        self.mode = mode
        self.rate_limit_iface = rate_limit_iface
        self.blocked_ips: set[str] = set()
        self.executed_actions: list[dict] = []

        if mode == "live" and not _is_admin():
            logger.warning(
                "ResponseEngine is in live mode but process is NOT running as Administrator. "
                "Firewall commands will fail. Restart as Administrator for real blocking."
            )

    def execute(self, decision: dict) -> dict:
        action_type = decision.get("recommended_action")
        src_ip = decision.get("src_ip")

        record = {
            "id": str(uuid.uuid4()),
            "timestamp": datetime.now().isoformat(),
            "decision_id": decision.get("diagnosis_id"),
            "src_ip": src_ip,
            "action_type": action_type,
            "status": "PENDING",
            "execution_log": [],
            "mode": self.mode,
        }

        handlers = {
            "BLOCK_IP": self._block,
            "THROTTLE": self._throttle,
            "QUARANTINE": self._quarantine,
            "MONITOR": self._monitor,
        }
        result = handlers.get(action_type, self._monitor)(src_ip)
        record["status"] = result["status"]
        record["execution_log"] = result["log"]
        self.executed_actions.append(record)

        log_fn = logger.warning if result["status"] == "FAILED" else logger.info
        log_fn("Response %s on %s → %s", action_type, src_ip, result["status"])
        return record

    def _block(self, ip: str) -> dict:
        if self.mode == "simulate":
            self.blocked_ips.add(ip)
            return {"status": "EXECUTED", "log": [_simulate("BLOCK_IP", ip)]}

        if _OS == "Windows":
            ok, msg = _windows_block(ip)
        elif _OS == "Linux":
            ok, msg = _linux_block(ip)
        else:
            return {"status": "FAILED", "log": [f"Unsupported OS for live blocking: {_OS}"]}

        if ok:
            self.blocked_ips.add(ip)
        return {"status": "EXECUTED" if ok else "FAILED", "log": [msg]}

    def _throttle(self, ip: str) -> dict:
        if self.mode == "simulate":
            return {"status": "EXECUTED", "log": [_simulate("THROTTLE", ip, "10 pkts/sec limit")]}

        if _OS == "Linux":
            cmds = [
                ["tc", "qdisc", "add", "dev", self.rate_limit_iface, "root", "handle", "1:", "htb", "default", "12"],
                ["tc", "class", "add", "dev", self.rate_limit_iface, "parent", "1:", "classid", "1:1", "htb", "rate", "10kbps"],
            ]
            log = []
            for cmd in cmds:
                ok, out = _run(cmd)
                log.append(out or " ".join(cmd))
            return {"status": "EXECUTED", "log": log}

        if _OS == "Windows":
            ok, msg = _windows_block(ip)
            note = "[Windows throttle via block — tc not available on Windows]"
            if ok:
                self.blocked_ips.add(ip)
            return {"status": "EXECUTED" if ok else "FAILED", "log": [msg, note]}

        return {"status": "FAILED", "log": [f"Throttle not supported on {_OS}"]}

    def _quarantine(self, ip: str) -> dict:
        if self.mode == "simulate":
            return {"status": "EXECUTED", "log": [_simulate("QUARANTINE", ip, "VLAN 999 isolation")]}

        ok, msg = (_windows_block(ip) if _OS == "Windows" else _linux_block(ip))
        note = f"[{_OS}] Quarantine via DROP rule — VLAN isolation requires managed switch config"
        if ok:
            self.blocked_ips.add(ip)
        return {"status": "EXECUTED" if ok else "FAILED", "log": [msg, note]}

    def _monitor(self, ip: str) -> dict:
        return {"status": "MONITORING", "log": [f"[MONITOR] {ip} added to watchlist — no firewall change"]}

    def is_blocked(self, ip: str) -> bool:
        return ip in self.blocked_ips

    def unblock(self, ip: str) -> dict:
        """Remove firewall block for ip. Always attempts the OS command even if
        the IP is not in the in-memory tracked set (e.g. after a backend restart)."""

        if self.mode == "simulate":
            self.blocked_ips.discard(ip)
            return {"success": True, "message": f"[SIMULATE] Unblocked {ip}"}

        # Always try the OS command — don't gate on in-memory set
        ok, msg = (_windows_unblock(ip) if _OS == "Windows" else _linux_unblock(ip))
        if ok:
            self.blocked_ips.discard(ip)
            return {"success": True, "message": msg}

        # If the rule simply didn't exist, treat that as already-unblocked
        if ip in self.blocked_ips:
            self.blocked_ips.discard(ip)
            return {"success": True, "message": f"{ip} rule not found in firewall (already unblocked)"}

        return {"success": False, "message": msg}