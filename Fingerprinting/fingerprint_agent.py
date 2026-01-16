#!/usr/bin/env python3
import argparse
import json
import platform
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple
from fingerprints import macos


# ----------------------------
# Command Execution Abstraction
# ----------------------------

@dataclass
class CommandResult:
    command: str
    raw_output: str
    exit_code: int

class Executor:
    """Base executor interface."""
    def run(self, command: str) -> CommandResult:
        raise NotImplementedError

class LocalExecutor(Executor):
    def run(self, command: str) -> CommandResult:
        p = subprocess.run(
            command,
            shell=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT
        )
        return CommandResult(command=command, raw_output=(p.stdout or "").strip(), exit_code=p.returncode)

class SSHExecutor(Executor):
    """
    Remote mode using system ssh (preferred, no dependencies).
    Assumes ssh key auth or agent is configured, or user will be prompted by ssh.
    """
    def __init__(self, host: str, user: Optional[str] = None, port: int = 22, identity_file: Optional[str] = None):
        self.host = host
        self.user = user
        self.port = port
        self.identity_file = identity_file

    def run(self, command: str) -> CommandResult:
        target = f"{self.user}@{self.host}" if self.user else self.host
        parts = ["ssh", "-p", str(self.port)]
        if self.identity_file:
            parts += ["-i", self.identity_file]
        parts += [target, command]

        p = subprocess.run(parts, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        return CommandResult(command=" ".join(parts), raw_output=(p.stdout or "").strip(), exit_code=p.returncode)


# ----------------------------
# Helpers
# ----------------------------

def now_utc_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

def parse_first_line(s: str) -> str:
    return (s.splitlines()[0].strip() if s else "").strip()

def safe_value_or_unknown(val: str) -> str:
    return val if val else "unknown"

def detect_remote_os(executor: Executor) -> str:
    """
    Best-effort OS detection for remote machines.
    Uses generic commands that exist on most systems.
    """
    # Try uname (unix-like)
    r = executor.run("uname -s")
    if r.exit_code == 0:
        name = parse_first_line(r.raw_output).lower()
        if "darwin" in name:
            return "macos"
        if "linux" in name:
            return "linux"
        # other unix can be added
        return "unix"

    # Try Windows via cmd
    r2 = executor.run("cmd.exe /c ver")
    if r2.exit_code == 0 and r2.raw_output:
        return "windows"

    return "unknown"


# ----------------------------
# OS-specific collectors
# ----------------------------

def collect_macos_system_info(executor: Executor) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    evidence: Dict[str, Any] = {}

    os_name = "macOS"

    r_ver = executor.run("sw_vers -productVersion")
    evidence["version"] = {"command_run": r_ver.command, "raw_output": r_ver.raw_output}
    version = parse_first_line(r_ver.raw_output)

    r_kernel = executor.run("uname -r")
    evidence["kernel"] = {"command_run": r_kernel.command, "raw_output": r_kernel.raw_output}
    kernel = parse_first_line(r_kernel.raw_output)

    r_arch = executor.run("uname -m")
    evidence["cpu_architecture"] = {"command_run": r_arch.command, "raw_output": r_arch.raw_output}
    arch = parse_first_line(r_arch.raw_output)

    # CPU model (best effort)
    r_cpu = executor.run("sysctl -n machdep.cpu.brand_string 2>/dev/null || sysctl -n hw.model")
    evidence["cpu_model"] = {"command_run": r_cpu.command, "raw_output": r_cpu.raw_output}
    cpu_model = parse_first_line(r_cpu.raw_output)

    system_info = {
        "os": os_name,
        "version": safe_value_or_unknown(version),
        "kernel": safe_value_or_unknown(kernel),
        "cpu": safe_value_or_unknown(cpu_model),
        "cpu_architecture": safe_value_or_unknown(arch),
        "evidence": evidence,
    }
    return system_info, evidence


def collect_linux_system_info(executor: Executor) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    evidence: Dict[str, Any] = {}
    os_name = "Linux"

    r_ver = executor.run("cat /etc/os-release 2>/dev/null | grep '^PRETTY_NAME=' | cut -d= -f2- | tr -d '\"'")
    evidence["version"] = {"command_run": r_ver.command, "raw_output": r_ver.raw_output}
    version = parse_first_line(r_ver.raw_output)

    r_kernel = executor.run("uname -r")
    evidence["kernel"] = {"command_run": r_kernel.command, "raw_output": r_kernel.raw_output}
    kernel = parse_first_line(r_kernel.raw_output)

    r_arch = executor.run("uname -m")
    evidence["cpu_architecture"] = {"command_run": r_arch.command, "raw_output": r_arch.raw_output}
    arch = parse_first_line(r_arch.raw_output)

    r_cpu = executor.run("cat /proc/cpuinfo 2>/dev/null | grep -m1 'model name' | cut -d: -f2- | sed 's/^ *//'")
    evidence["cpu_model"] = {"command_run": r_cpu.command, "raw_output": r_cpu.raw_output}
    cpu_model = parse_first_line(r_cpu.raw_output)

    system_info = {
        "os": os_name,
        "version": safe_value_or_unknown(version),
        "kernel": safe_value_or_unknown(kernel),
        "cpu": safe_value_or_unknown(cpu_model),
        "cpu_architecture": safe_value_or_unknown(arch),
        "evidence": evidence,
    }
    return system_info, evidence


def collect_windows_system_info(executor: Executor) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    evidence: Dict[str, Any] = {}
    os_name = "Windows"

    # Version
    r_ver = executor.run('powershell -NoProfile -Command "(Get-ComputerInfo).WindowsVersion"')
    evidence["version"] = {"command_run": r_ver.command, "raw_output": r_ver.raw_output}
    version = parse_first_line(r_ver.raw_output)

    # Kernel-ish: build number
    r_kernel = executor.run('powershell -NoProfile -Command "(Get-ComputerInfo).WindowsBuildLabEx"')
    evidence["kernel"] = {"command_run": r_kernel.command, "raw_output": r_kernel.raw_output}
    kernel = parse_first_line(r_kernel.raw_output)

    r_arch = executor.run('powershell -NoProfile -Command "$env:PROCESSOR_ARCHITECTURE"')
    evidence["cpu_architecture"] = {"command_run": r_arch.command, "raw_output": r_arch.raw_output}
    arch = parse_first_line(r_arch.raw_output)

    r_cpu = executor.run('powershell -NoProfile -Command "(Get-CimInstance Win32_Processor | Select-Object -First 1 -ExpandProperty Name)"')
    evidence["cpu_model"] = {"command_run": r_cpu.command, "raw_output": r_cpu.raw_output}
    cpu_model = parse_first_line(r_cpu.raw_output)

    system_info = {
        "os": os_name,
        "version": safe_value_or_unknown(version),
        "kernel": safe_value_or_unknown(kernel),
        "cpu": safe_value_or_unknown(cpu_model),
        "cpu_architecture": safe_value_or_unknown(arch),
        "evidence": evidence,
    }
    return system_info, evidence


# ----------------------------
# Software Fingerprinting
# ----------------------------

def software_targets() -> List[Dict[str, str]]:
    """
    A simple, extendable target registry.
    Each entry has:
      id, productName, productFamily, vendor
    """
    return [
        {"id": "vscode", "productName": "Visual Studio Code", "productFamily": "IDE", "vendor": "Microsoft"},
        {"id": "docker", "productName": "Docker", "productFamily": "Virtualization", "vendor": "Docker, Inc."},
        {"id": "slack", "productName": "Slack", "productFamily": "Collaboration", "vendor": "Slack Technologies"},
        {"id": "chrome", "productName": "Google Chrome", "productFamily": "Browser", "vendor": "Google"},
        {"id": "pycharm", "productName": "PyCharm", "productFamily": "IDE", "vendor": "JetBrains"},
    ]

def fingerprint_software_macos(executor: Executor) -> List[Dict[str, Any]]:
    inv: List[Dict[str, Any]] = []
    arch_res = executor.run("uname -m")
    host_arch = parse_first_line(arch_res.raw_output)

    for t in software_targets():
        pid = t["id"]
        if pid == "vscode":
            cmd = 'mdfind "kMDItemCFBundleIdentifier == \'com.microsoft.VSCode\'" | head -n 1'
            path_res = executor.run(cmd)
            path = parse_first_line(path_res.raw_output)
            if path:
                ver_cmd = f'/usr/libexec/PlistBuddy -c "Print :CFBundleShortVersionString" "{path}/Contents/Info.plist" 2>/dev/null || defaults read "{path}/Contents/Info" CFBundleShortVersionString'
                ver_res = executor.run(ver_cmd)
                version = parse_first_line(ver_res.raw_output)
                inv.append({
                    **t,
                    "versionNumber": safe_value_or_unknown(version),
                    "architecture": safe_value_or_unknown(host_arch),
                    "evidence": {
                        "command_run": path_res.command,
                        "raw_output": path_res.raw_output,
                        "version_command_run": ver_res.command,
                        "version_raw_output": ver_res.raw_output,
                    }
                })

        elif pid == "chrome":
            cmd = 'mdfind "kMDItemCFBundleIdentifier == \'com.google.Chrome\'" | head -n 1'
            path_res = executor.run(cmd)
            path = parse_first_line(path_res.raw_output)
            if path:
                ver_cmd = f'/usr/libexec/PlistBuddy -c "Print :CFBundleShortVersionString" "{path}/Contents/Info.plist" 2>/dev/null'
                ver_res = executor.run(ver_cmd)
                version = parse_first_line(ver_res.raw_output)
                inv.append({
                    **t,
                    "versionNumber": safe_value_or_unknown(version),
                    "architecture": safe_value_or_unknown(host_arch),
                    "evidence": {
                        "command_run": path_res.command,
                        "raw_output": path_res.raw_output,
                        "version_command_run": ver_res.command,
                        "version_raw_output": ver_res.raw_output,
                    }
                })

        elif pid == "slack":
            cmd = 'mdfind "kMDItemCFBundleIdentifier == \'com.tinyspeck.slackmacgap\'" | head -n 1'

            path_res = executor.run(cmd)
            path = parse_first_line(path_res.raw_output)
            if path:
                ver_cmd = f'/usr/libexec/PlistBuddy -c "Print :CFBundleShortVersionString" "{path}/Contents/Info.plist" 2>/dev/null'
                ver_res = executor.run(ver_cmd)
                version = parse_first_line(ver_res.raw_output)
                inv.append({
                    **t,
                    "versionNumber": safe_value_or_unknown(version),
                    "architecture": safe_value_or_unknown(host_arch),
                    "evidence": {
                        "command_run": path_res.command,
                        "raw_output": path_res.raw_output,
                        "version_command_run": ver_res.command,
                        "version_raw_output": ver_res.raw_output,
                    }
                })

        elif pid == "docker":
            # Docker Desktop installs a Docker.app and also a docker CLI in PATH sometimes.
            cli_res = executor.run("docker --version 2>/dev/null || true")
            app_res = executor.run('mdfind "kMDItemCFBundleIdentifier == \'com.docker.docker\'" | head -n 1')
            # Use CLI version if available, else App plist
            version = ""
            ver_evidence = {}
            if cli_res.raw_output:
                version = cli_res.raw_output
                ver_evidence = {"version_command_run": cli_res.command, "version_raw_output": cli_res.raw_output}
            else:
                app_path = parse_first_line(app_res.raw_output)
                if app_path:
                    ver_cmd = f'/usr/libexec/PlistBuddy -c "Print :CFBundleShortVersionString" "{app_path}/Contents/Info.plist" 2>/dev/null'
                    ver_res = executor.run(ver_cmd)
                    version = parse_first_line(ver_res.raw_output)
                    ver_evidence = {"version_command_run": ver_res.command, "version_raw_output": ver_res.raw_output}

            if app_res.raw_output or cli_res.raw_output:
                inv.append({
                    **t,
                    "versionNumber": safe_value_or_unknown(version),
                    "architecture": safe_value_or_unknown(host_arch),
                    "evidence": {
                        "command_run": app_res.command,
                        "raw_output": app_res.raw_output,
                        **ver_evidence
                    }
                })

        elif pid == "pycharm":
            # There are multiple PyCharm editions; bundle ids vary.
            cmd = 'mdfind "kMDItemCFBundleIdentifier == \'com.jetbrains.pycharm\' || kMDItemCFBundleIdentifier == \'com.jetbrains.pycharm.ce\'" | head -n 1'
            path_res = executor.run(cmd)
            path = parse_first_line(path_res.raw_output)
            if path:
                ver_cmd = f'/usr/libexec/PlistBuddy -c "Print :CFBundleShortVersionString" "{path}/Contents/Info.plist" 2>/dev/null'
                ver_res = executor.run(ver_cmd)
                version = parse_first_line(ver_res.raw_output)
                inv.append({
                    **t,
                    "productName": "PyCharm (Detected Bundle)",
                    "versionNumber": safe_value_or_unknown(version),
                    "architecture": safe_value_or_unknown(host_arch),
                    "evidence": {
                        "command_run": path_res.command,
                        "raw_output": path_res.raw_output,
                        "version_command_run": ver_res.command,
                        "version_raw_output": ver_res.raw_output,
                    }
                })

    return inv

def fingerprint_software_linux(executor: Executor) -> List[Dict[str, Any]]:
    inv: List[Dict[str, Any]] = []
    arch_res = executor.run("uname -m")
    host_arch = parse_first_line(arch_res.raw_output)

    for t in software_targets():
        pid = t["id"]

        if pid == "vscode":
            # Works for apt/rpm/snap depending; best effort.
            res = executor.run("code --version 2>/dev/null | head -n 1 || true")
            if res.raw_output:
                inv.append({
                    **t,
                    "versionNumber": parse_first_line(res.raw_output),
                    "architecture": safe_value_or_unknown(host_arch),
                    "evidence": {"command_run": res.command, "raw_output": res.raw_output},
                })

        elif pid == "docker":
            res = executor.run("docker --version 2>/dev/null || true")
            if res.raw_output:
                inv.append({
                    **t,
                    "versionNumber": parse_first_line(res.raw_output),
                    "architecture": safe_value_or_unknown(host_arch),
                    "evidence": {"command_run": res.command, "raw_output": res.raw_output},
                })

        elif pid == "slack":
            # Slack can be snap/flatpak/deb
            res = executor.run("slack --version 2>/dev/null || snap info slack 2>/dev/null | grep -i '^installed:' || flatpak info com.slack.Slack 2>/dev/null | grep -i '^Version:' || true")
            if res.raw_output:
                inv.append({
                    **t,
                    "versionNumber": parse_first_line(res.raw_output),
                    "architecture": safe_value_or_unknown(host_arch),
                    "evidence": {"command_run": res.command, "raw_output": res.raw_output},
                })

        elif pid == "chrome":
            res = executor.run("google-chrome --version 2>/dev/null || chromium --version 2>/dev/null || true")
            if res.raw_output:
                inv.append({
                    **t,
                    "versionNumber": parse_first_line(res.raw_output),
                    "architecture": safe_value_or_unknown(host_arch),
                    "evidence": {"command_run": res.command, "raw_output": res.raw_output},
                })

        elif pid == "pycharm":
            # JetBrains Toolbox installs vary; try common command
            res = executor.run("pycharm --version 2>/dev/null | head -n 1 || true")
            if res.raw_output:
                inv.append({
                    **t,
                    "versionNumber": parse_first_line(res.raw_output),
                    "architecture": safe_value_or_unknown(host_arch),
                    "evidence": {"command_run": res.command, "raw_output": res.raw_output},
                })

    return inv

def fingerprint_software_windows(executor: Executor) -> List[Dict[str, Any]]:
    inv: List[Dict[str, Any]] = []
    arch_res = executor.run('powershell -NoProfile -Command "$env:PROCESSOR_ARCHITECTURE"')
    host_arch = parse_first_line(arch_res.raw_output)

    for t in software_targets():
        pid = t["id"]

        if pid == "vscode":
            # Try querying VS Code exe version via typical install paths
            cmd = r'''powershell -NoProfile -Command "$paths=@(
              \"$env:LOCALAPPDATA\Programs\Microsoft VS Code\Code.exe\",
              \"$env:ProgramFiles\Microsoft VS Code\Code.exe\",
              \"$env:ProgramFiles(x86)\Microsoft VS Code\Code.exe\"
            ); $p=$paths | Where-Object { Test-Path $_ } | Select-Object -First 1;
            if($p){ (Get-Item $p).VersionInfo.ProductVersion }"'''
            res = executor.run(cmd)
            if res.raw_output:
                inv.append({
                    **t,
                    "versionNumber": parse_first_line(res.raw_output),
                    "architecture": safe_value_or_unknown(host_arch),
                    "evidence": {"command_run": res.command, "raw_output": res.raw_output},
                })

        elif pid == "docker":
            res = executor.run('powershell -NoProfile -Command "docker --version"')
            if res.exit_code == 0 and res.raw_output:
                inv.append({
                    **t,
                    "versionNumber": parse_first_line(res.raw_output),
                    "architecture": safe_value_or_unknown(host_arch),
                    "evidence": {"command_run": res.command, "raw_output": res.raw_output},
                })

        elif pid == "slack":
            cmd = r'''powershell -NoProfile -Command "
              $p1=\"$env:LOCALAPPDATA\slack\slack.exe\";
              $p2=\"$env:ProgramFiles\Slack\slack.exe\";
              $p=@($p1,$p2) | Where-Object { Test-Path $_ } | Select-Object -First 1;
              if($p){ (Get-Item $p).VersionInfo.ProductVersion }"'''
            res = executor.run(cmd)
            if res.raw_output:
                inv.append({
                    **t,
                    "versionNumber": parse_first_line(res.raw_output),
                    "architecture": safe_value_or_unknown(host_arch),
                    "evidence": {"command_run": res.command, "raw_output": res.raw_output},
                })

        elif pid == "chrome":
            cmd = r'''powershell -NoProfile -Command "
              $p1=\"$env:ProgramFiles\Google\Chrome\Application\chrome.exe\";
              $p2=\"$env:ProgramFiles(x86)\Google\Chrome\Application\chrome.exe\";
              $p=@($p1,$p2) | Where-Object { Test-Path $_ } | Select-Object -First 1;
              if($p){ (Get-Item $p).VersionInfo.ProductVersion }"'''
            res = executor.run(cmd)
            if res.raw_output:
                inv.append({
                    **t,
                    "versionNumber": parse_first_line(res.raw_output),
                    "architecture": safe_value_or_unknown(host_arch),
                    "evidence": {"command_run": res.command, "raw_output": res.raw_output},
                })

        elif pid == "pycharm":
            # PyCharm may be installed in Program Files or via Toolbox, so this is best effort
            cmd = r'''powershell -NoProfile -Command "
              $candidates = Get-ChildItem -Path $env:ProgramFiles,$env:ProgramFiles(x86) -Recurse -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -ieq 'pycharm64.exe' -or $_.Name -ieq 'pycharm.exe' } |
                Select-Object -First 1;
              if($candidates){ (Get-Item $candidates.FullName).VersionInfo.ProductVersion }"'''
            res = executor.run(cmd)
            if res.raw_output:
                inv.append({
                    **t,
                    "versionNumber": parse_first_line(res.raw_output),
                    "architecture": safe_value_or_unknown(host_arch),
                    "evidence": {"command_run": res.command, "raw_output": res.raw_output},
                })

    return inv


# ----------------------------
# Orchestration
# ----------------------------

def collect_all(scan_type: str, executor: Executor, target_host: str) -> Dict[str, Any]:
    os_key = detect_remote_os(executor) if scan_type == "remote" else _local_os_key()

    if os_key == "macos":
        system_info = macos.collect_system_info(executor)
        software = macos.collect_software_inventory(executor)
    elif os_key == "linux":
        system_info, _ = collect_linux_system_info(executor)
        software = fingerprint_software_linux(executor)
    elif os_key == "windows":
        system_info, _ = collect_windows_system_info(executor)
        software = fingerprint_software_windows(executor)
    else:


        # minimal fallback
        uname = executor.run("uname -a 2>/dev/null || ver")
        system_info = {
            "os": "unknown",
            "version": "unknown",
            "kernel": "unknown",
            "cpu": "unknown",
            "cpu_architecture": "unknown",
            "evidence": {"fallback": {"command_run": uname.command, "raw_output": uname.raw_output}},
        }
        software = []

    report = {
        "agent_metadata": {
            "timestamp": now_utc_iso(),
            "scan_type": scan_type,
            "target_host": target_host,
        },
        "system_info": {
            # keep your requested keys, plus cpu_architecture evidence-friendly extension
            "os": system_info.get("os", "unknown"),
            "version": system_info.get("version", "unknown"),
            "kernel": system_info.get("kernel", "unknown"),
            "cpu": system_info.get("cpu", "unknown"),
            "cpu_architecture": system_info.get("cpu_architecture", "unknown"),
            "evidence": system_info.get("evidence", {}),
        },
        "software_inventory": software,
    }
    return report

def _local_os_key() -> str:
    sysname = platform.system().lower()
    if "darwin" in sysname:
        return "macos"
    if "linux" in sysname:
        return "linux"
    if "windows" in sysname:
        return "windows"
    return "unknown"

def main():
    parser = argparse.ArgumentParser(description="System & Software Fingerprinting Agent")
    sub = parser.add_subparsers(dest="mode", required=True)

    p_local = sub.add_parser("local", help="Run fingerprinting on local machine")

    p_remote = sub.add_parser("remote", help="Run fingerprinting on a remote host via SSH")
    p_remote.add_argument("--host", required=True, help="Target host (IP/DNS)")
    p_remote.add_argument("--user", required=False, help="SSH username")
    p_remote.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    p_remote.add_argument("--identity-file", required=False, help="SSH identity file path (optional)")

    parser.add_argument("--out", default="fingerprint_report.json", help="Output file name")

    args = parser.parse_args()

    if args.mode == "local":
        executor = LocalExecutor()
        report = collect_all("local", executor, target_host="localhost")
    else:
        executor = SSHExecutor(host=args.host, user=args.user, port=args.port, identity_file=args.identity_file)
        report = collect_all("remote", executor, target_host=args.host)

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print(f"✅ Wrote report to {args.out}")

if __name__ == "__main__":
    main()
