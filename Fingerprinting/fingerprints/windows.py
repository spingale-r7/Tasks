# fingerprints/windows.py
from typing import Dict, Any, List
import re


def _first_line(s: str) -> str:
    return (s.splitlines()[0].strip() if s else "").strip()


def _val_or_unknown(s: str) -> str:
    s = (s or "").strip()
    return s if s else "unknown"


def _extract_version(text: str) -> str:
    if not text:
        return ""
    m = re.search(r"(\d+(?:\.\d+){1,4})", text)
    return m.group(1) if m else ""


def collect_system_info(executor) -> Dict[str, Any]:
    evidence: Dict[str, Any] = {}

    # OS version (e.g., 10.0.22631)
    r_ver = executor.run('powershell -NoProfile -Command "(Get-ComputerInfo).WindowsVersion"')
    evidence["version"] = {"command_run": r_ver.command, "raw_output": r_ver.raw_output}
    version = _first_line(r_ver.raw_output)

    # Kernel-ish: build lab info
    r_kernel = executor.run('powershell -NoProfile -Command "(Get-ComputerInfo).WindowsBuildLabEx"')
    evidence["kernel"] = {"command_run": r_kernel.command, "raw_output": r_kernel.raw_output}
    kernel = _first_line(r_kernel.raw_output)

    r_arch = executor.run('powershell -NoProfile -Command "$env:PROCESSOR_ARCHITECTURE"')
    evidence["cpu_architecture"] = {"command_run": r_arch.command, "raw_output": r_arch.raw_output}
    arch = _first_line(r_arch.raw_output)

    r_cpu = executor.run(
        'powershell -NoProfile -Command '
        '"(Get-CimInstance Win32_Processor | Select-Object -First 1 -ExpandProperty Name)"'
    )
    evidence["cpu_model"] = {"command_run": r_cpu.command, "raw_output": r_cpu.raw_output}
    cpu_model = _first_line(r_cpu.raw_output)

    return {
        "os": "Windows",
        "version": _val_or_unknown(version),
        "kernel": _val_or_unknown(kernel),
        "cpu": _val_or_unknown(cpu_model),
        "cpu_architecture": _val_or_unknown(arch),
        "evidence": evidence,
    }


def collect_software_inventory(executor) -> List[Dict[str, Any]]:
    inventory: List[Dict[str, Any]] = []

    r_arch = executor.run('powershell -NoProfile -Command "$env:PROCESSOR_ARCHITECTURE"')
    host_arch = _first_line(r_arch.raw_output)

    # Helper: get ProductVersion from an exe path if it exists
    def exe_version_command(paths_ps_array: str) -> str:
        # paths_ps_array should be a PowerShell array string like "@('path1','path2')"
        return (
            'powershell -NoProfile -Command '
            f'"$paths={paths_ps_array}; '
            '$p=$paths | Where-Object { Test-Path $_ } | Select-Object -First 1; '
            'if($p){ (Get-Item $p).VersionInfo.ProductVersion }"'
        )

    targets = [
        {
            "productName": "Visual Studio Code",
            "productFamily": "IDE",
            "vendor": "Microsoft",
            "cmd_version": exe_version_command(
                "@("
                "'$env:LOCALAPPDATA\\Programs\\Microsoft VS Code\\Code.exe',"
                "'$env:ProgramFiles\\Microsoft VS Code\\Code.exe',"
                "'$env:ProgramFiles(x86)\\Microsoft VS Code\\Code.exe'"
                ")"
            ),
        },
        {
            "productName": "Slack",
            "productFamily": "Collaboration",
            "vendor": "Slack Technologies",
            "cmd_version": exe_version_command(
                "@("
                "'$env:LOCALAPPDATA\\slack\\slack.exe',"
                "'$env:ProgramFiles\\Slack\\slack.exe'"
                ")"
            ),
        },
        {
            "productName": "Google Chrome",
            "productFamily": "Browser",
            "vendor": "Google",
            "cmd_version": exe_version_command(
                "@("
                "'$env:ProgramFiles\\Google\\Chrome\\Application\\chrome.exe',"
                "'$env:ProgramFiles(x86)\\Google\\Chrome\\Application\\chrome.exe'"
                ")"
            ),
        },
        {
            "productName": "Docker",
            "productFamily": "Virtualization",
            "vendor": "Docker, Inc.",
            "cmd_version": 'powershell -NoProfile -Command "docker --version"'
        },
        {
            "productName": "PyCharm",
            "productFamily": "IDE",
            "vendor": "JetBrains",
            # Best-effort search (can be slow). You can narrow paths later.
            "cmd_version": (
                "powershell -NoProfile -Command "
                "\"$c=Get-ChildItem -Path $env:ProgramFiles,$env:ProgramFiles(x86) "
                "-Recurse -ErrorAction SilentlyContinue | "
                "Where-Object { $_.Name -ieq 'pycharm64.exe' -or $_.Name -ieq 'pycharm.exe' } | "
                "Select-Object -First 1; "
                "if($c){ (Get-Item $c.FullName).VersionInfo.ProductVersion }\""
            ),
        },
    ]

    for t in targets:
        r = executor.run(t["cmd_version"])
        raw = (r.raw_output or "").strip()
        if not raw:
            continue

        extracted = _extract_version(raw)
        version = extracted if extracted else _first_line(raw)

        inventory.append({
            "productName": t["productName"],
            "versionNumber": _val_or_unknown(version),
            "architecture": _val_or_unknown(host_arch),
            "productFamily": t["productFamily"],
            "vendor": t["vendor"],
            "evidence": {
                "command_run": r.command,
                "raw_output": r.raw_output,
            }
        })

    return inventory
