# fingerprints/macos.py
from typing import Dict, Any, List


def _first_line(s: str) -> str:
    return (s.splitlines()[0].strip() if s else "").strip()


def _val_or_unknown(s: str) -> str:
    s = (s or "").strip()
    return s if s else "unknown"


def collect_system_info(executor) -> Dict[str, Any]:
    """
    macOS system fingerprint + evidence.
    """
    evidence: Dict[str, Any] = {}

    r_ver = executor.run("sw_vers -productVersion")
    evidence["version"] = {"command_run": r_ver.command, "raw_output": r_ver.raw_output}
    version = _first_line(r_ver.raw_output)

    r_kernel = executor.run("uname -r")
    evidence["kernel"] = {"command_run": r_kernel.command, "raw_output": r_kernel.raw_output}
    kernel = _first_line(r_kernel.raw_output)

    r_arch = executor.run("uname -m")
    evidence["cpu_architecture"] = {"command_run": r_arch.command, "raw_output": r_arch.raw_output}
    arch = _first_line(r_arch.raw_output)

    r_cpu = executor.run("sysctl -n machdep.cpu.brand_string 2>/dev/null || sysctl -n hw.model")
    evidence["cpu_model"] = {"command_run": r_cpu.command, "raw_output": r_cpu.raw_output}
    cpu_model = _first_line(r_cpu.raw_output)

    return {
        "os": "macOS",
        "version": _val_or_unknown(version),
        "kernel": _val_or_unknown(kernel),
        "cpu": _val_or_unknown(cpu_model),
        "cpu_architecture": _val_or_unknown(arch),
        "evidence": evidence,
    }


def collect_software_inventory(executor) -> List[Dict[str, Any]]:
    """
    macOS software fingerprinting for a small target set.
    Uses Spotlight (mdfind) by bundle identifier + Info.plist version.
    """
    inventory: List[Dict[str, Any]] = []

    host_arch_res = executor.run("uname -m")
    host_arch = _first_line(host_arch_res.raw_output)

    def find_app(bundle_id: str):
        # shell-safe quoting pattern for bundle id inside mdfind query
        cmd = f'mdfind "kMDItemCFBundleIdentifier == \'{bundle_id}\'" | head -n 1'
        r = executor.run(cmd)
        return _first_line(r.raw_output), r

    def app_version(app_path: str):
        cmd = f'/usr/libexec/PlistBuddy -c "Print :CFBundleShortVersionString" "{app_path}/Contents/Info.plist" 2>/dev/null'
        r = executor.run(cmd)
        return _first_line(r.raw_output), r

    targets = [
        {
            "productName": "Visual Studio Code",
            "productFamily": "IDE",
            "vendor": "Microsoft",
            "bundle_ids": ["com.microsoft.VSCode"],
        },
        {
            "productName": "Slack",
            "productFamily": "Collaboration",
            "vendor": "Slack Technologies",
            "bundle_ids": ["com.tinyspeck.slackmacgap"],
        },
        {
            "productName": "Google Chrome",
            "productFamily": "Browser",
            "vendor": "Google",
            "bundle_ids": ["com.google.Chrome"],
        },
        {
            "productName": "Docker Desktop",
            "productFamily": "Virtualization",
            "vendor": "Docker, Inc.",
            "bundle_ids": ["com.docker.docker"],
        },
        {
            "productName": "PyCharm",
            "productFamily": "IDE",
            "vendor": "JetBrains",
            "bundle_ids": ["com.jetbrains.pycharm", "com.jetbrains.pycharm.ce"],
        },
    ]

    for t in targets:
        app_path = ""
        find_res = None

        for bid in t["bundle_ids"]:
            p, r_find = find_app(bid)
            if p:
                app_path = p
                find_res = r_find
                break

        if not app_path:
            continue  # not installed

        version, ver_res = app_version(app_path)

        inventory.append({
            "productName": t["productName"],
            "versionNumber": _val_or_unknown(version),
            "architecture": _val_or_unknown(host_arch),
            "productFamily": t["productFamily"],
            "vendor": t["vendor"],
            "evidence": {
                "command_run": find_res.command if find_res else "",
                "raw_output": find_res.raw_output if find_res else "",
                "version_command_run": ver_res.command,
                "version_raw_output": ver_res.raw_output,
            }
        })

    return inventory
