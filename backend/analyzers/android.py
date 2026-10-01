"""APK / DEX / JAR / Java class static analysis.

Includes a small binary-XML (AXML) parser for AndroidManifest.xml, a DEX string
table reader and a Java class constant-pool reader. Nothing is loaded into a VM.
"""

from __future__ import annotations

import struct
import zipfile
from typing import Any

from .base import AnalysisContext, ArtifactContext, ExtractedString
from .pe import _parse_certificates

ANDROID_NS = "http://schemas.android.com/apk/res/android"
RES_IDS = {0x01010003: "name", 0x01010010: "exported", 0x01010006: "permission", 0x0101021B: "versionCode",
           0x0101021C: "versionName", 0x0101020C: "minSdkVersion", 0x01010270: "targetSdkVersion",
           0x0101000F: "debuggable", 0x01010280: "allowBackup", 0x010104EC: "usesCleartextTraffic"}
DANGEROUS_PERMISSIONS = {
    "READ_SMS": ("high", "Reads SMS messages (including one-time passcodes)."),
    "RECEIVE_SMS": ("high", "Intercepts incoming SMS."),
    "SEND_SMS": ("high", "Sends SMS (premium-rate fraud)."),
    "RECEIVE_MMS": ("medium", "Intercepts MMS."),
    "READ_CALL_LOG": ("medium", "Reads call history."),
    "PROCESS_OUTGOING_CALLS": ("medium", "Monitors/redirects outgoing calls."),
    "CALL_PHONE": ("medium", "Places calls without user interaction."),
    "READ_CONTACTS": ("medium", "Reads contacts."),
    "RECORD_AUDIO": ("medium", "Records audio."),
    "CAMERA": ("low", "Uses the camera."),
    "ACCESS_FINE_LOCATION": ("low", "Precise location."),
    "ACCESS_BACKGROUND_LOCATION": ("medium", "Location while in background."),
    "READ_PHONE_STATE": ("low", "Device identifiers / phone state."),
    "READ_PHONE_NUMBERS": ("low", "Reads phone numbers."),
    "MANAGE_EXTERNAL_STORAGE": ("medium", "Full shared-storage access."),
    "SYSTEM_ALERT_WINDOW": ("medium", "Draws over other apps (overlay phishing)."),
    "REQUEST_INSTALL_PACKAGES": ("medium", "Installs other APKs (dropper behaviour)."),
    "RECEIVE_BOOT_COMPLETED": ("low", "Starts at boot (persistence)."),
    "QUERY_ALL_PACKAGES": ("low", "Enumerates installed apps."),
    "BIND_ACCESSIBILITY_SERVICE": ("high", "Accessibility service: can read the screen and perform actions."),
    "BIND_DEVICE_ADMIN": ("high", "Device administrator: hard to uninstall, can lock/wipe."),
    "BIND_NOTIFICATION_LISTENER_SERVICE": ("medium", "Reads all notifications (OTP interception)."),
    "REQUEST_IGNORE_BATTERY_OPTIMIZATIONS": ("low", "Keeps running in background."),
    "WRITE_SETTINGS": ("low", "Modifies system settings."),
    "PACKAGE_USAGE_STATS": ("medium", "Monitors foreground apps (overlay targeting)."),
    "READ_EXTERNAL_STORAGE": ("info", "Reads shared storage."),
    "WRITE_EXTERNAL_STORAGE": ("info", "Writes shared storage."),
    "INTERNET": ("info", "Network access."),
}
SUSPICIOUS_DEX_REFS = {
    "Ldalvik/system/DexClassLoader;": ("packing", "Loads DEX code at runtime", ["T1407"]),
    "Ldalvik/system/InMemoryDexClassLoader;": ("packing", "Loads DEX code from memory", ["T1407"]),
    "Ldalvik/system/PathClassLoader;": ("packing", "Custom class loading", []),
    "Ljava/lang/Runtime;": ("execution", "Runtime.exec command execution", []),
    "Ljava/lang/ProcessBuilder;": ("execution", "Spawns processes", []),
    "Landroid/telephony/SmsManager;": ("collection", "Sends/manages SMS", ["T1636.004"]),
    "Landroid/app/admin/DevicePolicyManager;": ("privilege", "Device administration APIs", ["T1626.001"]),
    "Landroid/accessibilityservice/AccessibilityService;": ("collection", "Accessibility service implementation", []),
    "Ljavax/crypto/Cipher;": ("impact", "Cryptography", []),
    "Ljava/lang/reflect/Method;": ("packing", "Reflection (hides API usage)", []),
    "/system/bin/su": ("privilege", "Root binary path", []),
    "/system/xbin/su": ("privilege", "Root binary path", []),
    "Landroid/content/pm/PackageInstaller;": ("execution", "Installs packages", []),
}


# --------------------------------------------------------------------------------- AXML
def _string_pool(data: bytes, off: int) -> list[str]:
    _t, hsize, size, count, _styles, flags, strings_start, _ss = struct.unpack_from("<HHIIIIII", data, off)
    utf8 = bool(flags & 0x100)
    count = min(count, 200_000)
    offsets = struct.unpack_from(f"<{count}I", data, off + hsize)
    base = off + strings_start
    out = []
    for o in offsets:
        p = base + o
        try:
            if utf8:
                n = data[p]
                p += 2 if n & 0x80 else 1
                blen = data[p]
                if blen & 0x80:
                    blen = ((blen & 0x7F) << 8) | data[p + 1]
                    p += 2
                else:
                    p += 1
                out.append(data[p:p + blen].decode("utf-8", "replace"))
            else:
                n = struct.unpack_from("<H", data, p)[0]
                p += 2
                if n & 0x8000:
                    n = ((n & 0x7FFF) << 16) | struct.unpack_from("<H", data, p)[0]
                    p += 2
                out.append(data[p:p + n * 2].decode("utf-16-le", "replace"))
        except (IndexError, struct.error):
            out.append("")
    return out


def parse_axml(data: bytes) -> list[dict[str, Any]]:
    """Return a flat list of elements: {tag, depth, attrs}."""
    if len(data) < 8 or struct.unpack_from("<H", data, 0)[0] != 0x0003:
        raise ValueError("not a binary XML document")
    strings: list[str] = []
    resmap: list[int] = []
    elements = []
    depth = 0
    off = struct.unpack_from("<H", data, 2)[0]
    end = min(len(data), struct.unpack_from("<I", data, 4)[0] or len(data))
    guard = 0
    while off + 8 <= end and guard < 500_000:
        guard += 1
        ctype, hsize, csize = struct.unpack_from("<HHI", data, off)
        if csize < 8:
            break
        if ctype == 0x0001:
            strings = _string_pool(data, off)
        elif ctype == 0x0180:
            n = (csize - hsize) // 4
            resmap = list(struct.unpack_from(f"<{n}I", data, off + hsize))
        elif ctype == 0x0102:
            name_idx = struct.unpack_from("<I", data, off + 20)[0]
            attr_start, attr_size, attr_count = struct.unpack_from("<HHH", data, off + 24)
            attrs = {}
            p = off + 16 + attr_start
            for _ in range(min(attr_count, 256)):
                _ns, aname, raw, _sz, _r, dtype, adata = struct.unpack_from("<IIIHBBI", data, p)
                p += attr_size or 20
                key = strings[aname] if aname < len(strings) else ""
                if not key and aname < len(resmap):
                    key = RES_IDS.get(resmap[aname], f"res_0x{resmap[aname]:08x}")
                if raw != 0xFFFFFFFF and raw < len(strings):
                    val: Any = strings[raw]
                elif dtype == 0x12:
                    val = adata != 0
                elif dtype in (0x10,):
                    val = struct.unpack("<i", struct.pack("<I", adata))[0]
                elif dtype == 0x11:
                    val = f"0x{adata:x}"
                elif dtype == 0x03 and adata < len(strings):
                    val = strings[adata]
                elif dtype == 0x01:
                    val = f"@0x{adata:08x}"
                else:
                    val = adata
                attrs[key] = val
            tag = strings[name_idx] if name_idx < len(strings) else "?"
            elements.append({"tag": tag, "depth": depth, "attrs": attrs})
            depth += 1
        elif ctype == 0x0103:
            depth = max(0, depth - 1)
        off += csize
    return elements


def _manifest_model(elements: list[dict[str, Any]]) -> dict[str, Any]:
    model: dict[str, Any] = {"package": None, "permissions": [], "components": [], "application": {}, "sdk": {}}
    current = None
    for el in elements:
        tag, a = el["tag"], el["attrs"]
        if tag == "manifest":
            model["package"] = a.get("package")
            model["version_name"] = a.get("versionName")
            model["version_code"] = a.get("versionCode")
        elif tag == "uses-sdk":
            model["sdk"] = {"min": a.get("minSdkVersion"), "target": a.get("targetSdkVersion")}
        elif tag in ("uses-permission", "uses-permission-sdk-23"):
            if a.get("name"):
                model["permissions"].append(str(a.get("name")))
        elif tag == "application":
            model["application"] = {k: a.get(k) for k in ("name", "debuggable", "allowBackup", "usesCleartextTraffic") if k in a}
        elif tag in ("activity", "activity-alias", "service", "receiver", "provider"):
            current = {"type": tag, "name": a.get("name"), "exported": a.get("exported"), "permission": a.get("permission"),
                       "actions": [], "categories": [], "depth": el["depth"]}
            model["components"].append(current)
        elif tag == "action" and current is not None and el["depth"] > current["depth"]:
            current["actions"].append(a.get("name"))
        elif tag == "category" and current is not None and el["depth"] > current["depth"]:
            current["categories"].append(a.get("name"))
    target = model["sdk"].get("target")
    for c in model["components"]:
        if c["exported"] is None:
            # Before Android 12 a component with an intent-filter is exported by default.
            c["exported_effective"] = bool(c["actions"]) and (not isinstance(target, int) or target < 31)
        else:
            c["exported_effective"] = bool(c["exported"])
        c.pop("depth", None)
    return model


def analyze_apk(ctx: AnalysisContext, art: ArtifactContext) -> None:
    meta: dict[str, Any] = {}
    try:
        zf = zipfile.ZipFile(art.path)
    except Exception as exc:
        art.errors.append(f"apk: {exc}")
        return
    with zf:
        names = zf.namelist()
        meta["dex_files"] = [n for n in names if n.endswith(".dex")][:50]
        meta["native_libs"] = [n for n in names if n.startswith("lib/") and n.endswith(".so")][:200]
        meta["abis"] = sorted({n.split("/")[1] for n in meta["native_libs"] if n.count("/") >= 2})
        meta["assets"] = [n for n in names if n.startswith("assets/")][:300]
        try:
            info = zf.getinfo("AndroidManifest.xml")
            raw = zf.read(info) if info.file_size < 8 * 1024 * 1024 else b""
            elements = parse_axml(raw)
            meta["manifest"] = _manifest_model(elements)
        except Exception as exc:
            meta["manifest_error"] = str(exc)[:200]
            ctx.add_evidence(type="apk_manifest_malformed", category="anti_analysis", source="apk_analyzer", artifact=art,
                             title="AndroidManifest.xml could not be parsed",
                             description="Malformed manifests are a known trick to break analysis tools while remaining installable.",
                             severity="medium", confidence=0.5, reliability="medium", value=str(exc)[:200])
        certs = []
        for n in names:
            if n.upper().startswith("META-INF/") and n.upper().endswith((".RSA", ".DSA", ".EC")):
                try:
                    certs.extend(_parse_certificates(zf.read(n)[:1024 * 1024]))
                except Exception:
                    pass
        meta["certificates"] = certs
    art.metadata["apk"] = meta
    man = meta.get("manifest") or {}
    perms = man.get("permissions", [])
    short = [p.rsplit(".", 1)[-1] for p in perms]
    art.strings.extend(ExtractedString(0, "manifest", p, origin="decoded") for p in perms)
    for c in man.get("components", []):
        for a in c.get("actions", []) or []:
            if a:
                art.strings.append(ExtractedString(0, "manifest", str(a), origin="decoded"))
    art.invalidate_strings()
    for p in short:
        art.tags.add(f"perm:{p}")
    for p in short:
        if p in DANGEROUS_PERMISSIONS and DANGEROUS_PERMISSIONS[p][0] != "info":
            sev, desc = DANGEROUS_PERMISSIONS[p]
            ctx.add_evidence(
                type="android_dangerous_permission", category="mobile", source="apk_analyzer", artifact=art,
                title=f"Requests {p}", description=f"{desc} Many legitimate apps request it; it matters in combination.",
                severity=sev if sev != "high" else "medium", confidence=0.5, reliability="high", value=p,
            )
    for c in man.get("components", []):
        perm = (c.get("permission") or "")
        if perm.endswith("BIND_ACCESSIBILITY_SERVICE"):
            art.tags.add("accessibility_service")
            ctx.add_evidence(
                type="android_accessibility_service", category="mobile", source="apk_analyzer", artifact=art,
                title=f"Declares an accessibility service ({c.get('name')})",
                description="Accessibility services can read screen content and act on behalf of the user — abused by banking trojans.",
                severity="high", confidence=0.65, reliability="high", value=str(c.get("name")),
            )
        if perm.endswith("BIND_DEVICE_ADMIN"):
            art.tags.add("device_admin")
            ctx.add_evidence(
                type="android_device_admin", category="mobile", source="apk_analyzer", artifact=art,
                title=f"Declares a device-admin receiver ({c.get('name')})",
                description="Device administrators resist uninstallation and can lock or wipe the device.",
                severity="high", confidence=0.65, reliability="high", value=str(c.get("name")), mitre=["T1626.001"],
            )
        if c.get("exported_effective") and c["type"] in ("service", "receiver", "provider") and not c.get("permission"):
            ctx.add_evidence(
                type="android_exported_component", category="mobile", source="apk_analyzer", artifact=art,
                title=f"Exported {c['type']} without permission: {c.get('name')}",
                description="Other apps can invoke this component. An attack surface for the app itself.",
                severity="low", confidence=0.6, reliability="high", value=str(c.get("name")), details=c,
            )
        if "android.intent.action.BOOT_COMPLETED" in (c.get("actions") or []):
            art.tags.add("boot_receiver")
    app = man.get("application", {})
    if app.get("debuggable") is True:
        ctx.add_evidence(type="android_debuggable", category="mobile", source="apk_analyzer", artifact=art,
                         title="Application is debuggable", description="android:debuggable=true in a distributed APK.",
                         severity="low", confidence=0.7, reliability="high", value="debuggable=true")
    if any("android debug" in c["subject"].lower() for c in meta.get("certificates", [])):
        ctx.add_evidence(type="android_debug_certificate", category="signature", source="apk_analyzer", artifact=art,
                         title="Signed with the Android debug certificate",
                         description="Debug-signed APKs are not from an official store build.",
                         severity="low", confidence=0.7, reliability="high", value="CN=Android Debug")
    if man.get("package"):
        ctx.event(f"APK package {man['package']}", engine="apk_analyzer", artifact_id=art.id)


def analyze_dex(ctx: AnalysisContext, art: ArtifactContext) -> None:
    with open(art.path, "rb") as fh:
        data = fh.read(min(art.size, 128 * 1024 * 1024))
    if len(data) < 0x70:
        return
    string_ids_size, string_ids_off = struct.unpack_from("<II", data, 0x38)
    type_ids_size = struct.unpack_from("<I", data, 0x40)[0]
    method_ids_size = struct.unpack_from("<I", data, 0x58)[0]
    class_defs_size = struct.unpack_from("<I", data, 0x60)[0]
    strings = []
    for i in range(min(string_ids_size, 300_000)):
        try:
            off = struct.unpack_from("<I", data, string_ids_off + i * 4)[0]
            p = off
            while data[p] & 0x80:  # ULEB128 utf16 length
                p += 1
            p += 1
            end = data.index(b"\x00", p, p + 65536)
            strings.append(data[p:end].decode("utf-8", "replace"))
        except (ValueError, IndexError, struct.error):
            continue
    meta = {"version": data[4:7].decode("ascii", "replace"), "strings": len(strings), "types": type_ids_size,
            "methods": method_ids_size, "classes": class_defs_size}
    refs = {k: v for k, v in SUSPICIOUS_DEX_REFS.items() if any(k in s for s in strings)}
    meta["suspicious_references"] = sorted(refs)
    art.metadata["dex"] = meta
    art.strings.extend(ExtractedString(0, "dex", s[:4096], origin="dex") for s in strings if len(s) >= 5)
    art.invalidate_strings()
    for ref, (cat, desc, mitre) in refs.items():
        sev = "medium" if ref in ("Ldalvik/system/DexClassLoader;", "Ldalvik/system/InMemoryDexClassLoader;", "Landroid/telephony/SmsManager;") else "low"
        ctx.add_evidence(
            type="dex_api_reference", category=cat, source="dex_analyzer", artifact=art,
            title=f"References {ref}", description=f"{desc}. Present in many legitimate apps/libraries; relevant in combination.",
            severity=sev, confidence=0.5, reliability="high", value=ref, mitre=mitre,
        )


# --------------------------------------------------------------------------------- Java
def class_constant_strings(data: bytes) -> list[str]:
    if data[:4] != b"\xca\xfe\xba\xbe" or len(data) < 10:
        return []
    count = struct.unpack_from(">H", data, 8)[0]
    p = 10
    out = []
    i = 1
    while i < count and p < len(data):
        tag = data[p]
        p += 1
        if tag == 1:
            ln = struct.unpack_from(">H", data, p)[0]
            p += 2
            out.append(data[p:p + ln].decode("utf-8", "replace"))
            p += ln
        elif tag in (3, 4, 9, 10, 11, 12, 17, 18):
            p += 4
        elif tag in (5, 6):
            p += 8
            i += 1
        elif tag in (7, 8, 16, 19, 20):
            p += 2
        elif tag == 15:
            p += 3
        else:
            break
        i += 1
    return out


def analyze_jar(ctx: AnalysisContext, art: ArtifactContext) -> None:
    meta: dict[str, Any] = {"manifest": {}, "classes": 0}
    if art.detected_type == "class":
        with open(art.path, "rb") as fh:
            strs = class_constant_strings(fh.read(min(art.size, 16 * 1024 * 1024)))
        art.strings.extend(ExtractedString(0, "java-const", s[:4096], origin="java") for s in strs if len(s) >= 5)
        art.invalidate_strings()
        meta["classes"] = 1
        art.metadata["java"] = meta
        return
    try:
        zf = zipfile.ZipFile(art.path)
    except Exception as exc:
        art.errors.append(f"jar: {exc}")
        return
    budget = 64 * 1024 * 1024
    seen: set[str] = set()
    with zf:
        for info in zf.infolist()[:50000]:
            n = info.filename
            if n.upper() == "META-INF/MANIFEST.MF" and info.file_size < 1024 * 1024:
                text = zf.read(info).decode("utf-8", "replace")
                for line in text.splitlines():
                    if ":" in line:
                        k, v = line.split(":", 1)
                        if k.strip() in ("Main-Class", "Created-By", "Premain-Class", "Agent-Class", "Launcher-Agent-Class",
                                         "Class-Path", "Implementation-Title", "Implementation-Vendor", "Built-By"):
                            meta["manifest"][k.strip()] = v.strip()[:300]
            elif n.endswith(".class") and budget > 0 and info.file_size < 4 * 1024 * 1024:
                meta["classes"] += 1
                try:
                    raw = zf.read(info)
                except Exception:
                    continue
                budget -= len(raw)
                for s in class_constant_strings(raw):
                    if len(s) >= 5 and s not in seen and len(seen) < 200_000:
                        seen.add(s)
            elif n.endswith(".class"):
                meta["classes"] += 1
    art.metadata["java"] = meta
    art.strings.extend(ExtractedString(0, "java-const", s[:4096], origin="java") for s in seen)
    art.invalidate_strings()
    if budget <= 0:
        ctx.limitation(f"{art.display_name}: only part of the class files were inspected (size budget).")
    m = meta["manifest"]
    if m.get("Premain-Class") or m.get("Agent-Class") or m.get("Launcher-Agent-Class"):
        ctx.add_evidence(
            type="java_agent", category="injection", source="java_analyzer", artifact=art,
            title="JAR declares a Java agent", description="Java agents instrument other classes in the JVM (used by profilers/APMs and by malicious loaders).",
            severity="medium", confidence=0.55, reliability="high", value=m.get("Premain-Class") or m.get("Agent-Class"),
        )
    lows = [s.lower() for s in seen]
    risky = {
        "java/lang/runtime": "Runtime.exec", "java/lang/processbuilder": "ProcessBuilder",
        "java/net/urlclassloader": "URLClassLoader (remote code loading)", "definecalss": "",
        "javax/script/scriptenginemanager": "Script engine", "java/lang/reflect/method": "Reflection",
        "sun/misc/unsafe": "Unsafe memory access", "java/io/objectinputstream": "Java deserialization",
    }
    hits = sorted({v for k, v in risky.items() if v and any(k in s for s in lows)})
    if hits:
        meta["notable_apis"] = hits
