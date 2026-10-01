/*
   MALX core YARA rules — written for MALX, generic behaviour/technique indicators.
   A match is EVIDENCE, never a verdict: every rule documents its severity and
   the correlation engine decides what it means together with other observations.

   Required meta: description, author, reference, severity
   Optional meta: category (evidence category), mitre (comma separated), confidence
*/

rule MALX_EICAR_Test_String
{
    meta:
        description = "EICAR anti-virus test string (harmless test file)"
        author = "MALX"
        reference = "https://www.eicar.org/download-anti-malware-testfile/"
        severity = "info"
        category = "yara"
        confidence = "0.99"
    strings:
        $e = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
    condition:
        $e
}

rule MALX_UPX_Packed
{
    meta:
        description = "UPX packer markers"
        author = "MALX"
        reference = "https://upx.github.io/"
        severity = "low"
        category = "packing"
        mitre = "T1027.002"
    strings:
        $s0 = "UPX0" ascii
        $s1 = "UPX1" ascii
        $s2 = "UPX!" ascii
    condition:
        (uint16(0) == 0x5A4D or uint32(0) == 0x464C457F) and 2 of them
}

rule MALX_Base64_PE_Header
{
    meta:
        description = "Base64-encoded PE (MZ) header embedded in content"
        author = "MALX"
        reference = "https://attack.mitre.org/techniques/T1027/"
        severity = "high"
        category = "packing"
        mitre = "T1027,T1140"
    strings:
        $a = "TVqQAAMAAAAEAAAA" ascii wide
        $b = "TVpQAAIAAAAEAA" ascii wide
        $c = "TVoAAAAAAAAAAAAA" ascii wide
        $d = "TVroAAAAAAAAAAAA" ascii wide
    condition:
        any of them
}

rule MALX_PowerShell_Download_Cradle
{
    meta:
        description = "PowerShell download-and-execute cradle"
        author = "MALX"
        reference = "https://attack.mitre.org/techniques/T1059/001/"
        severity = "high"
        category = "execution"
        mitre = "T1059.001,T1105"
    strings:
        $dl1 = "DownloadString" ascii wide nocase
        $dl2 = "DownloadFile" ascii wide nocase
        $dl3 = "Invoke-WebRequest" ascii wide nocase
        $dl4 = "Net.WebClient" ascii wide nocase
        $dl5 = "Invoke-RestMethod" ascii wide nocase
        $ex1 = "IEX" ascii wide
        $ex2 = "Invoke-Expression" ascii wide nocase
        $ex3 = "Start-Process" ascii wide nocase
    condition:
        any of ($dl*) and any of ($ex*)
}

rule MALX_PowerShell_Encoded_UTF16_Base64
{
    meta:
        description = "Base64 of UTF-16LE PowerShell keywords (typical -EncodedCommand payloads)"
        author = "MALX"
        reference = "https://attack.mitre.org/techniques/T1027/"
        severity = "medium"
        category = "execution"
        mitre = "T1059.001,T1027"
    strings:
        $iex = "SQBFAFgA" ascii wide
        $invoke = "SQBuAHYAbwBrAGUALQBFAHgAcAByAGUAcwBzAGkAbwBu" ascii wide
        $dls0 = "RABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBn" ascii wide
        $dls1 = "AEQAbwB3AG4AbABvAGEAZABTAHQAcgBpAG4AZw" ascii wide
        $nobj0 = "TgBlAHcALQBPAGIAagBlAGMAdA" ascii wide
        $nobj1 = "AE4AZQB3AC0ATwBiAGoAZQBjAHQA" ascii wide
        $fb64a = "RgByAG8AbQBCAGEAcwBlADYANABTAHQAcgBpAG4AZw" ascii wide
        $fb64b = "AEYAcgBvAG0AQgBhAHMAZQA2ADQAUwB0AHIAaQBuAGc" ascii wide
    condition:
        any of them
}

rule MALX_AMSI_Bypass_Strings
{
    meta:
        description = "Strings associated with AMSI tampering"
        author = "MALX"
        reference = "https://attack.mitre.org/techniques/T1562/001/"
        severity = "high"
        category = "defense_evasion"
        mitre = "T1562.001"
    strings:
        $a = "AmsiScanBuffer" ascii wide nocase
        $b = "amsiInitFailed" ascii wide nocase
        $c = "AmsiUtils" ascii wide nocase
        $d = "amsi.dll" ascii wide nocase
    condition:
        2 of them
}

rule MALX_Inhibit_System_Recovery
{
    meta:
        description = "Commands deleting shadow copies/backups or disabling recovery"
        author = "MALX"
        reference = "https://attack.mitre.org/techniques/T1490/"
        severity = "high"
        category = "impact"
        mitre = "T1490"
    strings:
        $v1 = "vssadmin" ascii wide nocase
        $v2 = "delete shadows" ascii wide nocase
        $w1 = "shadowcopy delete" ascii wide nocase
        $b1 = "recoveryenabled no" ascii wide nocase
        $b2 = "bootstatuspolicy ignoreallfailures" ascii wide nocase
        $wb = "wbadmin delete catalog" ascii wide nocase
    condition:
        ($v1 and $v2) or $w1 or $b1 or $b2 or $wb
}

rule MALX_Ransom_Note_Language
{
    meta:
        description = "Ransom-note-like wording"
        author = "MALX"
        reference = "https://attack.mitre.org/techniques/T1486/"
        severity = "high"
        category = "impact"
        mitre = "T1486"
    strings:
        $n1 = "your files have been encrypted" ascii wide nocase
        $n2 = "all your files are encrypted" ascii wide nocase
        $n3 = "to decrypt your files" ascii wide nocase
        $n4 = "recover your files" ascii wide nocase
        $p1 = "bitcoin" ascii wide nocase
        $p2 = ".onion" ascii wide nocase
        $p3 = "decryptor" ascii wide nocase
        $p4 = "private key" ascii wide nocase
    condition:
        any of ($n*) and any of ($p*)
}

rule MALX_Browser_Credential_Store_Access
{
    meta:
        description = "References to several browser credential/cookie stores"
        author = "MALX"
        reference = "https://attack.mitre.org/techniques/T1555/003/"
        severity = "high"
        category = "credential_access"
        mitre = "T1555.003"
    strings:
        $c1 = "\\Login Data" ascii wide nocase
        $c2 = "\\Local State" ascii wide nocase
        $c3 = "logins.json" ascii wide nocase
        $c4 = "key4.db" ascii wide nocase
        $c5 = "\\Network\\Cookies" ascii wide nocase
        $c6 = "cookies.sqlite" ascii wide nocase
        $c7 = "\\Web Data" ascii wide nocase
        $c8 = "encrypted_key" ascii wide
    condition:
        3 of them
}

rule MALX_Credential_Dumping_Tool_Strings
{
    meta:
        description = "Command strings of well-known credential dumping tooling"
        author = "MALX"
        reference = "https://attack.mitre.org/techniques/T1003/001/"
        severity = "high"
        category = "credential_access"
        mitre = "T1003.001"
    strings:
        $a = "sekurlsa::logonpasswords" ascii wide nocase
        $b = "lsadump::sam" ascii wide nocase
        $c = "privilege::debug" ascii wide nocase
        $d = "sekurlsa::" ascii wide nocase
        $e = "kerberos::golden" ascii wide nocase
    condition:
        2 of them
}

rule MALX_Process_Injection_API_Set
{
    meta:
        description = "Classic remote-process injection API combination"
        author = "MALX"
        reference = "https://attack.mitre.org/techniques/T1055/"
        severity = "medium"
        category = "injection"
        mitre = "T1055"
    strings:
        $a1 = "VirtualAllocEx" ascii wide
        $a2 = "NtAllocateVirtualMemory" ascii wide
        $w1 = "WriteProcessMemory" ascii wide
        $w2 = "NtWriteVirtualMemory" ascii wide
        $t1 = "CreateRemoteThread" ascii wide
        $t2 = "NtCreateThreadEx" ascii wide
        $t3 = "QueueUserAPC" ascii wide
        $t4 = "RtlCreateUserThread" ascii wide
    condition:
        any of ($a*) and any of ($w*) and any of ($t*)
}

rule MALX_Process_Hollowing_API_Set
{
    meta:
        description = "API combination characteristic of process hollowing"
        author = "MALX"
        reference = "https://attack.mitre.org/techniques/T1055/012/"
        severity = "high"
        category = "injection"
        mitre = "T1055.012"
    strings:
        $u1 = "NtUnmapViewOfSection" ascii wide
        $u2 = "ZwUnmapViewOfSection" ascii wide
        $c1 = "SetThreadContext" ascii wide
        $c2 = "Wow64SetThreadContext" ascii wide
        $r = "ResumeThread" ascii wide
        $w = "WriteProcessMemory" ascii wide
    condition:
        any of ($u*) and any of ($c*) and $r and $w
}

rule MALX_Keylogger_API_Set
{
    meta:
        description = "Keyboard hook/polling with foreground window tracking"
        author = "MALX"
        reference = "https://attack.mitre.org/techniques/T1056/001/"
        severity = "medium"
        category = "collection"
        mitre = "T1056.001"
    strings:
        $h1 = "SetWindowsHookExA" ascii wide
        $h2 = "SetWindowsHookExW" ascii wide
        $k1 = "GetAsyncKeyState" ascii wide
        $k2 = "GetKeyState" ascii wide
        $k3 = "GetKeyboardState" ascii wide
        $f = "GetForegroundWindow" ascii wide
        $t = "GetWindowText" ascii wide
    condition:
        (any of ($h*) or 2 of ($k*)) and $f and $t
}

rule MALX_Unix_Reverse_Shell
{
    meta:
        description = "Unix reverse shell one-liners"
        author = "MALX"
        reference = "https://attack.mitre.org/techniques/T1059/004/"
        severity = "high"
        category = "network"
        mitre = "T1059.004"
    strings:
        $a = "/dev/tcp/" ascii
        $b = "bash -i >&" ascii
        $c = "nc -e /bin/sh" ascii
        $d = "nc -e /bin/bash" ascii
        $e = /socat\s+[^\n]{0,80}exec:/ nocase
        $f = "0<&196;exec 196<>" ascii
    condition:
        any of them
}

rule MALX_Crypto_Miner_Configuration
{
    meta:
        description = "Cryptocurrency miner / mining-pool configuration"
        author = "MALX"
        reference = "https://attack.mitre.org/techniques/T1496/"
        severity = "high"
        category = "impact"
        mitre = "T1496"
    strings:
        $a = "stratum+tcp://" ascii wide nocase
        $b = "stratum+ssl://" ascii wide nocase
        $c = "\"donate-level\"" ascii
        $d = "--donate-level" ascii
        $e = "xmrig" ascii wide nocase
        $f = "cryptonight" ascii wide nocase
    condition:
        any of ($a, $b) or 2 of them
}

rule MALX_PHP_Webshell_Generic
{
    meta:
        description = "PHP code evaluating request parameters (webshell pattern)"
        author = "MALX"
        reference = "https://attack.mitre.org/techniques/T1505/003/"
        severity = "high"
        category = "execution"
        mitre = "T1505.003"
    strings:
        $php = "<?php" ascii nocase
        $e1 = /(eval|assert|system|passthru|shell_exec|exec|popen)\s*\(\s*(base64_decode\s*\(\s*)?\$_(POST|GET|REQUEST|COOKIE|SERVER)/ nocase
        $e2 = /preg_replace\s*\(\s*['"][^'"]{1,40}\/e['"]/ nocase
        $e3 = /\$_(POST|GET|REQUEST)\s*\[[^\]]{1,40}\]\s*\(\s*\$_(POST|GET|REQUEST)/ nocase
    condition:
        $php and any of ($e*)
}

rule MALX_PDF_AutoRun_JavaScript
{
    meta:
        description = "PDF with automatic action and JavaScript"
        author = "MALX"
        reference = "https://attack.mitre.org/techniques/T1204/002/"
        severity = "medium"
        category = "document"
        mitre = "T1204.002,T1059.007"
    strings:
        $hdr = "%PDF-"
        $oa = "/OpenAction"
        $aa = "/AA"
        $js1 = "/JavaScript"
        $js2 = "/JS"
    condition:
        $hdr in (0..1024) and ($oa or $aa) and any of ($js*)
}

rule MALX_RTF_Equation_Editor_Object
{
    meta:
        description = "RTF document embedding an Equation Editor object"
        author = "MALX"
        reference = "https://attack.mitre.org/techniques/T1203/"
        severity = "high"
        category = "document"
        mitre = "T1203"
    strings:
        $rtf = "{\\rt"
        $eq1 = "Equation.3" ascii nocase
        $eq2 = "4571756174696f6e2e33" ascii nocase
        $obj = "\\objdata" ascii nocase
    condition:
        $rtf at 0 and $obj and any of ($eq*)
}

rule MALX_LNK_Launches_Interpreter
{
    meta:
        description = "Windows shortcut referencing a script interpreter"
        author = "MALX"
        reference = "https://attack.mitre.org/techniques/T1204/002/"
        severity = "medium"
        category = "execution"
        mitre = "T1204.002"
    strings:
        $p = "powershell" ascii wide nocase
        $c = "cmd.exe" ascii wide nocase
        $m = "mshta" ascii wide nocase
        $w = "wscript" ascii wide nocase
        $r = "rundll32" ascii wide nocase
    condition:
        uint32(0) == 0x0000004C and any of them
}

rule MALX_Chat_Webhook_Exfiltration_Channel
{
    meta:
        description = "Discord webhook / Telegram bot API endpoint"
        author = "MALX"
        reference = "https://attack.mitre.org/techniques/T1567/"
        severity = "medium"
        category = "network"
        mitre = "T1567"
    strings:
        $d = "discord.com/api/webhooks/" ascii wide nocase
        $d2 = "discordapp.com/api/webhooks/" ascii wide nocase
        $t = "api.telegram.org/bot" ascii wide nocase
    condition:
        any of them
}

rule MALX_Anti_VM_Artifacts
{
    meta:
        description = "Several virtualisation/sandbox artefact names"
        author = "MALX"
        reference = "https://attack.mitre.org/techniques/T1497/001/"
        severity = "medium"
        category = "anti_analysis"
        mitre = "T1497.001"
    strings:
        $a = "VBoxService" ascii wide nocase
        $b = "VBoxTray" ascii wide nocase
        $c = "vmtoolsd" ascii wide nocase
        $d = "VMwareService" ascii wide nocase
        $e = "SbieDll.dll" ascii wide nocase
        $f = "qemu-ga" ascii wide nocase
        $g = "vmci.sys" ascii wide nocase
        $h = "VBoxGuest" ascii wide nocase
        $i = "wine_get_unix_file_name" ascii
    condition:
        3 of them
}

rule MALX_Linux_Persistence_Locations
{
    meta:
        description = "Multiple Linux persistence locations referenced"
        author = "MALX"
        reference = "https://attack.mitre.org/techniques/T1053/003/"
        severity = "medium"
        category = "persistence"
        mitre = "T1053.003,T1546.004"
    strings:
        $a = "/etc/crontab" ascii
        $b = "/etc/rc.local" ascii
        $c = "/etc/ld.so.preload" ascii
        $d = "/.bashrc" ascii
        $e = "systemctl enable" ascii
        $f = "/etc/systemd/system/" ascii
        $g = "crontab -" ascii
        $h = "authorized_keys" ascii
    condition:
        uint32(0) == 0x464C457F and 2 of them or 3 of them
}

rule MALX_Windows_Defender_Tampering
{
    meta:
        description = "Microsoft Defender exclusion or disabling commands"
        author = "MALX"
        reference = "https://attack.mitre.org/techniques/T1562/001/"
        severity = "high"
        category = "defense_evasion"
        mitre = "T1562.001"
    strings:
        $a = "Add-MpPreference" ascii wide nocase
        $b = "ExclusionPath" ascii wide nocase
        $c = "Set-MpPreference" ascii wide nocase
        $d = "DisableRealtimeMonitoring" ascii wide nocase
        $e = "DisableAntiSpyware" ascii wide nocase
    condition:
        ($a and $b) or ($c and $d) or $e
}

rule MALX_Office_External_Template
{
    meta:
        description = "OOXML relationship to an external attached template"
        author = "MALX"
        reference = "https://attack.mitre.org/techniques/T1221/"
        severity = "high"
        category = "document"
        mitre = "T1221"
    strings:
        $t = "attachedTemplate" ascii
        $m = "TargetMode=\"External\"" ascii
        $h = /Target="https?:\/\// ascii
    condition:
        $t and $m and $h
}
