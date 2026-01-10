package scoring

func (s *Store) seedBuiltinRules() error {
	builtinRules := []Rule{
		// Reductions (negative scores)
		{Name: "Double dots", Description: "Reduce score for double dot patterns", MatchType: MatchContains, Pattern: "..", Score: -5, Enabled: true, IsBuiltin: true, Category: "Reductions"},
		{Name: "Triple spaces", Description: "Reduce score for excessive spaces", MatchType: MatchContains, Pattern: "   ", Score: -5, Enabled: true, IsBuiltin: true, Category: "Reductions"},
		{Name: "WinRAR SFX", Description: "Packer string", MatchType: MatchRegex, Pattern: `WinRAR\\SFX`, Score: -4, Enabled: true, IsBuiltin: true, Category: "Reductions"},
		{Name: "Zero chains", Description: "Chains of zeros", MatchType: MatchContains, Pattern: "0000000000", Score: -5, Enabled: true, IsBuiltin: true, Category: "Reductions"},
		{Name: "Certificate keywords", Description: "Certificate-related strings", MatchType: MatchRegex, Pattern: `(?i)(thawte|trustcenter|signing|class|crl|CA|certificate|assembly)`, Score: -4, Enabled: true, IsBuiltin: true, Category: "Reductions"},
		{Name: "Alphabet sequence", Description: "Common test strings", MatchType: MatchRegex, Pattern: `(?i)(abcdefghijklmnopqsst|ABCDEFGHIJKLMNOPQRSTUVWXYZ|0123456789:;)`, Score: -5, Enabled: true, IsBuiltin: true, Category: "Reductions"},
		{Name: "Rundll32 ending", Description: "Common system file", MatchType: MatchRegex, Pattern: `(?i)rundll32\.exe$`, Score: -4, Enabled: true, IsBuiltin: true, Category: "Reductions"},
		{Name: "Kernel dll ending", Description: "Common system file", MatchType: MatchRegex, Pattern: `(?i)kernel\.dll$`, Score: -4, Enabled: true, IsBuiltin: true, Category: "Reductions"},

		// File paths (+2 to +4)
		{Name: "Drive letter path", Description: "Windows drive path", MatchType: MatchRegex, Pattern: `[A-Za-z]:\\`, Score: 2, Enabled: true, IsBuiltin: true, Category: "File Paths"},
		{Name: "File extensions", Description: "Relevant file extensions", MatchType: MatchRegex, Pattern: `(?i)\.(exe|pdb|scr|log|cfg|txt|dat|msi|com|bat|dll|pdb|vbs|tmp|sys|ps1|vbp|hta|lnk)`, Score: 4, Enabled: true, IsBuiltin: true, Category: "File Paths"},
		{Name: "Drive letter C-Z", Description: "Drive path", MatchType: MatchRegex, Pattern: `[C-Zc-z]:\\`, Score: 4, Enabled: true, IsBuiltin: true, Category: "File Paths"},
		{Name: "Directory path", Description: "Full directory path", MatchType: MatchRegex, Pattern: `([a-zA-Z]:|^|%)\\[A-Za-z]{4,30}\\`, Score: 4, Enabled: true, IsBuiltin: true, Category: "File Paths"},
		{Name: "Executable no dir", Description: "Executable name without directory", MatchType: MatchRegex, Pattern: `(?i)^[^\\]+\.(exe|com|scr|bat|sys)$`, Score: 4, Enabled: true, IsBuiltin: true, Category: "File Paths"},
		{Name: "Generic extension", Description: "Any 3-letter extension", MatchType: MatchRegex, Pattern: `\.[a-zA-Z]{3}\b`, Score: 3, Enabled: true, IsBuiltin: true, Category: "File Paths"},
		{Name: "Program path not Windows", Description: "C:\\ path not to Programs or Windows", MatchType: MatchRegex, Pattern: `^[Cc]:\\\\[^PW]`, Score: 3, Enabled: true, IsBuiltin: true, Category: "File Paths"},
		{Name: "Compiler output dirs", Description: "Release/Debug/bin paths", MatchType: MatchRegex, Pattern: `(?i)(\\Release\\|\\Debug\\|\\bin|\\sbin)`, Score: 2, Enabled: true, IsBuiltin: true, Category: "File Paths"},

		// System keywords (+5)
		{Name: "System commands", Description: "cmd.exe, system32, etc.", MatchType: MatchRegex, Pattern: `(?i)(cmd\.exe|system32|users|Documents and|SystemRoot|Grant|hello|password|process|log)`, Score: 5, Enabled: true, IsBuiltin: true, Category: "System"},
		{Name: "TEMP directories", Description: "Temp folder keywords", MatchType: MatchRegex, Pattern: `(?i)(TEMP|Temporary|Appdata|Recycler)`, Score: 4, Enabled: true, IsBuiltin: true, Category: "System"},
		{Name: "User profiles", Description: "User profile paths", MatchType: MatchRegex, Pattern: `(?i)[\\](users|profiles|username|benutzer|Documents and Settings|Utilisateurs|Utenti|Usuários)[\\]`, Score: 3, Enabled: true, IsBuiltin: true, Category: "System"},
		{Name: "File system strings", Description: "File system elements", MatchType: MatchRegex, Pattern: `(?i)(cmd|com|pipe|tmp|temp|recycle|bin|secret|private|AppData|driver|config)`, Score: 3, Enabled: true, IsBuiltin: true, Category: "System"},
		{Name: "System process names", Description: "Known system files", MatchType: MatchRegex, Pattern: `(LSASS|SAM|lsass\.exe|cmd\.exe|LSASRV\.DLL)`, Score: 4, Enabled: true, IsBuiltin: true, Category: "System"},
		{Name: "Special kernel strings", Description: "Kernel mode strings", MatchType: MatchRegex, Pattern: `(?i)(\\\\\.\\|kernel|\.dll|usage|\\DosDevices\\)`, Score: 5, Enabled: true, IsBuiltin: true, Category: "System"},

		// Protocol keywords (+5)
		{Name: "Protocol keywords", Description: "Network protocol keywords", MatchType: MatchRegex, Pattern: `(?i)(ftp|irc|smtp|command|GET|POST|Agent|tor2web|HEAD)`, Score: 5, Enabled: true, IsBuiltin: true, Category: "Network"},
		{Name: "Connection keywords", Description: "Connection-related strings", MatchType: MatchRegex, Pattern: `(?i)(error|http|closed|fail|version|proxy)`, Score: 3, Enabled: true, IsBuiltin: true, Category: "Network"},
		{Name: "Browser User Agents", Description: "HTTP user agent strings", MatchType: MatchRegex, Pattern: `(?i)(Mozilla|MSIE|Windows NT|Macintosh|Gecko|Opera|User\-Agent)`, Score: 5, Enabled: true, IsBuiltin: true, Category: "Network"},
		{Name: "Network keywords", Description: "Socket/network terms", MatchType: MatchRegex, Pattern: `(?i)(address|port|listen|remote|local|process|service|mutex|pipe|frame|key|lookup|connection)`, Score: 3, Enabled: true, IsBuiltin: true, Category: "Network"},
		{Name: "IP address", Description: "IPv4 address pattern", MatchType: MatchRegex, Pattern: `\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`, Score: 5, Enabled: true, IsBuiltin: true, Category: "Network"},

		// Malware keywords (+5)
		{Name: "Hacking tools", Description: "Hack tool keywords", MatchType: MatchRegex, Pattern: `(?i)(scan|sniff|poison|intercept|fake|spoof|sweep|dump|flood|inject|forward|scan|vulnerable|credentials|creds|coded|p0c|Content|host)`, Score: 5, Enabled: true, IsBuiltin: true, Category: "Malware"},
		{Name: "RAT keywords", Description: "RAT/malware keywords", MatchType: MatchRegex, Pattern: `(?i)(spy|logger|dark|cryptor|RAT\b|eye|comet|evil|xtreme|poison|meterpreter|metasploit|/veil|Blood)`, Score: 5, Enabled: true, IsBuiltin: true, Category: "Malware"},
		{Name: "Malicious intent", Description: "Attack-related keywords", MatchType: MatchRegex, Pattern: `(?i)(loader|cmdline|ntlmhash|lmhash|infect|encrypt|exec|elevat|dump|target|victim|override|traverse|mutex|pawnde|exploited|shellcode|injected|spoofed|dllinjec|exeinj|reflective|payload|inject|back conn)`, Score: 5, Enabled: true, IsBuiltin: true, Category: "Malware"},
		{Name: "Privilege escalation", Description: "Privilege keywords", MatchType: MatchRegex, Pattern: `(?i)(administrator|highest|system|debug|dbg|admin|adm|root) privilege`, Score: 4, Enabled: true, IsBuiltin: true, Category: "Malware"},
		{Name: "Priv esc tools", Description: "UAC bypass tools", MatchType: MatchRegex, Pattern: `(?i)(sysprep|cryptbase|secur32)`, Score: 2, Enabled: true, IsBuiltin: true, Category: "Malware"},
		{Name: "Mutex/Named Pipes", Description: "IPC mechanisms", MatchType: MatchRegex, Pattern: `(?i)(Mutex|NamedPipe|\\Global\\|\\pipe\\)`, Score: 3, Enabled: true, IsBuiltin: true, Category: "Malware"},
		{Name: "Attack keywords", Description: "Attack-related terms", MatchType: MatchRegex, Pattern: `(?i)(attacker|brute force|bruteforce|connecting back|EXHAUSTIVE|exhaustion| spawn| evil| elevated)`, Score: 3, Enabled: true, IsBuiltin: true, Category: "Malware"},
		{Name: "Swear words", Description: "Profanity often in malware", MatchType: MatchRegex, Pattern: `(?i)\b(fuck|damn|shit|penis)\b`, Score: 5, Enabled: true, IsBuiltin: true, Category: "Malware"},

		// Programming/scripting (+3 to +4)
		{Name: "Programming keywords", Description: "Code execution terms", MatchType: MatchRegex, Pattern: `(?i)(execute|run|system|shell|root|cimv2|login|exec|stdin|read|process|netuse|script|share)`, Score: 3, Enabled: true, IsBuiltin: true, Category: "Programming"},
		{Name: "Credentials", Description: "Auth-related keywords", MatchType: MatchRegex, Pattern: `(?i)(user|pass|login|logon|token|cookie|creds|hash|ticket|NTLM|LMHASH|kerberos|spnego|session|identif|account|login|auth|privilege)`, Score: 3, Enabled: true, IsBuiltin: true, Category: "Programming"},
		{Name: "Variables", Description: "Environment variables", MatchType: MatchRegex, Pattern: `%[A-Z_]+%`, Score: 4, Enabled: true, IsBuiltin: true, Category: "Programming"},
		{Name: "Parameters", Description: "Command line parameters", MatchType: MatchRegex, Pattern: `(?i)( \-[a-z]{,2}[\s]?[0-9]?| /[a-z]+[\s]?[\w]*)`, Score: 4, Enabled: true, IsBuiltin: true, Category: "Programming"},
		{Name: "Parameters v2", Description: "More parameter patterns", MatchType: MatchRegex, Pattern: `( \-[a-z] | /[a-z] | \-[a-z]:[a-zA-Z]| \/[a-z]:[a-zA-Z])`, Score: 4, Enabled: true, IsBuiltin: true, Category: "Programming"},

		// PowerShell (+4)
		{Name: "PowerShell", Description: "PowerShell keywords", MatchType: MatchRegex, Pattern: `(?i)(bypass|windowstyle | hidden |-command|IEX |Invoke-Expression|Net\.Webclient|Invoke[A-Z]|Net\.WebClient|-w hidden |-encoded|-encodedcommand| -nop |MemoryLoadLibrary|FromBase64String|Download|EncodedCommand)`, Score: 4, Enabled: true, IsBuiltin: true, Category: "PowerShell"},
		{Name: "WMI", Description: "WMI command execution", MatchType: MatchRegex, Pattern: `(?i)( /c WMIC)`, Score: 3, Enabled: true, IsBuiltin: true, Category: "PowerShell"},
		{Name: "Windows commands", Description: "Suspicious Windows commands", MatchType: MatchRegex, Pattern: `(?i)( net user | net group |ping |whoami |bitsadmin |rundll32\.exe javascript:|schtasks\.exe /create|/c start )`, Score: 3, Enabled: true, IsBuiltin: true, Category: "PowerShell"},
		{Name: "Scripting strings", Description: "Script execution paths", MatchType: MatchRegex, Pattern: `(?i)(%APPDATA%|%USERPROFILE%|Public|Roaming|& del|& rm| && |script)`, Score: 3, Enabled: true, IsBuiltin: true, Category: "PowerShell"},

		// JavaScript (+3)
		{Name: "JavaScript malicious", Description: "Suspicious JS patterns", MatchType: MatchRegex, Pattern: `(?i)(new ActiveXObject\("WScript\.Shell"\)\.Run|\.Run\("cmd\.exe|\.Run\("%comspec%\)|\.Run\("c:\\Windows|\.RegisterXLL\()`, Score: 3, Enabled: true, IsBuiltin: true, Category: "JavaScript"},

		// Webshells (+2)
		{Name: "Webshell patterns", Description: "PHP webshell patterns", MatchType: MatchRegex, Pattern: `(?i)(isset\(\$post\[|isset\(\$get\[|eval\(Request)`, Score: 2, Enabled: true, IsBuiltin: true, Category: "Webshell"},

		// Suspicious words (+2 to +4)
		{Name: "Suspicious words", Description: "Hacking-related terms", MatchType: MatchRegex, Pattern: `(?i)(impersonate|drop|upload|download|execute|shell|\bcmd\b|decode|rot13|decrypt)`, Score: 2, Enabled: true, IsBuiltin: true, Category: "Suspicious"},
		{Name: "Attack indicators", Description: "Exploitation keywords", MatchType: MatchRegex, Pattern: `(?i)(\[\+\] |\[\-\] |\[\*\] |injecting|exploit|dumped|dumping|scanning|scanned|elevation|elevated|payload|vulnerable|payload|reverse connect|bind shell|reverse shell| dump | back connect |privesc|privilege escalat|debug privilege| inject |interactive shell|shell commands| spawning |\] target |\] Transmi|\] Connect|\] connect|\] Dump|\] command |\] token|\] Token |\] Firing | hashes | etc/passwd| SAM | NTML|unsupported target|race condition|Token system |LoaderConfig| add user |ile upload |ile download |Attaching to |ser has been successfully added|target system |LSA Secrets|DefaultPassword|Password: |loading dll|\.Execute\(|Shellcode|Loader|inject x86|inject x64|bypass|katz|sploit|ms[0-9][0-9][^0-9]|\bCVE[^a-zA-Z]|privilege::|lsadump|door)`, Score: 4, Enabled: true, IsBuiltin: true, Category: "Suspicious"},

		// Output patterns (+4)
		{Name: "Comment line", Description: "Log/output markers", MatchType: MatchRegex, Pattern: `^([\*\#]+ |\[[\*\-\+]\] |[\-=]> |\[[A-Za-z]\] )`, Score: 4, Enabled: true, IsBuiltin: true, Category: "Output"},
		{Name: "Output expressions", Description: "Special expressions", MatchType: MatchRegex, Pattern: `(!\.$|!!!$| :\)$| ;\)$|fucked|[\w]\.\.\.\.$)`, Score: 4, Enabled: true, IsBuiltin: true, Category: "Output"},
		{Name: "Arrow patterns", Description: "Arrow symbols in output", MatchType: MatchRegex, Pattern: `(-->|!!!| <<< | >>> )`, Score: 5, Enabled: true, IsBuiltin: true, Category: "Output"},
		{Name: "Suspicious combos", Description: "Special char patterns", MatchType: MatchRegex, Pattern: `([a-z]{4,}[!\?]|\[[\!\+\-]\] |[a-zA-Z]{4,}\.\.\.)`, Score: 3, Enabled: true, IsBuiltin: true, Category: "Output"},

		// String patterns (+2 to +3)
		{Name: "All uppercase", Description: "All uppercase 6+ chars", MatchType: MatchRegex, Pattern: `^[A-Z]{6,}$`, Score: 2, Enabled: true, IsBuiltin: true, Category: "Patterns"},
		{Name: "All lowercase", Description: "All lowercase 6+ chars", MatchType: MatchRegex, Pattern: `^[a-z]{6,}$`, Score: 2, Enabled: true, IsBuiltin: true, Category: "Patterns"},
		{Name: "Lower with space", Description: "Lowercase with spaces", MatchType: MatchRegex, Pattern: `^[a-z\s]{6,}$`, Score: 2, Enabled: true, IsBuiltin: true, Category: "Patterns"},
		{Name: "Capitalized word", Description: "Capitalized word pattern", MatchType: MatchRegex, Pattern: `^[A-Z][a-z]{5,}$`, Score: 2, Enabled: true, IsBuiltin: true, Category: "Patterns"},
		{Name: "Word with number", Description: "Word ending with number", MatchType: MatchRegex, Pattern: `^[A-Z][a-z]+[0-9]+$`, Score: 1, Enabled: true, IsBuiltin: true, Category: "Patterns"},
		{Name: "URL pattern", Description: "URL-like patterns", MatchType: MatchRegex, Pattern: `(%[a-z][:\-,;]|\\\\%s|\\\\[A-Z0-9a-z%]+\\[A-Z0-9a-z%]+)`, Score: 2, Enabled: true, IsBuiltin: true, Category: "Patterns"},
		{Name: "Date placeholders", Description: "Date format strings", MatchType: MatchRegex, Pattern: `(?i)(yyyy|hh:mm|dd/mm|mm/dd|%s:%s:)`, Score: 3, Enabled: true, IsBuiltin: true, Category: "Patterns"},
		{Name: "Format placeholders", Description: "Printf-style placeholders", MatchType: MatchRegex, Pattern: `(?i)[^A-Za-z](%s|%d|%i|%02d|%04d|%2d|%3s)[^A-Za-z]`, Score: 3, Enabled: true, IsBuiltin: true, Category: "Patterns"},
		{Name: "File name pattern", Description: "Filename with extension", MatchType: MatchRegex, Pattern: `^[a-zA-Z0-9]{3,40}\.[a-zA-Z]{3}`, Score: 3, Enabled: true, IsBuiltin: true, Category: "Patterns"},
		{Name: "Hash pattern", Description: "MD5/SHA1/SHA256 hash", MatchType: MatchRegex, Pattern: `(?i)\b([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})\b`, Score: 2, Enabled: true, IsBuiltin: true, Category: "Patterns"},
		{Name: "UNC path start", Description: "UNC path pattern", MatchType: MatchRegex, Pattern: `^\\\\`, Score: 1, Enabled: true, IsBuiltin: true, Category: "Patterns"},

		// Base64 (+5 to +7)
		{Name: "Base64 pattern", Description: "Base64 encoded string", MatchType: MatchRegex, Pattern: `^(?:[A-Za-z0-9+/]{4}){30,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$`, Score: 7, Enabled: true, IsBuiltin: true, Category: "Encoding"},
		{Name: "Base64 executable", Description: "Base64 MZ header", MatchType: MatchRegex, Pattern: `(TVqQAAMAAAAEAAAA//8AALgAAAA|TVpQAAIAAAAEAA8A//8AALgAAAA|TVqAAAEAAAAEABAAAAAAAAAAAAA|TVoAAAAAAAAAAAAAAAAAAAAAAAA|TVpTAQEAAAAEAAAA//8AALgAAAA)`, Score: 5, Enabled: true, IsBuiltin: true, Category: "Encoding"},

		// Persistence (+3)
		{Name: "Persistence", Description: "Persistence mechanisms", MatchType: MatchRegex, Pattern: `(?i)(sc\.exe |schtasks|at \\\\|at [0-9]{2}:[0-9]{2})`, Score: 3, Enabled: true, IsBuiltin: true, Category: "Persistence"},

		// Unix/Linux (+3)
		{Name: "Unix commands", Description: "Unix shell patterns", MatchType: MatchRegex, Pattern: `(?i)(;chmod |; chmod |sh -c|/dev/tcp/|/bin/telnet|selinux| shell| cp /bin/sh )`, Score: 3, Enabled: true, IsBuiltin: true, Category: "Unix"},

		// Copyright (+7)
		{Name: "Copyright owner", Description: "Malware author signatures", MatchType: MatchRegex, Pattern: `(?i)(coded | c0d3d |cr3w\b|Coded by |codedby)`, Score: 7, Enabled: true, IsBuiltin: true, Category: "Attribution"},
		{Name: "Signing certificates", Description: "Cert organization patterns", MatchType: MatchRegex, Pattern: `( Inc | Co\.|  Ltd\.,| LLC| Limited)`, Score: 2, Enabled: true, IsBuiltin: true, Category: "Attribution"},

		// UACME (+3)
		{Name: "UACME bypass", Description: "UAC bypass keywords", MatchType: MatchRegex, Pattern: `(?i)(Elevation|pwnd|pawn|elevate to)`, Score: 3, Enabled: true, IsBuiltin: true, Category: "UAC Bypass"},

		// VB Backdoors (+3)
		{Name: "VB backdoor", Description: "VB script patterns", MatchType: MatchRegex, Pattern: `(?i)(kill|wscript|plugins|svr32|Select )`, Score: 3, Enabled: true, IsBuiltin: true, Category: "VBScript"},

		// Special malware strings (+4)
		{Name: "Known malware", Description: "Known malware strings", MatchType: MatchRegex, Pattern: `(Management Support Team1|/c rundll32|DTOPTOOLZ Co\.|net start|Exec|taskkill)`, Score: 4, Enabled: true, IsBuiltin: true, Category: "Known Malware"},

		// Executable/DLL endings (+4)
		{Name: "Executable endings", Description: "PE file extensions at end", MatchType: MatchRegex, Pattern: `(?i)(\.exe|\.dll|\.sys)$`, Score: 4, Enabled: true, IsBuiltin: true, Category: "File Extensions"},

		// Implant (+1)
		{Name: "Implant keyword", Description: "Implant terminology", MatchType: MatchContains, Pattern: "implant", Score: 1, Enabled: true, IsBuiltin: true, Category: "Malware"},
	}

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() {
		_ = tx.Rollback() // Ignore error - transaction may have been committed
	}()

	stmt, err := tx.Prepare("INSERT INTO scoring_rules (name, description, match_type, pattern, score, enabled, is_builtin, category) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, r := range builtinRules {
		if _, err := stmt.Exec(r.Name, r.Description, r.MatchType, r.Pattern, r.Score, boolToInt(r.Enabled), boolToInt(r.IsBuiltin), r.Category); err != nil {
			return err
		}
	}

	return tx.Commit()
}
