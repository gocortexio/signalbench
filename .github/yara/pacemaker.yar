/*
 * YARA Rule for PACEMAKER Credential Stealer
 * Source: Mandiant "Check Your Pulse" APT Investigation
 * Reference: https://www.mandiant.com/resources/blog/suspected-apt-actors-leverage-bypass-techniques-pulse-secure-zero-day
 *
 * This rule detects the PACEMAKER credential-stealing malware used by UNC2630 (suspected APT5)
 * against U.S. Defense Industrial Base companies from August 2020 - March 2021.
 */

rule FE_APT_Trojan_Linux_PACEMAKER {
    meta:
        author = "Mandiant"
        description = "Detects PACEMAKER credential stealer targeting Pulse Secure VPN"
        date = "2021-04-19"
        reference = "https://www.mandiant.com/resources/blog/suspected-apt-actors-leverage-bypass-techniques-pulse-secure-zero-day"
        malware_family = "PACEMAKER"
        actor = "UNC2630 (suspected APT5)"
        
    strings:
        // Proc filesystem access strings for credential extraction
        $s1 = "\x00Name:%s || Pwd:%s || AuthNum:%s\x0a\x00"
        $s2 = "\x00/proc/%d/mem\x00"
        $s3 = "\x00/proc/%s/maps\x00"
        $s4 = "\x00/proc/%s/cmdline\x00"
        
    condition:
        // Must be an ELF file
        uint32(0) == 0x464c457f and
        // Must contain all 4 signature strings
        all of ($s*)
}

rule FE_APT_Trojan_Linux32_PACEMAKER {
    meta:
        author = "Mandiant"
        description = "Detects 32-bit PACEMAKER credential stealer with x86 byte patterns"
        date = "2021-04-19"
        reference = "https://www.mandiant.com/resources/blog/suspected-apt-actors-leverage-bypass-techniques-pulse-secure-zero-day"
        malware_family = "PACEMAKER"
        actor = "UNC2630 (suspected APT5)"
        
    strings:
        // Proc filesystem access strings
        $s1 = "\x00Name:%s || Pwd:%s || AuthNum:%s\x0a\x00"
        $s2 = "\x00/proc/%d/mem\x00"
        $s3 = "\x00/proc/%s/maps\x00"
        $s4 = "\x00/proc/%s/cmdline\x00"
        
    condition:
        // Must be a 32-bit ELF file (e_ident[EI_CLASS] == ELFCLASS32)
        uint32(0) == 0x464c457f and
        uint8(4) == 1 and
        // Must contain all 4 signature strings
        all of ($s*)
}
