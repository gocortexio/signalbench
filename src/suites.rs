// SPDX-FileCopyrightText: GoCortexIO
// SPDX-License-Identifier: AGPL-3.0-or-later

pub struct Suite {
    pub name: &'static str,
    pub description: &'static str,
    pub technique_ids: &'static [&'static str],
}

pub fn get_all_suites() -> &'static [Suite] {
    &[
        Suite {
            name: "c2-framework-profiling",
            description: "Full C2 framework traffic profile: HTTP beaconing, Stratum mining, AsyncRAT TLS handshake, DNS channel probes, SoftEther/PacketiX VPN tunnel simulation",
            technique_ids: &[
                "T1071-IOC-HTTP",
                "T1071-IOC-STRATUM",
                "T1071-IOC-ASYNCRAT",
                "T1071-IOC-DNS",
                "T1572-SOFTETHER",
            ],
        },
        Suite {
            name: "network-port-scan",
            description: "Two-phase network service discovery: common ports (1-1024 + backdoors) then targeted high-value ports",
            technique_ids: &["T1046-COMMON", "T1046-HIGH-VALUE"],
        },
    ]
}

pub fn get_suite_by_name(name: &str) -> Option<&'static Suite> {
    get_all_suites().iter().find(|s| s.name == name)
}
