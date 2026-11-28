//! Fixed states of the Linux Fortinet client, for the instance's journal.
//!
//! A line of `openfortivpn` or `pppd` output becomes at most one label compiled
//! into this binary. Nothing the client or the gateway printed is copied: lines
//! matched by their start (an interface, a terminal, an address or a reason
//! follows) give the same label whatever comes after.

use std::{fmt, io::Write, sync::Mutex};

const JOURNAL_PREFIX: &str = "vpnt-tunneld: fortinet client: ";

/// Lines recognized whole, with their label. The `INFO:` and `ERROR:` ones are
/// printed by `openfortivpn`; the others by `pppd` through `logfd`.
const LINES: [(&str, &str); 14] = [
    ("INFO:   Connected to gateway.", "Connected to gateway."),
    ("INFO:   Authenticated.", "Authenticated."),
    (
        "INFO:   Remote gateway has allocated a VPN.",
        "Remote gateway has allocated a VPN.",
    ),
    (
        "ERROR:  IPCP rejected by the Fortinet local IPv4 policy.",
        "IPCP rejected by the Fortinet local IPv4 policy.",
    ),
    (
        "ERROR:  Timed out waiting for the ppp interface to be UP.",
        "Timed out waiting for the ppp interface to be UP.",
    ),
    (
        "ERROR:  VPN establishment deadline expired or unavailable.",
        "VPN establishment deadline expired or unavailable.",
    ),
    (
        "INFO:   Tunnel is up and running.",
        "Tunnel is up and running.",
    ),
    (
        "LCP: timeout sending Config-Requests",
        "LCP: timeout sending Config-Requests",
    ),
    (
        "IPCP: timeout sending Config-Requests",
        "IPCP: timeout sending Config-Requests",
    ),
    (
        "Peer refused to agree to his IP address",
        "Peer refused to agree to his IP address",
    ),
    (
        "Peer refused to agree to our IP address",
        "Peer refused to agree to our IP address",
    ),
    (
        "Could not determine local IP address",
        "Could not determine local IP address",
    ),
    ("Modem hangup", "Modem hangup"),
    ("Connection terminated.", "Connection terminated."),
];

/// Lines recognized by their start, with their label. What follows is never
/// copied.
const STARTS: [(&str, &str); 6] = [
    ("Using interface ", "Using interface"),
    ("Connect: ", "Connect"),
    ("LCP terminated by peer", "LCP terminated by peer"),
    ("IPCP terminated by peer", "IPCP terminated by peer"),
    // pppd prints two spaces after "local".
    ("local  IP address ", "local IP address"),
    ("remote IP address ", "remote IP address"),
];

/// The label of a client line, without its newline; `None` for any other line.
pub(crate) fn classify(line: &[u8]) -> Option<&'static str> {
    LINES
        .iter()
        .find(|(whole, _)| line == whole.as_bytes())
        .or_else(|| {
            STARTS
                .iter()
                .find(|(start, _)| line.starts_with(start.as_bytes()))
        })
        .map(|&(_, label)| label)
}

/// The journal of one attempt, shared by the drains of the client's pipes.
///
/// `note` writes each label once, as `vpnt-tunneld: fortinet client: <label>`,
/// with one write call while holding the lock. The write happens on the drain
/// thread and may block it: the whole output of an attempt is one short line per
/// label. A failed write is not retried, as the journal is the only place that
/// could report it.
pub(crate) struct StateJournal(Mutex<(Vec<&'static str>, Box<dyn Write + Send>)>);

impl fmt::Debug for StateJournal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("StateJournal")
    }
}

impl StateJournal {
    pub(crate) fn new(writer: impl Write + Send + 'static) -> Self {
        Self(Mutex::new((Vec::new(), Box::new(writer))))
    }

    pub(crate) fn note(&self, line: &[u8]) {
        let Some(label) = classify(line) else {
            return;
        };
        let mut journal = self.0.lock().unwrap_or_else(|error| error.into_inner());
        let (written, writer) = &mut *journal;
        if written.contains(&label) {
            return;
        }
        written.push(label);
        let _ = writer.write_all(format!("{JOURNAL_PREFIX}{label}\n").as_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[derive(Clone, Default)]
    struct Shared(Arc<Mutex<Vec<u8>>>);

    impl Write for Shared {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl Shared {
        fn text(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }
    }

    /// Every recognized line as the packaged client and pppd 2.5.4 print it.
    const TABLE: [(&str, &str); 20] = [
        ("INFO:   Connected to gateway.", "Connected to gateway."),
        ("INFO:   Authenticated.", "Authenticated."),
        (
            "INFO:   Remote gateway has allocated a VPN.",
            "Remote gateway has allocated a VPN.",
        ),
        (
            "ERROR:  IPCP rejected by the Fortinet local IPv4 policy.",
            "IPCP rejected by the Fortinet local IPv4 policy.",
        ),
        (
            "ERROR:  Timed out waiting for the ppp interface to be UP.",
            "Timed out waiting for the ppp interface to be UP.",
        ),
        (
            "ERROR:  VPN establishment deadline expired or unavailable.",
            "VPN establishment deadline expired or unavailable.",
        ),
        (
            "INFO:   Tunnel is up and running.",
            "Tunnel is up and running.",
        ),
        ("Using interface ppp0", "Using interface"),
        ("Connect: vpntp1 <--> /dev/pts/3", "Connect"),
        (
            "LCP: timeout sending Config-Requests",
            "LCP: timeout sending Config-Requests",
        ),
        (
            "IPCP: timeout sending Config-Requests",
            "IPCP: timeout sending Config-Requests",
        ),
        (
            "Peer refused to agree to his IP address",
            "Peer refused to agree to his IP address",
        ),
        (
            "Peer refused to agree to our IP address",
            "Peer refused to agree to our IP address",
        ),
        (
            "Could not determine local IP address",
            "Could not determine local IP address",
        ),
        ("Modem hangup", "Modem hangup"),
        (
            "LCP terminated by peer (user alice at 10.1.2.3)",
            "LCP terminated by peer",
        ),
        ("IPCP terminated by peer", "IPCP terminated by peer"),
        ("Connection terminated.", "Connection terminated."),
        ("local  IP address 10.99.0.2", "local IP address"),
        ("remote IP address 169.254.2.1", "remote IP address"),
    ];

    #[test]
    fn every_recognized_line_has_its_fixed_label() {
        for (line, label) in TABLE {
            assert_eq!(classify(line.as_bytes()), Some(label), "{line}");
        }
        let mut labels: Vec<&str> = TABLE.iter().map(|(_, label)| *label).collect();
        labels.sort_unstable();
        labels.dedup();
        assert_eq!(labels.len(), TABLE.len(), "two lines share a label");
    }

    #[test]
    fn what_follows_a_fixed_start_never_reaches_the_journal() {
        const STARTS: [(&str, &str); 6] = [
            ("Using interface ", "Using interface"),
            ("Connect: ", "Connect"),
            ("LCP terminated by peer", "LCP terminated by peer"),
            ("IPCP terminated by peer", "IPCP terminated by peer"),
            ("local  IP address ", "local IP address"),
            ("remote IP address ", "remote IP address"),
        ];
        const TAIL: &[u8] =
            b"alice 10.20.30.40 SVPNCOOKIE=hunter2 \xff\x1b[31m Peer refused to agree to his IP address";
        for (start, label) in STARTS {
            let mut line = start.as_bytes().to_vec();
            line.extend_from_slice(TAIL);
            assert_eq!(classify(&line), Some(label), "{start}");
            let output = Shared::default();
            StateJournal::new(output.clone()).note(&line);
            assert_eq!(
                output.text(),
                format!("vpnt-tunneld: fortinet client: {label}\n")
            );
        }
    }

    #[test]
    fn anything_else_has_no_label_and_writes_nothing() {
        let mut hostile: Vec<Vec<u8>> = [
            "",
            "alice",
            "10.20.30.40",
            "SVPNCOOKIE=hunter2",
            "INFO:   Got addresses: [10.20.30.40], ns [10.20.30.41, 10.20.30.42]",
            "ERROR:  Could not authenticate user alice",
            "INFO:   vpnt: split-route 10.0.0.0/255.0.0.0",
            "INFO:   Authenticated. user=alice 10.20.30.40",
            "INFO:   Authenticated",
            "Authenticated.",
            " INFO:   Authenticated.",
            "INFO:   authenticated.",
            "DEBUG:  Connected to gateway.",
            "Peer refused to agree to his IP address 10.20.30.40",
            "Modem hangup alice",
            "Connection terminated. 10.20.30.40",
            "x Using interface ppp0",
            "Using interface",
            "using interface ppp0",
            "Connect:",
            "local IP address 10.20.30.40",
            "local  LL address fe80::1",
            "CCP terminated by peer (alice)",
        ]
        .iter()
        .map(|line| line.as_bytes().to_vec())
        .collect();
        // Every whole line of the table stops matching with anything around it.
        // The IPCP termination is matched by its start, although its sample has
        // no tail.
        let whole = TABLE
            .iter()
            .filter(|(line, label)| line.ends_with(label) && *label != "IPCP terminated by peer");
        let mut count = 0;
        for (line, _) in whole {
            hostile.push(format!("{line} alice@10.20.30.40").into_bytes());
            hostile.push(format!("alice {line}").into_bytes());
            count += 1;
        }
        assert_eq!(count, 14, "every whole line is covered");
        let output = Shared::default();
        let journal = StateJournal::new(output.clone());
        for line in &hostile {
            assert_eq!(classify(line), None, "{:?}", String::from_utf8_lossy(line));
            journal.note(line);
        }
        assert_eq!(output.text(), "");
    }

    #[test]
    fn each_label_is_written_once_per_journal() {
        let output = Shared::default();
        let journal = StateJournal::new(output.clone());
        for line in [
            "Using interface ppp0",
            "Using interface ppp1",
            "Modem hangup",
            "Using interface ppp0",
            "Modem hangup",
        ] {
            journal.note(line.as_bytes());
        }
        assert_eq!(
            output.text(),
            "vpnt-tunneld: fortinet client: Using interface\n\
             vpnt-tunneld: fortinet client: Modem hangup\n"
        );
        // Another attempt has its own journal.
        let next = Shared::default();
        StateJournal::new(next.clone()).note(b"Modem hangup");
        assert_eq!(next.text(), "vpnt-tunneld: fortinet client: Modem hangup\n");
    }
}
