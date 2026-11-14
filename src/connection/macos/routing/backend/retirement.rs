//! Passive observation only. No PID signals, ioctls or per-key deletion.
use super::*;
use crate::connection::{
    macos::{Interfaces, sink::RetiredSink},
    routes::Network,
};
use std::net::IpAddr;

pub(super) struct Retirement {
    pub ppp: Option<Arc<OwnedPpp>>,
    pub sink: Option<RetiredSink>,
}
pub(super) type Queue = Arc<Mutex<Vec<Retirement>>>;
pub(super) fn admit(queue: &Queue) -> Result<(), Error> {
    if !queue.lock().map_err(|_| Error::Unavailable)?.is_empty() {
        return Err(Error::Busy);
    }
    Ok(())
}
/// Moving through a fallible registry never loses cleanup metadata. Fields
/// holding live descriptors must be dropped before this guard is dropped.
pub(super) struct Guard {
    resource: Option<Retirement>,
    queue: Queue,
}
impl Guard {
    pub fn new(ppp: Arc<OwnedPpp>, queue: Queue) -> Self {
        Self {
            resource: Some(Retirement {
                ppp: Some(ppp),
                sink: None,
            }),
            queue,
        }
    }
    pub fn sink(&self) -> Option<&RetiredSink> {
        self.resource
            .as_ref()
            .and_then(|resource| resource.sink.as_ref())
    }
    pub fn set_sink(&mut self, sink: Option<RetiredSink>) {
        if let Some(resource) = &mut self.resource {
            resource.sink = sink;
        }
    }
    pub fn complete(&mut self) -> Result<bool, Error> {
        self.complete_using(Retirement::complete)
    }
    fn complete_using(
        &mut self,
        check: impl FnOnce(&Retirement) -> Result<bool, Error>,
    ) -> Result<bool, Error> {
        if let Some(resource) = &self.resource {
            if !check(resource)? {
                return Ok(false);
            }
            self.resource = None;
        }
        Ok(true)
    }
}
impl Drop for Guard {
    fn drop(&mut self) {
        if let Some(resource) = self.resource.take() {
            self.queue
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .push(resource);
        }
    }
}
pub(super) fn reap(queue: &Queue) -> Result<(), Error> {
    reap_using(queue, Retirement::complete)
}
fn reap_using(
    queue: &Queue,
    mut check: impl FnMut(&Retirement) -> Result<bool, Error>,
) -> Result<(), Error> {
    let mut queue = queue.lock().map_err(|_| Error::Unavailable)?;
    let mut first_error = None;
    queue.retain(|resource| match check(resource) {
        Ok(complete) => !complete,
        Err(error) => {
            first_error.get_or_insert(error);
            true
        }
    });
    first_error.map_or(Ok(()), Err)
}
impl Retirement {
    pub fn complete(&self) -> Result<bool, Error> {
        if let Some(ppp) = &self.ppp
            && !ppp.processes_exited().map_err(|_| Error::Unavailable)?
        {
            return Ok(false);
        }
        let interfaces = Interfaces::read().map_err(|_| Error::Unavailable)?;
        let table = Snapshot::read()?;
        if let Some(sink) = &self.sink
            && !sink.gone(&interfaces, &table)
        {
            return Ok(false);
        }
        if let Some(ppp) = &self.ppp
            && !ppp_gone(ppp.index(), ppp.addresses(), &interfaces, &table)
        {
            return Ok(false);
        }
        Ok(true)
    }
}
fn ppp_gone(
    index: u32,
    sources: impl Iterator<Item = IpAddr>,
    interfaces: &Interfaces,
    table: &Snapshot,
) -> bool {
    if interfaces
        .entries
        .values()
        .any(|entry| entry.index == index)
        || table
            .records
            .iter()
            .any(|record| u32::from(record.interface) == index)
    {
        return false;
    }
    // An address may legitimately be shared by another PPP. Preserve its
    // host route; otherwise an implicit local route left on lo0 is pending.
    sources.into_iter().all(|source| {
        interfaces
            .entries
            .values()
            .any(|entry| entry.addresses.contains(&source))
            || !table
                .records
                .iter()
                .any(|record| record.key.network == Network::host(source))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connection::{
        macos::{interfaces::Interface, routing::Record},
        routes::{Key, Network},
    };
    use std::collections::{BTreeMap, BTreeSet};
    #[test]
    fn failed_scope_retains_retirement_until_observed_complete_including_read_errors() {
        let queue = Arc::new(Mutex::new(Vec::new()));
        let pending = || Guard {
            resource: Some(Retirement {
                ppp: None,
                sink: Some(RetiredSink {
                    name: "utun42".into(),
                    index: 234,
                    source: Some("fd12::1".parse().unwrap()),
                }),
            }),
            queue: queue.clone(),
        };
        // A fallible registration moves and drops this same guard; only a
        // successful observation may disarm it. No real interface is created.
        drop(pending());
        assert_eq!(queue.lock().unwrap().len(), 1);
        assert_eq!(admit(&queue), Err(Error::Busy));
        reap_using(&queue, |_| Ok(false)).unwrap();
        assert_eq!(queue.lock().unwrap().len(), 1);
        assert_eq!(
            reap_using(&queue, |_| Err(Error::Unavailable)),
            Err(Error::Unavailable)
        );
        assert_eq!(queue.lock().unwrap().len(), 1);
        reap_using(&queue, |resource| {
            let sink = resource.sink.as_ref().unwrap();
            assert_eq!(sink.index, 234);
            assert_eq!(sink.source, Some("fd12::1".parse().unwrap()));
            Ok(true)
        })
        .unwrap();
        assert!(queue.lock().unwrap().is_empty());
        admit(&queue).unwrap();
        let mut guard = pending();
        assert_eq!(
            guard.complete_using(|_| Err(Error::Changed)),
            Err(Error::Changed)
        );
        assert!(!guard.complete_using(|_| Ok(false)).unwrap());
        assert!(guard.complete_using(|_| Ok(true)).unwrap());
        drop(guard);
        assert!(
            queue.lock().unwrap().is_empty(),
            "verified cleanup must not be queued again"
        );
    }
    #[test]
    fn retirement_waits_for_unplanned_and_local_routes_but_preserves_shared_sources() {
        let ip = "10.20.0.2".parse().unwrap();
        let mut interfaces = Interfaces::default();
        let mut table = Snapshot { records: vec![] };
        assert!(ppp_gone(3, [ip].into_iter(), &interfaces, &table));
        table.records.push(Record {
            key: Key {
                network: Network::host(ip),
                scope: 0,
            },
            interface: 1,
            flags: libc::RTF_LOCAL,
            gateway: None,
            source: None,
        });
        assert!(!ppp_gone(3, [ip].into_iter(), &interfaces, &table));
        interfaces.entries = BTreeMap::from([(
            "ppp9".into(),
            Interface {
                name: "ppp9".into(),
                index: 9,
                flags: libc::IFF_UP as u32,
                addresses: BTreeSet::from([ip]),
            },
        )]);
        assert!(ppp_gone(3, [ip].into_iter(), &interfaces, &table));
        table.records[0].interface = 3;
        assert!(!ppp_gone(3, [ip].into_iter(), &interfaces, &table));
        table.records.clear();
        interfaces.entries.get_mut("ppp9").unwrap().index = 3;
        assert!(!ppp_gone(3, [ip].into_iter(), &interfaces, &table));
    }
}
