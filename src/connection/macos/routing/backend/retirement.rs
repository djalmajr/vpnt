//! Passive observation only. No PID signals, ioctls or per-key deletion.
use super::*;
use crate::connection::{
    macos::{Interfaces, sink::RetiredSink},
    routes::Network,
};
use std::net::IpAddr;

pub(crate) struct Retirement {
    pub(super) owner: Option<Owner>,
    pub(super) ppp: Option<Arc<OwnedPpp>>,
    pub(super) sink: Option<RetiredSink>,
}
pub(crate) type Queue = Arc<Mutex<Vec<Retirement>>>;
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
    pub fn new(ppp: Arc<OwnedPpp>, owner: Owner, queue: Queue) -> Self {
        Self {
            resource: Some(Retirement {
                owner: Some(owner),
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
    /// Used only after the durable inventory has been committed.
    pub fn abandon(&mut self) {
        self.resource = None;
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
pub(crate) fn inventory(
    queue: &[Retirement],
    owner: &Owner,
) -> Vec<crate::connection::fence::RetiredIdentity> {
    queue
        .iter()
        .filter(|entry| entry.owner.as_ref() == Some(owner))
        .map(|entry| crate::connection::fence::RetiredIdentity {
            interface: entry
                .ppp
                .as_ref()
                .map(|ppp| crate::connection::fence::Interface {
                    name: ppp.name().to_owned(),
                    index: ppp.index(),
                }),
            sink: entry
                .sink
                .as_ref()
                .map(|sink| crate::connection::fence::Sink {
                    name: sink.name.clone(),
                    index: u32::from(sink.index),
                    source: sink.source,
                }),
        })
        .collect()
}
pub(crate) fn detach(queue: &mut Vec<Retirement>, owner: &Owner) {
    queue.retain(|entry| entry.owner.as_ref() != Some(owner));
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
    fn inventory_and_detach_use_exact_owner_and_keep_unknown_resources() {
        let first = Owner {
            uid: 501,
            profile: "first".into(),
            generation: 1,
        };
        let other = Owner {
            uid: 501,
            profile: "first".into(),
            generation: 2,
        };
        let sink = || {
            Some(RetiredSink {
                name: "utun42".into(),
                index: 234,
                source: Some("fd12::1".parse().unwrap()),
            })
        };
        let queue = Arc::new(Mutex::new(vec![
            Retirement {
                owner: Some(other.clone()),
                ppp: None,
                sink: sink(),
            },
            Retirement {
                owner: None,
                ppp: None,
                sink: sink(),
            },
        ]));
        let guard = Guard {
            resource: Some(Retirement {
                owner: Some(first.clone()),
                ppp: None,
                sink: sink(),
            }),
            queue: queue.clone(),
        };
        drop(guard);
        let mut entries = queue.lock().unwrap();
        let recorded = inventory(&entries, &first);
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].sink.as_ref().unwrap().name, "utun42");
        assert_eq!(recorded[0].sink.as_ref().unwrap().index, 234);
        assert_eq!(
            recorded[0].sink.as_ref().unwrap().source,
            Some("fd12::1".parse().unwrap())
        );
        detach(&mut entries, &first);
        assert!(inventory(&entries, &first).is_empty());
        assert_eq!(inventory(&entries, &other).len(), 1);
        assert_eq!(
            entries.iter().filter(|entry| entry.owner.is_none()).count(),
            1
        );
    }
    #[test]
    fn failed_scope_retains_retirement_until_observed_complete_including_read_errors() {
        let queue = Arc::new(Mutex::new(Vec::new()));
        let pending = || Guard {
            resource: Some(Retirement {
                owner: None,
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
