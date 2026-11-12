//! Bounded DNS-SD lookups with an explicit interface. Separate A/AAAA queries
//! prevent the first completed batch from discarding the other address family.
//! Services are deallocated on this thread before callback contexts are freed.
use super::{
    interfaces::address,
    tcp::{self, Error},
};
use std::{
    cell::UnsafeCell,
    ffi::{CString, c_char, c_void},
    net::IpAddr,
    ptr,
    sync::atomic::{AtomicBool, Ordering},
    time::Instant,
};
type Ref = *mut c_void;
type Callback = unsafe extern "C" fn(
    Ref,
    u32,
    u32,
    i32,
    *const c_char,
    *const libc::sockaddr,
    u32,
    *mut c_void,
);
// Darwin exports these public DNS-SD APIs through libSystem's dnssd reexport.
unsafe extern "C" {
    fn DNSServiceGetAddrInfo(
        reference: *mut Ref,
        flags: u32,
        index: u32,
        protocol: u32,
        hostname: *const c_char,
        callback: Option<Callback>,
        context: *mut c_void,
    ) -> i32;
    fn DNSServiceRefSockFD(reference: Ref) -> libc::c_int;
    fn DNSServiceProcessResult(reference: Ref) -> i32;
    fn DNSServiceRefDeallocate(reference: Ref);
}
struct Service(Ref);
impl Drop for Service {
    fn drop(&mut self) {
        // SAFETY: this owner holds one initialized live service reference.
        unsafe { DNSServiceRefDeallocate(self.0) }
    }
}
struct Answers {
    index: u32,
    protocol: u32,
    values: Vec<IpAddr>,
    finished: bool,
}
struct Query {
    // Declaration/drop order matters: deallocate before freeing the context.
    service: Service,
    answers: Box<UnsafeCell<Answers>>,
    fd: libc::c_int,
}
impl Query {
    fn start(host: &CString, index: u32, protocol: u32) -> Result<Self, Error> {
        let answers = Box::new(UnsafeCell::new(Answers {
            index,
            protocol,
            values: Vec::new(),
            finished: false,
        }));
        let mut reference = ptr::null_mut();
        // SAFETY: the boxed context has a stable address. No dispatch queue is
        // installed, so callbacks run only in our ProcessResult calls below.
        let result = unsafe {
            DNSServiceGetAddrInfo(
                &mut reference,
                0,
                index,
                protocol,
                host.as_ptr(),
                Some(answer),
                answers.get().cast(),
            )
        };
        if result != 0 || reference.is_null() {
            return Err(Error::Failed);
        }
        let service = Service(reference);
        // SAFETY: service owns the initialized live reference.
        let fd = unsafe { DNSServiceRefSockFD(service.0) };
        if fd < 0 {
            return Err(Error::Failed);
        }
        Ok(Self {
            service,
            answers,
            fd,
        })
    }
    fn answers(&self) -> &Answers {
        // SAFETY: callbacks execute synchronously on this thread only inside
        // ProcessResult. No reference returned here is retained across that call.
        unsafe { &*self.answers.get() }
    }
    fn fail(&self) {
        // SAFETY: no callback/Answers borrow overlaps this same-thread update.
        unsafe { &mut *self.answers.get() }.finished = true;
    }
}
unsafe extern "C" fn answer(
    _: Ref,
    flags: u32,
    index: u32,
    error: i32,
    _: *const c_char,
    value: *const libc::sockaddr,
    _: u32,
    context: *mut c_void,
) {
    if context.is_null() {
        return;
    }
    // SAFETY: Query retains this box on the same thread until its service is
    // deallocated. No callback can run concurrently with this exclusive borrow.
    let answers = unsafe { &mut *context.cast::<Answers>() };
    if error != 0 {
        answers.finished = true;
        return;
    }
    // LocalOnly records include /etc/hosts. They are addresses to test, not
    // proof of tunnel traffic; the probe separately rejects all local targets.
    if index == 0 || index == u32::MAX || index == answers.index {
        // SAFETY: DNS-SD supplies a sockaddr valid for this callback. The native
        // parser checks family/length before reading the corresponding fields.
        if let Some(value) = unsafe { address(value) }
            && (value.is_ipv4() == (answers.protocol == 1))
        {
            if flags & 2 == 0 {
                answers.values.retain(|old| *old != value);
            } else if !answers.values.contains(&value) && answers.values.len() < 8 {
                answers.values.push(value);
            }
        }
    }
    if flags & 1 == 0 || answers.values.len() == 8 {
        answers.finished = true;
    }
}
pub(super) fn resolve(
    host: &str,
    index: u32,
    protocol: u32,
    deadline: Instant,
    canceled: &AtomicBool,
) -> Result<Vec<IpAddr>, Error> {
    if canceled.load(Ordering::Acquire) {
        return Err(Error::Canceled);
    }
    if deadline <= Instant::now() {
        return Err(Error::TimedOut);
    }
    if index == 0 || protocol == 0 || protocol & !3 != 0 || host.is_empty() || host.len() > 253 {
        return Err(Error::Invalid);
    }
    if let Ok(value) = host.parse::<IpAddr>() {
        let family = if value.is_ipv4() { 1 } else { 2 };
        return if protocol & family != 0 {
            Ok(vec![value])
        } else {
            Err(Error::Invalid)
        };
    }
    let host = CString::new(host).map_err(|_| Error::Invalid)?;
    let mut queries: Vec<_> = [1, 2]
        .into_iter()
        .filter(|family| protocol & family != 0)
        .filter_map(|family| Query::start(&host, index, family).ok())
        .collect();
    if queries.is_empty() {
        return Err(Error::Failed);
    }
    while queries.iter().any(|query| !query.answers().finished) {
        let mut descriptors: Vec<_> = queries
            .iter()
            .map(|query| libc::pollfd {
                fd: if query.answers().finished {
                    -1
                } else {
                    query.fd
                },
                events: libc::POLLIN,
                revents: 0,
            })
            .collect();
        match tcp::wait_ready(&mut descriptors, deadline, canceled) {
            Err(Error::TimedOut) => break,
            Err(error) => return Err(error),
            Ok(()) => {}
        }
        for (query, descriptor) in queries.iter_mut().zip(descriptors) {
            if descriptor.revents & libc::POLLIN != 0 {
                // SAFETY: readability was observed on this live service socket.
                // Processing/callbacks complete before any Query can be dropped.
                if unsafe { DNSServiceProcessResult(query.service.0) } != 0 {
                    query.fail();
                }
            } else if descriptor.revents != 0 {
                query.fail();
            }
        }
    }
    if canceled.load(Ordering::Acquire) {
        return Err(Error::Canceled);
    }
    let values = queries
        .iter()
        .flat_map(|query| query.answers().values.iter().copied())
        .collect::<Vec<_>>();
    if values.is_empty() {
        Err(Error::Failed)
    } else {
        Ok(values)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{ffi::CString, time::Duration};
    #[test]
    fn native_localhost_queries_collect_both_families_and_reject_canceled_work() {
        let name = CString::new("lo0").unwrap();
        // SAFETY: name is a live NUL-terminated interface name.
        let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
        let canceled = AtomicBool::new(false);
        let deadline = Instant::now() + Duration::from_secs(2);
        let values = resolve("localhost", index, 3, deadline, &canceled).unwrap();
        assert!(values.contains(&"127.0.0.1".parse().unwrap()));
        assert!(values.contains(&"::1".parse().unwrap()));
        assert_eq!(
            resolve("::1", index, 1, deadline, &canceled),
            Err(Error::Invalid)
        );
        canceled.store(true, Ordering::Release);
        assert_eq!(
            resolve("localhost", index, 3, deadline, &canceled),
            Err(Error::Canceled)
        );
        assert_eq!(
            resolve("127.0.0.1", index, 1, deadline, &canceled),
            Err(Error::Canceled)
        );
    }
}
