use std::{cell::RefCell, collections::BTreeMap, rc::Rc};
use vpnt::connection::routes::{Backend, Error, Key, NextHop, Owner, Presence, Route};

#[derive(Default)]
pub struct Table {
    pub rows: BTreeMap<Key, (Route, u64)>,
    pub next: u64,
    pub fail_create: Option<Key>,
    pub fail_remove: bool,
    pub fail_remove_key: Option<Key>,
    pub disrupted: usize,
    pub pin: Option<Key>,
}
impl Table {
    pub fn insert(&mut self, route: Route) {
        self.next += 1;
        self.rows.insert(route.key, (route, self.next));
    }
}
#[derive(Clone, Default)]
pub struct Kernel(pub Rc<RefCell<Table>>);
pub struct Receipt {
    route: Route,
    identity: u64,
}
impl Backend for Kernel {
    type Receipt = Receipt;
    fn existing(&mut self, key: Key) -> Result<Option<Route>, Error> {
        Ok(self.0.borrow().rows.get(&key).map(|(route, _)| *route))
    }
    fn create(&mut self, route: Route) -> Result<Receipt, Error> {
        let mut table = self.0.borrow_mut();
        if table.fail_create == Some(route.key) {
            return Err(Error::Unavailable);
        }
        if table.rows.contains_key(&route.key) {
            return Err(Error::Conflict);
        }
        table.insert(route);
        Ok(Receipt {
            route,
            identity: table.next,
        })
    }
    fn receipt_state(&mut self, receipt: &Receipt) -> Result<Presence, Error> {
        Ok(match self.0.borrow().rows.get(&receipt.route.key) {
            None => Presence::Absent,
            Some((route, id)) if *id == receipt.identity && *route == receipt.route => {
                Presence::Owned
            }
            Some(_) => Presence::Replaced,
        })
    }
    fn remove(&mut self, receipt: &Receipt) -> Result<(), Error> {
        if self.receipt_state(receipt)? != Presence::Owned {
            return Err(Error::Changed);
        }
        let mut table = self.0.borrow_mut();
        if table.fail_remove || table.fail_remove_key == Some(receipt.route.key) {
            return Err(Error::Unavailable);
        }
        // Model the data-plane failure caused by prematurely unpinning the
        // gateway while the new full-tunnel networks are still installed.
        if table.pin == Some(receipt.route.key)
            && table.rows.values().any(|(route, _)| {
                route.key != receipt.route.key
                    && route
                        .key
                        .network
                        .contains(receipt.route.key.network.address())
            })
        {
            table.disrupted += 1;
        }
        table.rows.remove(&receipt.route.key);
        Ok(())
    }
}
pub fn owner(name: &str, generation: u64) -> Owner {
    Owner {
        uid: 501,
        profile: name.into(),
        generation,
    }
}
pub fn route(network: &str, interface: u16) -> Route {
    Route {
        key: Key {
            network: network.parse().unwrap(),
            scope: 0,
        },
        interface,
        next_hop: NextHop::Interface,
    }
}
