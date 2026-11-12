//! Bounded VICI transport for our private charon instances. Each connection
//! carries one command: VICI has no request IDs, and cancellation uses another
//! connection. Values may contain credentials and are never included in Debug.
use std::{
    collections::BTreeMap,
    fmt,
    io::{self, Read, Write},
};
use zeroize::Zeroizing;

const MAX_FRAME: usize = 512 * 1024;
const MAX_DEPTH: usize = 32;
const MAX_ELEMENTS: usize = 16_384;
mod client;
pub use client::{Client, CommandResult};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Io,
    Timeout,
    InvalidMessage,
    Limit,
    UntrustedPeer,
    UnknownCommand,
    UnknownEvent,
    UnexpectedPacket,
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        if matches!(
            error.kind(),
            io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
        ) {
            Self::Timeout
        } else {
            Self::Io
        }
    }
}

enum Element {
    Value(Zeroizing<Vec<u8>>),
    Section(Message),
    List(Vec<Zeroizing<Vec<u8>>>),
}

#[derive(Default)]
pub struct Message {
    elements: BTreeMap<String, Element>,
    invalid: bool,
}

impl fmt::Debug for Message {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Message([REDACTED])")
    }
}

impl Message {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn value(&mut self, key: &str, value: &[u8]) -> &mut Self {
        self.insert(key, Element::Value(Zeroizing::new(value.to_vec())));
        self
    }
    pub fn section(&mut self, key: &str, message: Message) -> &mut Self {
        self.insert(key, Element::Section(message));
        self
    }
    pub fn list<'a>(&mut self, key: &str, items: impl IntoIterator<Item = &'a [u8]>) -> &mut Self {
        self.insert(
            key,
            Element::List(
                items
                    .into_iter()
                    .map(|item| Zeroizing::new(item.to_vec()))
                    .collect(),
            ),
        );
        self
    }
    fn insert(&mut self, key: &str, value: Element) {
        // A duplicate in a locally built request is a programming error. Keep
        // the message invalid instead of silently sending the replacement.
        if self.elements.insert(key.into(), value).is_some() {
            self.invalid = true;
        }
    }
    pub fn get_value(&self, key: &str) -> Option<&[u8]> {
        match self.elements.get(key)? {
            Element::Value(value) => Some(value),
            _ => None,
        }
    }
    pub fn get_text(&self, key: &str) -> Option<&str> {
        std::str::from_utf8(self.get_value(key)?).ok()
    }
    pub fn get_section(&self, key: &str) -> Option<&Message> {
        match self.elements.get(key)? {
            Element::Section(message) => Some(message),
            _ => None,
        }
    }
    pub fn get_list(&self, key: &str) -> Option<&[Zeroizing<Vec<u8>>]> {
        match self.elements.get(key)? {
            Element::List(items) => Some(items),
            _ => None,
        }
    }
    pub fn sections(&self) -> impl Iterator<Item = (&str, &Message)> {
        self.elements
            .iter()
            .filter_map(|(name, value)| match value {
                Element::Section(message) => Some((name.as_str(), message)),
                _ => None,
            })
    }
}

#[derive(Debug)]
pub enum Packet {
    Request(String, Message),
    Response(Message),
    UnknownCommand,
    Register(String),
    Unregister(String),
    Confirm,
    UnknownEvent,
    Event(String, Message),
}

fn valid_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= 255 && name.bytes().all(|byte| byte.is_ascii_graphic())
}

struct Encoder {
    bytes: Zeroizing<Vec<u8>>,
    elements: usize,
}

impl Encoder {
    fn append(&mut self, bytes: &[u8]) -> Result<(), Error> {
        if self.bytes.len().saturating_add(bytes.len()) > MAX_FRAME {
            return Err(Error::Limit);
        }
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }
    fn name(&mut self, name: &str) -> Result<(), Error> {
        if !valid_name(name) {
            return Err(Error::InvalidMessage);
        }
        self.append(&[name.len() as u8])?;
        self.append(name.as_bytes())
    }
    fn blob(&mut self, value: &[u8]) -> Result<(), Error> {
        let length: u16 = value.len().try_into().map_err(|_| Error::Limit)?;
        self.append(&length.to_be_bytes())?;
        self.append(value)
    }
    fn tag(&mut self, tag: u8) -> Result<(), Error> {
        self.elements += 1;
        if self.elements > MAX_ELEMENTS {
            return Err(Error::Limit);
        }
        self.append(&[tag])
    }
    fn message(&mut self, message: &Message, depth: usize) -> Result<(), Error> {
        if depth > MAX_DEPTH {
            return Err(Error::Limit);
        }
        if message.invalid {
            return Err(Error::InvalidMessage);
        }
        for (name, element) in &message.elements {
            match element {
                Element::Value(value) => {
                    self.tag(3)?;
                    self.name(name)?;
                    self.blob(value)?;
                }
                Element::Section(section) => {
                    self.tag(1)?;
                    self.name(name)?;
                    self.message(section, depth + 1)?;
                    self.tag(2)?;
                }
                Element::List(items) => {
                    self.tag(4)?;
                    self.name(name)?;
                    for item in items {
                        self.tag(5)?;
                        self.blob(item)?;
                    }
                    self.tag(6)?;
                }
            }
        }
        Ok(())
    }
}

pub fn write_packet(writer: &mut impl Write, packet: &Packet) -> Result<(), Error> {
    let mut encoder = Encoder {
        // Reserve the full bounded frame once so realloc cannot leave old
        // copies of credential-bearing fragments in freed allocations.
        bytes: Zeroizing::new(Vec::with_capacity(MAX_FRAME)),
        elements: 0,
    };
    let tag = match packet {
        Packet::Request(..) => 0,
        Packet::Response(_) => 1,
        Packet::UnknownCommand => 2,
        Packet::Register(_) => 3,
        Packet::Unregister(_) => 4,
        Packet::Confirm => 5,
        Packet::UnknownEvent => 6,
        Packet::Event(..) => 7,
    };
    encoder.append(&[tag])?;
    match packet {
        Packet::Request(name, _)
        | Packet::Register(name)
        | Packet::Unregister(name)
        | Packet::Event(name, _) => encoder.name(name)?,
        _ => {}
    }
    match packet {
        Packet::Request(_, message) | Packet::Response(message) | Packet::Event(_, message) => {
            encoder.message(message, 0)?
        }
        _ => {}
    }
    writer.write_all(&(encoder.bytes.len() as u32).to_be_bytes())?;
    writer.write_all(&encoder.bytes)?;
    writer.flush()?;
    Ok(())
}

struct Decoder<'a> {
    bytes: &'a [u8],
    position: usize,
    elements: usize,
}

impl<'a> Decoder<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8], Error> {
        let end = self.position.checked_add(length).ok_or(Error::Limit)?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or(Error::InvalidMessage)?;
        self.position = end;
        Ok(value)
    }
    fn byte(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }
    fn name(&mut self) -> Result<String, Error> {
        let length = self.byte()? as usize;
        let name = std::str::from_utf8(self.take(length)?).map_err(|_| Error::InvalidMessage)?;
        if !valid_name(name) {
            return Err(Error::InvalidMessage);
        }
        Ok(name.into())
    }
    fn blob(&mut self) -> Result<Zeroizing<Vec<u8>>, Error> {
        let length = u16::from_be_bytes(
            self.take(2)?
                .try_into()
                .map_err(|_| Error::InvalidMessage)?,
        ) as usize;
        Ok(Zeroizing::new(self.take(length)?.to_vec()))
    }
    fn tag(&mut self) -> Result<u8, Error> {
        self.elements += 1;
        if self.elements > MAX_ELEMENTS {
            return Err(Error::Limit);
        }
        self.byte()
    }
    fn message(&mut self, nested: bool, depth: usize) -> Result<Message, Error> {
        if depth > MAX_DEPTH {
            return Err(Error::Limit);
        }
        let mut message = Message::new();
        while self.position < self.bytes.len() {
            let tag = self.tag()?;
            if tag == 2 && nested {
                return Ok(message);
            }
            if !matches!(tag, 1 | 3 | 4) {
                return Err(Error::InvalidMessage);
            }
            let name = self.name()?;
            if message.elements.contains_key(&name) {
                return Err(Error::InvalidMessage);
            }
            let element = match tag {
                1 => Element::Section(self.message(true, depth + 1)?),
                3 => Element::Value(self.blob()?),
                4 => {
                    let mut items = Vec::new();
                    loop {
                        match self.tag()? {
                            5 => items.push(self.blob()?),
                            6 => break,
                            _ => return Err(Error::InvalidMessage),
                        }
                    }
                    Element::List(items)
                }
                _ => unreachable!(),
            };
            message.elements.insert(name, element);
        }
        if nested {
            Err(Error::InvalidMessage)
        } else {
            Ok(message)
        }
    }
}

pub fn read_packet(reader: &mut impl Read) -> Result<Packet, Error> {
    let mut header = [0; 4];
    reader.read_exact(&mut header)?;
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 || length > MAX_FRAME {
        return Err(Error::Limit);
    }
    let mut bytes = Zeroizing::new(vec![0; length]);
    reader.read_exact(&mut bytes)?;
    let mut decoder = Decoder {
        bytes: &bytes,
        position: 0,
        elements: 0,
    };
    let packet = match decoder.byte()? {
        0 => Packet::Request(decoder.name()?, decoder.message(false, 0)?),
        1 => Packet::Response(decoder.message(false, 0)?),
        2 => Packet::UnknownCommand,
        3 => Packet::Register(decoder.name()?),
        4 => Packet::Unregister(decoder.name()?),
        5 => Packet::Confirm,
        6 => Packet::UnknownEvent,
        7 => Packet::Event(decoder.name()?, decoder.message(false, 0)?),
        _ => return Err(Error::InvalidMessage),
    };
    if decoder.position != bytes.len() {
        return Err(Error::InvalidMessage);
    }
    Ok(packet)
}
