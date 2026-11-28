use std::{
    io::{self, Write},
    sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
        mpsc::{Receiver, SyncSender, TrySendError, sync_channel},
    },
    thread,
};

const CAPACITY: usize = 64;
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub(crate) static BROKER: StderrSink = StderrSink::new("vpnt");
pub(crate) static ENGINE: StderrSink = StderrSink::new("vpnt-helper");

pub(crate) trait Sink: Send {
    fn record(&mut self, line: String);
}

pub(crate) struct StderrSink {
    label: &'static str,
    queue: Mutex<Queue>,
    dropped: AtomicUsize,
}

enum Queue {
    Pending,
    Active(SyncSender<Line>),
    Disabled,
}

struct Line {
    text: String,
    dropped: usize,
}

impl StderrSink {
    const fn new(label: &'static str) -> Self {
        Self {
            label,
            queue: Mutex::new(Queue::Pending),
            dropped: AtomicUsize::new(0),
        }
    }

    fn record_with<W: Write>(&self, text: String, writer: impl FnOnce() -> W + Send + 'static) {
        let Ok(mut queue) = self.queue.try_lock() else {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        };
        if matches!(*queue, Queue::Pending) {
            let (sender, receiver) = sync_channel(CAPACITY);
            let label = self.label;
            *queue = if thread::Builder::new()
                .name("vpnt-diagnostics".into())
                .spawn(move || drain(receiver, writer(), label))
                .is_ok()
            {
                Queue::Active(sender)
            } else {
                Queue::Disabled
            };
        }
        if let Queue::Active(sender) = &*queue {
            // Attach the count to the next admitted line, behind older entries.
            let dropped = self.dropped.swap(0, Ordering::Relaxed);
            let line = Line { text, dropped };
            match sender.try_send(line) {
                Ok(()) => {}
                Err(TrySendError::Full(line)) => {
                    self.dropped.fetch_add(line.dropped + 1, Ordering::Relaxed);
                }
                Err(TrySendError::Disconnected(_)) => *queue = Queue::Disabled,
            }
        }
    }
}

impl Sink for &StderrSink {
    fn record(&mut self, line: String) {
        self.record_with(line, io::stderr);
    }
}

fn drain(input: Receiver<Line>, mut writer: impl Write, label: &str) {
    for mut line in input {
        if line.dropped != 0 {
            let _ = writer
                .write_all(format!("{label}: diagnostics: dropped={}\n", line.dropped).as_bytes());
        }
        line.text.push('\n');
        let _ = writer.write_all(line.text.as_bytes());
    }
}

#[cfg(test)]
pub(crate) struct Memory<W>(pub W);

#[cfg(test)]
impl<W: Write + Send> Sink for Memory<W> {
    fn record(&mut self, line: String) {
        writeln!(self.0, "{line}").unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        sync::mpsc::{self, RecvTimeoutError, Sender},
        time::Duration,
    };

    struct BlockedWriter {
        entered: Option<Sender<()>>,
        release: Receiver<()>,
        output: Sender<Vec<u8>>,
    }

    impl Write for BlockedWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if let Some(entered) = self.entered.take() {
                let _ = entered.send(());
                if self.release.recv().is_err() {
                    return Err(io::ErrorKind::BrokenPipe.into());
                }
            }
            self.output
                .send(bytes.to_vec())
                .map_err(|_| io::ErrorKind::BrokenPipe)?;
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn broker_and_engine_diagnostics_bound_blocked_writes_and_report_drops_in_order() {
        const EVENTS: usize = 1000;
        const DEADLINE: Duration = Duration::from_secs(1);
        let sink = StderrSink::new("vpnt-helper");
        let (entered, started) = mpsc::channel();
        let (unblock, release) = mpsc::channel();
        let (output, lines) = mpsc::channel();
        sink.record_with("first".into(), || BlockedWriter {
            entered: Some(entered),
            release,
            output,
        });
        started.recv_timeout(DEADLINE).unwrap();

        let enqueue = |line| {
            sink.record_with(line, || -> BlockedWriter {
                panic!("a second writer was started")
            });
        };
        thread::scope(|scope| {
            let (done, completion) = mpsc::channel();
            let enqueue = &enqueue;
            let producer = scope.spawn(move || {
                for index in 0..EVENTS {
                    enqueue(index.to_string());
                }
                let _ = done.send(());
            });
            let result = completion.recv_timeout(DEADLINE);
            // Release the writer before any assertion, including on the blocking mutant.
            unblock.send(()).unwrap();
            producer.join().unwrap();
            assert_eq!(result, Ok(()), "producer blocked on the diagnostic writer");
        });

        assert_eq!(lines.recv_timeout(DEADLINE).unwrap(), b"first\n");
        for index in 0..CAPACITY {
            assert_eq!(
                lines.recv_timeout(DEADLINE).unwrap(),
                format!("{index}\n").as_bytes()
            );
        }
        enqueue("after".into());
        assert_eq!(
            lines.recv_timeout(DEADLINE).unwrap(),
            format!("vpnt-helper: diagnostics: dropped={}\n", EVENTS - CAPACITY).as_bytes()
        );
        assert_eq!(lines.recv_timeout(DEADLINE).unwrap(), b"after\n");
        drop(sink);
        assert_eq!(
            lines.recv_timeout(DEADLINE),
            Err(RecvTimeoutError::Disconnected)
        );
    }
}
