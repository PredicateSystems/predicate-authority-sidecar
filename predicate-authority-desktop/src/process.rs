//! Spawn and supervise `predicate-authorityd` with stdout/stderr capture.

use std::collections::VecDeque;
use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread;

const MAX_LOG_LINES: usize = 5_000;

pub struct ProcessSupervisor {
    pub child: Option<Child>,
    log_rx: Option<Receiver<String>>,
}

impl Default for ProcessSupervisor {
    fn default() -> Self {
        Self {
            child: None,
            log_rx: None,
        }
    }
}

impl ProcessSupervisor {
    pub fn is_running(&self) -> bool {
        self.child.is_some()
    }

    /// Start sidecar. Global CLI flags must come before `run` subcommand.
    pub fn start(&mut self, binary: &str, args_before_run: Vec<String>) -> Result<(), String> {
        self.stop();

        let mut cmd = Command::new(binary);
        for a in &args_before_run {
            cmd.arg(a);
        }
        cmd.arg("run");
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        let mut child = cmd
            .spawn()
            .map_err(|e| format!("failed to spawn {binary}: {e}"))?;

        let (tx, rx) = mpsc::channel::<String>();

        if let Some(stdout) = child.stdout.take() {
            let tx = tx.clone();
            thread::spawn(move || {
                let reader = BufReader::new(stdout);
                for line in reader.lines().map_while(Result::ok) {
                    let _ = tx.send(format!("[stdout] {line}"));
                }
            });
        }
        if let Some(stderr) = child.stderr.take() {
            thread::spawn(move || {
                let reader = BufReader::new(stderr);
                for line in reader.lines().map_while(Result::ok) {
                    let _ = tx.send(format!("[stderr] {line}"));
                }
            });
        }

        self.child = Some(child);
        self.log_rx = Some(rx);
        Ok(())
    }

    pub fn stop(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
        self.log_rx = None;
    }

    /// Drain log lines into `buffer`, capped at `MAX_LOG_LINES`.
    pub fn drain_logs(&mut self, buffer: &mut VecDeque<String>) {
        let Some(rx) = &self.log_rx else {
            return;
        };
        while let Ok(line) = rx.try_recv() {
            buffer.push_back(line);
            while buffer.len() > MAX_LOG_LINES {
                buffer.pop_front();
            }
        }
    }

    /// If the child has exited, reap it and clear handles. Returns status once.
    pub fn poll_exit(&mut self) -> Option<std::process::ExitStatus> {
        let c = self.child.as_mut()?;
        match c.try_wait() {
            Ok(Some(status)) => {
                self.child.take();
                self.log_rx.take();
                Some(status)
            }
            Ok(None) | Err(_) => None,
        }
    }
}
