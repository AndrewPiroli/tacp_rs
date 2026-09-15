use std::io::{BufRead, BufReader};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

pub struct ProcessHandle {
    process: Child,
    stdout: Arc<Mutex<String>>,
    stderr: Arc<Mutex<String>>,
    readers: Vec<JoinHandle<()>>,
    status: Option<ExitStatus>,
}

impl ProcessHandle {
    pub fn wait(&mut self, timeout: Duration) -> std::io::Result<Option<ExitStatus>> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = self.process.try_wait()? {
                self.status = Some(status);
                self.join_readers();
                return Ok(Some(status));
            }
            if Instant::now() >= deadline {
                return Ok(None);
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    pub fn output(&self) -> (String, String) {
        (
            self.stdout.lock().unwrap().clone(),
            self.stderr.lock().unwrap().clone(),
        )
    }

    pub fn terminate(&mut self) {
        if self.status.is_none() {
            match self.process.try_wait() {
                Ok(Some(status)) => self.status = Some(status),
                Ok(None) => {
                    let _ = self.process.kill();
                    self.status = self.process.wait().ok();
                }
                Err(_) => {
                    let _ = self.process.kill();
                    self.status = self.process.wait().ok();
                }
            }
        }
        self.join_readers();
    }

    fn join_readers(&mut self) {
        for reader in self.readers.drain(..) {
            let _ = reader.join();
        }
    }
}

impl Drop for ProcessHandle {
    fn drop(&mut self) {
        self.terminate();
    }
}

pub fn cargo_run(bin: &str, args: &[&str], envs: &[(&str, &str)]) -> ProcessHandle {
    let mut command = escargot::CargoBuild::new()
        .package(bin)
        .bin(bin)
        .current_release()
        .current_target()
        .run()
        .unwrap_or_else(|error| panic!("failed to build {bin}: {error}"))
        .command();
    command.args(args).stdin(Stdio::null());
    command.envs(envs.iter().copied());
    spawn(command)
}

fn spawn(mut command: Command) -> ProcessHandle {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = command.spawn().expect("failed to spawn process");
    let stdout = Arc::new(Mutex::new(String::new()));
    let stderr = Arc::new(Mutex::new(String::new()));

    let stdout_reader = child.stdout.take().expect("failed to capture stdout");
    let stdout_output = Arc::clone(&stdout);
    let stdout_thread = thread::spawn(move || read_lines(stdout_reader, stdout_output));

    let stderr_reader = child.stderr.take().expect("failed to capture stderr");
    let stderr_output = Arc::clone(&stderr);
    let stderr_thread = thread::spawn(move || read_lines(stderr_reader, stderr_output));

    ProcessHandle {
        process: child,
        stdout,
        stderr,
        readers: vec![stdout_thread, stderr_thread],
        status: None,
    }
}

fn read_lines(reader: impl std::io::Read, output: Arc<Mutex<String>>) {
    for line in BufReader::new(reader).lines() {
        let Ok(line) = line else {
            break;
        };
        let mut output = output.lock().unwrap();
        output.push_str(&line);
        output.push('\n');
    }
}
