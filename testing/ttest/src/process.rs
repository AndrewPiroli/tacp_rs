use std::ffi::OsString;
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::thread;

#[allow(dead_code)]
pub struct ProcessHandle {
    pub stdin: mpsc::Sender<String>,
    pub stdout: mpsc::Receiver<String>,
    pub stderr: mpsc::Receiver<String>,
    process: Child,
    dead: bool,
    pub exit: Option<ExitStatus>,
}
impl Drop for ProcessHandle {
    fn drop(&mut self) {
        self.kill();
    }
}
impl ProcessHandle {
    pub fn kill(&mut self) {
        if !self.dead {
            self.dead = true;
            match self.process.try_wait() {
                Ok(de) => {
                    match de {
                        Some(ex) => self.exit = Some(ex),
                        None => {
                            let _ = self.process.kill();
                            self.exit = Some(self.process.wait().unwrap());
                        },
                    }
                },
                Err(_) => {
                    panic!("{:?}", self.process.kill());
                },
            }
        }
    }
}

pub fn cargo_run(bin: &str, args: &[&str], envs: &[(&str, &str)]) -> ProcessHandle {
    let mut bin_cmd = escargot::CargoBuild::new()
        .bin(bin)
        .current_release()
        .current_target()
        .run()
        .unwrap()
        .command();
    bin_cmd.args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_clear();
    // .envs didn't work...
    for env in envs {
        bin_cmd.env(OsString::from(env.0), OsString::from(env.1));
    }
    spawn(bin_cmd)
}


pub fn spawn(mut cmd: Command) -> ProcessHandle {
    let mut child = cmd.spawn().expect("Failed to spawn process");

    let child_stdin = child.stdin.take().expect("Failed to open child stdin");
    let child_stdout = child.stdout.take().expect("Failed to open child stdout");
    let child_stderr = child.stderr.take().expect("Failed to open child stderr");

    let (stdin_tx, stdin_rx) = mpsc::channel::<String>();
    let (stdout_tx, stdout_rx) = mpsc::channel::<String>();
    let (stderr_tx, stderr_rx) = mpsc::channel::<String>();

    // stdin
    thread::spawn(move || {
        let mut stdin = child_stdin;
        while let Ok(msg) = stdin_rx.recv() {
            if writeln!(stdin, "{}", msg).is_err() {
                break;
            }
            let _ = stdin.flush();
        }
    });
    // stdout
    thread::spawn(move || {
        let reader = BufReader::new(child_stdout);
        for line in reader.lines() {
            match line {
                Ok(l) => {
                    if stdout_tx.send(l).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    // stderr
    thread::spawn(move || {
        let reader = BufReader::new(child_stderr);
        for line in reader.lines() {
            match line {
                Ok(l) => {
                    if stderr_tx.send(l).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    ProcessHandle {
        stdin: stdin_tx,
        stdout: stdout_rx,
        stderr: stderr_rx,
        process: child,
        dead: false,
        exit: None,
    }
}
