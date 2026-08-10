use nix::pty::OpenptyResult;
use nix::sys::signal::{self, Signal};
use nix::unistd::{self, ForkResult, Pid};
use russh::server::{Msg, Session};
use russh::*;
use std::collections::HashMap;
use std::os::fd::{FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::process::Stdio;
use std::sync::{Arc, OnceLock};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    process::Command,
    sync::mpsc,
};
use tokio_vsock::{VMADDR_CID_ANY, VMADDR_CID_HOST, VsockAddr, VsockListener};

const PORT: u32 = 0x6b72756e;

static WORKLOAD_PID: OnceLock<Pid> = OnceLock::new();

pub fn run(pid_rx: OwnedFd) {
    match unsafe { unistd::fork() } {
        Ok(ForkResult::Child) => {
            // Detach immediately so getty doesn't kill us
            let _ = unistd::setsid();
            spawn_pid_receiver(pid_rx);
            let Ok(rt) = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            else {
                unsafe { libc::_exit(1) };
            };
            let _ = rt.block_on(serve());
            unsafe { libc::_exit(1) };
        }
        _ => {
            // Parent or fork error: do nothing.
        }
    }
}

fn spawn_pid_receiver(pid_rx: OwnedFd) {
    std::thread::spawn(move || {
        let mut buf = [0u8; 4];
        if unistd::read(&pid_rx, &mut buf) == Ok(4) {
            let _ = WORKLOAD_PID.set(Pid::from_raw(i32::from_le_bytes(buf)));
        }
    });
}

async fn serve() -> anyhow::Result<()> {
    let config = Arc::new(russh::server::Config {
        keys: vec![russh::keys::PrivateKey::random(
            &mut rand::rng(),
            russh::keys::Algorithm::Ed25519,
        )?],
        // The default of 100 causes hangs when you send more than 100 environment variables (i.e. in CI).
        channel_buffer_size: 10000,
        ..Default::default()
    });
    let vsl = VsockListener::bind(VsockAddr::new(VMADDR_CID_ANY, PORT))?;
    loop {
        let (socket, addr) = vsl.accept().await?;
        // Ensure connection is from the host.
        if addr.cid() != VMADDR_CID_HOST {
            continue;
        }
        let config = config.clone();
        tokio::spawn(async move {
            let _ = server::run_stream(config, socket, Server::default()).await;
        });
    }
}

#[derive(Default)]
struct SessionData {
    ch: Option<Channel<Msg>>,
    pty: Option<OpenptyResult>,
    env: Vec<(String, String)>,
    stdin: Option<mpsc::Sender<Vec<u8>>>,
    pty_fd: Option<RawFd>,
}

#[derive(Default)]
struct Server {
    sd: HashMap<ChannelId, SessionData>,
}

async fn close_channel(ch: &Channel<Msg>, child: &mut tokio::process::Child) {
    let code = child.wait().await.ok().and_then(|s| s.code()).unwrap_or(1) as u32;
    let _ = ch.exit_status(code).await;
    let _ = ch.eof().await;
    let _ = ch.close().await;
}

impl server::Handler for Server {
    type Error = anyhow::Error;

    async fn auth_none(&mut self, _: &str) -> Result<server::Auth, Self::Error> {
        Ok(server::Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        ch: Channel<Msg>,
        reply: server::ChannelOpenHandle,
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        let id = ch.id();
        self.sd.insert(
            id,
            SessionData {
                ch: Some(ch),
                ..Default::default()
            },
        );
        reply.accept().await;
        Ok(())
    }

    async fn env_request(
        &mut self,
        id: ChannelId,
        var: &str,
        val: &str,
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(s) = self.sd.get_mut(&id) {
            s.env.push((var.to_owned(), val.to_owned()));
        }
        Ok(())
    }

    async fn pty_request(
        &mut self,
        id: ChannelId,
        _: &str,
        cols: u32,
        rows: u32,
        _: u32,
        _: u32,
        _: &[(Pty, u32)],
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(s) = self.sd.get_mut(&id) {
            let ws = nix::pty::Winsize {
                ws_col: cols as u16,
                ws_row: rows as u16,
                ws_xpixel: 0,
                ws_ypixel: 0,
            };
            s.pty = Some(nix::pty::openpty(Some(&ws), None)?);
        }
        Ok(())
    }

    async fn window_change_request(
        &mut self,
        id: ChannelId,
        cols: u32,
        rows: u32,
        _: u32,
        _: u32,
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(fd) = self.sd.get(&id).and_then(|c| c.pty_fd) {
            let ws = nix::pty::Winsize {
                ws_col: cols as u16,
                ws_row: rows as u16,
                ws_xpixel: 0,
                ws_ypixel: 0,
            };
            unsafe {
                libc::ioctl(fd, libc::TIOCSWINSZ, &ws);
            }
        }
        Ok(())
    }

    async fn data(
        &mut self,
        id: ChannelId,
        data: &[u8],
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(tx) = self.sd.get(&id).and_then(|c| c.stdin.clone()) {
            let _ = tx.send(data.to_vec()).await;
        }
        Ok(())
    }

    async fn channel_eof(&mut self, id: ChannelId, _: &mut Session) -> Result<(), Self::Error> {
        if let Some(c) = self.sd.get_mut(&id) {
            c.stdin = None;
        }
        Ok(())
    }

    async fn shell_request(&mut self, id: ChannelId, s: &mut Session) -> Result<(), Self::Error> {
        self.exec_request(id, b"", s).await
    }

    async fn exec_request(
        &mut self,
        id: ChannelId,
        cmd_data: &[u8],
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        let cmd = String::from_utf8_lossy(cmd_data);

        // Handle the magic command sent by podman stop and crun kill.
        if let Some(sig) = cmd
            .strip_prefix('\u{1}')
            .and_then(|r| r.strip_prefix("KRUN_STOP "))
            .and_then(|s| s.trim().parse::<i32>().ok())
        {
            if crate::exec::use_custom_pid1() {
                // For some reason `poweroff` starts a shutdown but hangs at the end with
                // "reboot: Power off not available: System halted instead",
                // whereas `reboot` actually does a proper poweroff.
                let _ = Command::new("reboot").spawn();
            } else if let Some(pid) = WORKLOAD_PID.get() {
                let _ = signal::kill(*pid, Signal::try_from(sig).unwrap_or(Signal::SIGTERM));
            }
            if let Some(s) = self.sd.get_mut(&id)
                && let Some(ch) = s.ch.take()
            {
                let _ = ch.exit_status(0).await;
                let _ = ch.eof().await;
                let _ = ch.close().await;
            }
            return Ok(());
        }

        let mut builder = if cmd.is_empty() {
            Command::new("sh")
        } else {
            // Split the cmd ourselves instead of using sh,
            // since on Debian sh drops environment variables with hyphens.
            match shlex::split(&cmd).as_deref() {
                Some([arg, argv @ ..]) => {
                    let mut b = Command::new(arg);
                    b.args(argv);
                    b
                }
                _ => {
                    let mut b = Command::new("sh");
                    b.arg("-c").arg(cmd.as_ref());
                    b
                }
            }
        };
        let s = self.sd.get_mut(&id).expect("ChannelID not found");
        let ch = s.ch.take().expect("Channel already consumed");
        builder.envs(std::mem::take(&mut s.env));
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(32);
        if let Some(ptys) = s.pty.take() {
            // Interactive
            let sf = unsafe { std::fs::File::from_raw_fd(ptys.slave.into_raw_fd()) };
            let mut child = unsafe {
                builder
                    .stdin(sf.try_clone()?)
                    .stdout(sf.try_clone()?)
                    .stderr(sf)
                    .pre_exec(|| {
                        libc::setsid();
                        libc::ioctl(libc::STDIN_FILENO, libc::TIOCSCTTY, 0i32);
                        Ok(())
                    })
                    .spawn()?
            };

            let mfd = ptys.master.into_raw_fd();
            let rfd = unsafe { libc::dup(mfd) };
            if rfd < 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            s.stdin = Some(tx);
            s.pty_fd = Some(mfd);

            let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(8);
            tokio::task::spawn_blocking(move || {
                let mut buf = [0u8; 4096];
                loop {
                    let n = unsafe { libc::read(rfd, buf.as_mut_ptr() as _, buf.len()) };
                    if n <= 0 {
                        break;
                    }
                    if out_tx.blocking_send(buf[..n as usize].to_vec()).is_err() {
                        break;
                    }
                }
                unsafe {
                    libc::close(rfd);
                }
            });
            let mut rx_open = true;
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        d = out_rx.recv() => match d {
                            Some(b) => { if ch.data_bytes(b).await.is_err() { break; } }
                            None => break,
                        },
                        msg = rx.recv(), if rx_open => match msg {
                            Some(b) => unsafe { libc::write(mfd, b.as_ptr() as _, b.len()); },
                            None => rx_open = false,
                        },
                    }
                }
                close_channel(&ch, &mut child).await;
                unsafe {
                    libc::close(mfd);
                }
            });
        } else {
            // Noninteractive
            let mut child = builder
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()?;
            let mut si = child.stdin.take();
            let mut so = child.stdout.take().expect("stdout was piped");
            let mut se = child.stderr.take().expect("stderr was piped");
            s.stdin = Some(tx);

            let mut rx_open = true;
            tokio::spawn(async move {
                let mut buf_so = [0u8; 4096];
                let mut buf_se = [0u8; 4096];
                loop {
                    tokio::select! {
                        n = so.read(&mut buf_so) => match n {
                            Ok(n) if n > 0 => { if ch.data(&buf_so[..n]).await.is_err() { break; } }
                            _ => break,
                        },
                        n = se.read(&mut buf_se) => match n {
                            Ok(n) if n > 0 => { if ch.extended_data(1, &buf_se[..n]).await.is_err() { break; } }
                            _ => break,
                        },
                        msg = rx.recv(), if rx_open => match msg {
                            Some(b) => {
                                if let Some(ref mut stdin) = si {
                                    let _ = stdin.write_all(&b).await;
                                }
                            }
                            None => {
                                drop(si.take());
                                rx_open = false;
                            }
                        },
                    }
                }
                close_channel(&ch, &mut child).await;
            });
        }
        Ok(())
    }
}
