//! Local coding-agent bridge: runs the user's own `claude` (Claude Code) or `codex` CLI
//! non-interactively, streams its answer, and keeps the conversation going with `--resume`.
//! sshield itself sends nothing anywhere: the CLI uses the user's own login.

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Provider {
    Claude,
    Codex,
}

impl Provider {
    pub fn name(self) -> &'static str {
        match self {
            Provider::Claude => "Claude Code",
            Provider::Codex => "Codex",
        }
    }

    pub fn bin(self) -> &'static str {
        match self {
            Provider::Claude => "claude",
            Provider::Codex => "codex",
        }
    }

    pub fn install_hint(self) -> &'static str {
        match self {
            Provider::Claude => "Install Claude Code (npm i -g @anthropic-ai/claude-code), run `claude` once and sign in with your subscription.",
            Provider::Codex => "Install Codex (npm i -g @openai/codex), run `codex` once and sign in with your ChatGPT account.",
        }
    }
}

/// What the UI hears back, in order.
#[derive(Clone, Debug, PartialEq)]
pub enum Event {
    /// The CLI's conversation id, used to continue the chat on the next turn.
    Session(String),
    /// More answer text (a streamed chunk).
    Text(String),
    /// The turn is over. `error` is set when it failed or was stopped.
    Done { error: Option<String> },
}

pub struct Turn {
    pub provider: Provider,
    /// Full user message including any attached terminal context.
    pub prompt: String,
    /// Host label for the system prompt, if a terminal is the active tab.
    pub host: Option<String>,
    pub session: Option<String>,
}

#[derive(Clone)]
pub struct Running {
    child: Arc<Mutex<Option<Child>>>,
    cancelled: Arc<AtomicBool>,
}

impl Running {
    pub fn stop(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
        if let Some(c) = self.child.lock().unwrap().as_mut() {
            let _ = c.kill();
        }
    }
}

const SYSTEM_PROMPT: &str = "You are an assistant docked in the sidebar of sshield, an SSH client. \
The user is working in a terminal on a remote server. You cannot run commands or read files yourself; \
you only see the text the user attaches. Be concise and practical. Put every shell command in its own \
fenced code block (```bash) so the app can offer Insert / Run buttons, one command or one short script per \
block. Say briefly what a command does and flag anything destructive before suggesting it.";

fn make_command(provider: Provider, exe: &str) -> Command {
    let mut c = Command::new(exe);
    c.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // GUI app: never flash a console window for the helper process.
        c.creation_flags(0x0800_0000);
    }
    let _ = provider;
    c
}

fn args_for(turn: &Turn) -> Vec<String> {
    let s = |x: &str| x.to_string();
    match turn.provider {
        Provider::Claude => {
            let mut a = vec![
                s("-p"),
                s("--output-format"),
                s("stream-json"),
                s("--verbose"),
                s("--include-partial-messages"),
                // The CLI runs on *this* machine, not the server: no tools, advice only.
                s("--tools"),
                s(""),
                s("--append-system-prompt"),
                format!(
                    "{SYSTEM_PROMPT}{}",
                    turn.host
                        .as_deref()
                        .map(|h| format!(" The active terminal is connected to {h}."))
                        .unwrap_or_default()
                ),
            ];
            if let Some(id) = &turn.session {
                a.push(s("--resume"));
                a.push(id.clone());
            }
            a
        }
        Provider::Codex => {
            let mut a = vec![s("exec")];
            if let Some(id) = &turn.session {
                a.push(s("resume"));
                a.push(id.clone());
            }
            a.extend([
                s("--json"),
                s("--skip-git-repo-check"),
                s("-s"),
                s("read-only"),
                s("-"),
            ]);
            a
        }
    }
}

/// Start a turn. `on_event` is called from a worker thread.
pub fn spawn(turn: Turn, on_event: impl Fn(Event) + Send + 'static) -> Result<Running, String> {
    let args = args_for(&turn);
    let bin = turn.provider.bin();
    let candidates: Vec<String> = if cfg!(windows) {
        vec![bin.to_string(), format!("{bin}.cmd")]
    } else {
        vec![bin.to_string()]
    };
    let mut last_err = String::new();
    let mut child = None;
    for exe in &candidates {
        match make_command(turn.provider, exe).args(&args).spawn() {
            Ok(c) => {
                child = Some(c);
                break;
            }
            Err(e) => last_err = e.to_string(),
        }
    }
    let Some(mut child) = child else {
        return Err(format!(
            "Could not start `{bin}` ({last_err}). {}",
            turn.provider.install_hint()
        ));
    };
    // Codex has no system-prompt flag, so its instructions ride along with the message.
    let prompt = if turn.provider == Provider::Codex && turn.session.is_none() {
        format!("{SYSTEM_PROMPT}\n\n{}", turn.prompt)
    } else {
        turn.prompt.clone()
    };
    if let Some(mut si) = child.stdin.take() {
        let _ = si.write_all(prompt.as_bytes());
    }
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let child = Arc::new(Mutex::new(Some(child)));
    let cancelled = Arc::new(AtomicBool::new(false));
    let running = Running {
        child: child.clone(),
        cancelled: cancelled.clone(),
    };
    let provider = turn.provider;
    std::thread::spawn(move || {
        let err_buf = Arc::new(Mutex::new(String::new()));
        let err_thread = stderr.map(|e| {
            let buf = err_buf.clone();
            std::thread::spawn(move || {
                for l in BufReader::new(e).lines().map_while(Result::ok) {
                    let mut b = buf.lock().unwrap();
                    if b.len() < 4000 {
                        b.push_str(&l);
                        b.push('\n');
                    }
                }
            })
        });
        let mut st = ParseState::default();
        let mut finished = false;
        if let Some(out) = stdout {
            for line in BufReader::new(out).lines().map_while(Result::ok) {
                for ev in parse_line(provider, &line, &mut st) {
                    if matches!(ev, Event::Done { .. }) {
                        finished = true;
                    }
                    on_event(ev);
                }
            }
        }
        if let Some(t) = err_thread {
            let _ = t.join();
        }
        let status = child.lock().unwrap().as_mut().and_then(|c| c.wait().ok());
        if !finished {
            let err = if cancelled.load(Ordering::SeqCst) {
                Some("Stopped".to_string())
            } else if status.map(|s| s.success()).unwrap_or(false) {
                None
            } else {
                let e = err_buf.lock().unwrap().trim().to_string();
                Some(if e.is_empty() {
                    format!("`{}` exited with an error", provider.bin())
                } else {
                    e
                })
            };
            on_event(Event::Done { error: err });
        }
    });
    Ok(running)
}

/// `claude --version` / `codex --version`; None if it can't be started.
pub fn detect(provider: Provider) -> Option<String> {
    let bin = provider.bin();
    let names: Vec<String> = if cfg!(windows) {
        vec![bin.to_string(), format!("{bin}.cmd")]
    } else {
        vec![bin.to_string()]
    };
    for n in names {
        if let Ok(o) = make_command(provider, &n)
            .arg("--version")
            .stdin(Stdio::null())
            .output()
        {
            if o.status.success() {
                return Some(String::from_utf8_lossy(&o.stdout).trim().to_string());
            }
        }
    }
    None
}

#[derive(Default)]
pub struct ParseState {
    /// Saw token-level deltas for the current message, so its final copy must not be appended again.
    partial: bool,
    emitted: bool,
}

/// Turn one line of CLI output into UI events. Tolerant: unknown lines are ignored.
pub fn parse_line(provider: Provider, line: &str, st: &mut ParseState) -> Vec<Event> {
    let line = line.trim();
    if line.is_empty() {
        return vec![];
    }
    let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
        // Plain text (older CLI versions, or a non-JSON mode): show it as is.
        st.emitted = true;
        return vec![Event::Text(format!("{line}\n"))];
    };
    let ty = v.get("type").and_then(|t| t.as_str()).unwrap_or("");
    let mut out = vec![];
    match provider {
        Provider::Claude => match ty {
            "system" if v.get("subtype").and_then(|s| s.as_str()) == Some("init") => {
                if let Some(id) = v.get("session_id").and_then(|s| s.as_str()) {
                    out.push(Event::Session(id.to_string()));
                }
            }
            "stream_event" => {
                let ev = &v["event"];
                if ev["type"] == "content_block_delta" && ev["delta"]["type"] == "text_delta" {
                    if let Some(t) = ev["delta"]["text"].as_str() {
                        st.partial = true;
                        st.emitted = true;
                        out.push(Event::Text(t.to_string()));
                    }
                }
            }
            "assistant" => {
                if !st.partial {
                    for c in v["message"]["content"].as_array().into_iter().flatten() {
                        if c["type"] == "text" {
                            if let Some(t) = c["text"].as_str() {
                                st.emitted = true;
                                out.push(Event::Text(t.to_string()));
                            }
                        }
                    }
                }
                st.partial = false;
            }
            "result" => {
                if let Some(id) = v.get("session_id").and_then(|s| s.as_str()) {
                    out.push(Event::Session(id.to_string()));
                }
                let text = v.get("result").and_then(|r| r.as_str()).unwrap_or("");
                if v.get("is_error").and_then(|b| b.as_bool()).unwrap_or(false) {
                    let msg = if text.is_empty() {
                        "The agent reported an error".to_string()
                    } else {
                        text.to_string()
                    };
                    out.push(Event::Done { error: Some(msg) });
                } else {
                    if !st.emitted && !text.is_empty() {
                        out.push(Event::Text(text.to_string()));
                    }
                    out.push(Event::Done { error: None });
                }
            }
            _ => {}
        },
        Provider::Codex => match ty {
            "thread.started" => {
                if let Some(id) = v.get("thread_id").and_then(|s| s.as_str()) {
                    out.push(Event::Session(id.to_string()));
                }
            }
            "item.completed" => {
                let item = &v["item"];
                if item["type"] == "agent_message" {
                    if let Some(t) = item["text"].as_str() {
                        if st.emitted {
                            out.push(Event::Text("\n\n".into()));
                        }
                        st.emitted = true;
                        out.push(Event::Text(t.to_string()));
                    }
                }
            }
            "turn.completed" => out.push(Event::Done { error: None }),
            "turn.failed" | "error" => {
                let msg = v["error"]["message"]
                    .as_str()
                    .or_else(|| v["message"].as_str())
                    .unwrap_or("The agent reported an error");
                out.push(Event::Done {
                    error: Some(msg.to_string()),
                });
            }
            _ => {}
        },
    }
    out
}

/// A piece of an assistant message for rendering.
#[derive(Debug, PartialEq)]
pub enum Block {
    Text(String),
    Code { lang: String, code: String },
}

/// Split markdown into prose and fenced code blocks. An unterminated fence (still streaming)
/// is treated as an open code block.
pub fn parse_blocks(s: &str) -> Vec<Block> {
    let mut blocks = vec![];
    let mut text = String::new();
    let mut code: Option<(String, String)> = None;
    for line in s.lines() {
        let t = line.trim_start();
        if let Some(rest) = t.strip_prefix("```") {
            match code.take() {
                Some((lang, c)) => blocks.push(Block::Code {
                    lang,
                    code: c.trim_end_matches('\n').to_string(),
                }),
                None => {
                    if !text.trim().is_empty() {
                        blocks.push(Block::Text(std::mem::take(&mut text).trim().to_string()));
                    }
                    text.clear();
                    code = Some((rest.trim().to_string(), String::new()));
                }
            }
        } else if let Some((_, c)) = code.as_mut() {
            c.push_str(line);
            c.push('\n');
        } else {
            text.push_str(line);
            text.push('\n');
        }
    }
    if let Some((lang, c)) = code {
        blocks.push(Block::Code {
            lang,
            code: c.trim_end_matches('\n').to_string(),
        });
    }
    if !text.trim().is_empty() {
        blocks.push(Block::Text(text.trim().to_string()));
    }
    blocks
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(p: Provider, lines: &str) -> Vec<Event> {
        let mut st = ParseState::default();
        lines
            .lines()
            .flat_map(|l| parse_line(p, l, &mut st))
            .collect()
    }

    #[test]
    fn parses_a_real_claude_stream_without_duplicating_text() {
        let ev = run(
            Provider::Claude,
            include_str!("../tests/fixtures/claude_stream.jsonl"),
        );
        let text: String = ev
            .iter()
            .filter_map(|e| {
                if let Event::Text(t) = e {
                    Some(t.as_str())
                } else {
                    None
                }
            })
            .collect();
        assert_eq!(text, "hello world"); // partial delta + final copy are not both shown
        assert!(ev.contains(&Event::Session(
            "00000000-0000-4000-8000-000000000000".into()
        )));
        assert_eq!(ev.last(), Some(&Event::Done { error: None }));
    }

    #[test]
    fn claude_without_partials_uses_the_assistant_message() {
        let ev = run(
            Provider::Claude,
            r#"{"type":"assistant","message":{"content":[{"type":"text","text":"hi"}]}}
{"type":"result","subtype":"success","is_error":false,"result":"hi","session_id":"s1"}"#,
        );
        let text: String = ev
            .iter()
            .filter_map(|e| {
                if let Event::Text(t) = e {
                    Some(t.as_str())
                } else {
                    None
                }
            })
            .collect();
        assert_eq!(text, "hi");
    }

    #[test]
    fn claude_error_result_is_reported() {
        let ev = run(
            Provider::Claude,
            r#"{"type":"result","subtype":"error","is_error":true,"result":"Not logged in","session_id":"s"}"#,
        );
        assert_eq!(
            ev.last(),
            Some(&Event::Done {
                error: Some("Not logged in".into())
            })
        );
    }

    #[test]
    fn codex_events() {
        let ev = run(
            Provider::Codex,
            r#"{"type":"thread.started","thread_id":"t-1"}
{"type":"item.completed","item":{"type":"agent_message","text":"first"}}
{"type":"item.completed","item":{"type":"agent_message","text":"second"}}
{"type":"turn.completed"}"#,
        );
        assert_eq!(ev[0], Event::Session("t-1".into()));
        let text: String = ev
            .iter()
            .filter_map(|e| {
                if let Event::Text(t) = e {
                    Some(t.as_str())
                } else {
                    None
                }
            })
            .collect();
        assert_eq!(text, "first\n\nsecond");
        assert_eq!(ev.last(), Some(&Event::Done { error: None }));
    }

    #[test]
    fn plain_lines_pass_through() {
        assert_eq!(
            run(Provider::Codex, "not json at all"),
            vec![Event::Text("not json at all\n".into())]
        );
    }

    #[test]
    fn splits_code_blocks_even_while_streaming() {
        let b = parse_blocks("Try this:\n```bash\nls -la\ndf -h\n```\nThen done.");
        assert_eq!(
            b,
            vec![
                Block::Text("Try this:".into()),
                Block::Code {
                    lang: "bash".into(),
                    code: "ls -la\ndf -h".into()
                },
                Block::Text("Then done.".into())
            ]
        );
        // fence not closed yet
        assert_eq!(
            parse_blocks("```sh\nsudo apt"),
            vec![Block::Code {
                lang: "sh".into(),
                code: "sudo apt".into()
            }]
        );
    }

    #[test]
    fn claude_args_disable_tools_and_resume() {
        let t = Turn {
            provider: Provider::Claude,
            prompt: "x".into(),
            host: Some("web1".into()),
            session: Some("abc".into()),
        };
        let a = args_for(&t);
        let i = a.iter().position(|x| x == "--tools").unwrap();
        assert_eq!(a[i + 1], "");
        assert!(a.windows(2).any(|w| w[0] == "--resume" && w[1] == "abc"));
        assert!(a.iter().any(|x| x.contains("web1")));
    }

    #[test]
    fn codex_resume_args() {
        let t = Turn {
            provider: Provider::Codex,
            prompt: "x".into(),
            host: None,
            session: Some("t-9".into()),
        };
        let a = args_for(&t);
        assert_eq!(&a[..3], &["exec", "resume", "t-9"]);
        assert!(a.contains(&"read-only".to_string()));
    }

    /// Needs a logged-in `claude` on PATH: `cargo test -p sshield -- --ignored live_claude`.
    #[test]
    #[ignore]
    fn live_claude_streams_and_remembers() {
        use std::sync::mpsc::channel;
        let ask =
            |prompt: &str, session: Option<String>| -> (String, Option<String>, Option<String>) {
                let (tx, rx) = channel();
                let t = Turn {
                    provider: Provider::Claude,
                    prompt: prompt.into(),
                    host: Some("testhost".into()),
                    session,
                };
                spawn(t, move |e| {
                    let _ = tx.send(e);
                })
                .expect("claude should start");
                let (mut text, mut sess, mut err) = (String::new(), None, None);
                loop {
                    match rx
                        .recv_timeout(std::time::Duration::from_secs(120))
                        .expect("timed out")
                    {
                        Event::Text(t) => text.push_str(&t),
                        Event::Session(s) => sess = Some(s),
                        Event::Done { error } => {
                            err = error;
                            break;
                        }
                    }
                }
                (text, sess, err)
            };
        let (a, sess, err) = ask(
            "Remember the secret word BANANA42. Reply with just: ok",
            None,
        );
        assert!(err.is_none(), "{err:?}");
        assert!(a.to_lowercase().contains("ok"), "{a}");
        let sess = sess.expect("session id");
        let (b, _, err) = ask(
            "What was the secret word? Reply with only the word.",
            Some(sess),
        );
        assert!(err.is_none(), "{err:?}");
        assert!(b.contains("BANANA42"), "follow-up lost context: {b}");
    }
}
