//! The `tinfoil-conformance` command line: one stage per invocation, input on
//! stdin, output on stdout, the verdict in the exit code.

use std::io::{Read, Write};
use std::process::ExitCode;

use tinfoil_conformance::EXIT_INTERNAL;

fn main() -> ExitCode {
    exit(run())
}

fn run() -> i32 {
    let Some(command) = std::env::args().nth(1) else {
        // No stage ran, so there is no verdict to report.
        eprintln!("usage: tinfoil-conformance <stage>|capabilities|live-verify|capture");
        return EXIT_INTERNAL;
    };
    match command.as_str() {
        "capabilities" => write_json(&tinfoil_conformance::capabilities(), 0),
        // Not implemented yet. These commands take their own input, not a
        // stage input, so they are answered here instead of being decoded as
        // a stage; the suite skips a command that reports itself unsupported.
        "live-verify" | "capture" => {
            let (output, code) = tinfoil_conformance::unsupported(&command);
            write_json(&output, code)
        }
        stage => {
            let mut stdin = Vec::new();
            if let Err(error) = std::io::stdin().read_to_end(&mut stdin) {
                eprintln!("reading input: {error}");
                return EXIT_INTERNAL;
            }
            let (output, code) = tinfoil_conformance::run(stage, &stdin);
            write_json(&output, code)
        }
    }
}

/// Writes the value as indented JSON and returns `code`, or the internal
/// error code when stdout cannot be written.
fn write_json(value: &impl serde::Serialize, code: i32) -> i32 {
    let mut stdout = std::io::stdout().lock();
    let written = serde_json::to_writer_pretty(&mut stdout, value)
        .map_err(std::io::Error::from)
        .and_then(|()| stdout.write_all(b"\n"));
    match written {
        Ok(()) => code,
        Err(error) => {
            eprintln!("writing output: {error}");
            EXIT_INTERNAL
        }
    }
}

fn exit(code: i32) -> ExitCode {
    ExitCode::from(u8::try_from(code).unwrap_or(1))
}
