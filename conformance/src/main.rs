//! The `tinfoil-conformance` command line: one stage per invocation, input on
//! stdin, output on stdout, the verdict in the exit code.

use std::io::{Read, Write};
use std::process::ExitCode;

use tinfoil_conformance::{EXIT_INTERNAL, live};

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
        // Not implemented. The command takes arguments, not a stage input,
        // so it is answered here instead of being decoded as a stage.
        "capture" => {
            let (output, code) = tinfoil_conformance::unsupported(&command);
            write_json(&output, code)
        }
        live::COMMAND => {
            let Some(stdin) = read_stdin() else {
                return EXIT_INTERNAL;
            };
            let outcome = live::run(&stdin);
            if let Some(diagnostic) = &outcome.diagnostic {
                eprintln!("{}: {diagnostic}", live::COMMAND);
            }
            // A run without a verdict prints nothing to stdout.
            match &outcome.output {
                Some(output) => write_json(output, outcome.code),
                None => outcome.code,
            }
        }
        stage => {
            let Some(stdin) = read_stdin() else {
                return EXIT_INTERNAL;
            };
            let (output, code) = tinfoil_conformance::run(stage, &stdin);
            write_json(&output, code)
        }
    }
}

/// Reads all of stdin, or reports why it could not be read.
fn read_stdin() -> Option<Vec<u8>> {
    let mut stdin = Vec::new();
    match std::io::stdin().read_to_end(&mut stdin) {
        Ok(_) => Some(stdin),
        Err(error) => {
            eprintln!("reading input: {error}");
            None
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
