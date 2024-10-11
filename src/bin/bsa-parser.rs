//! Bethesda Softworks Archive format parser.

use bsa_parser::prelude::*;
use bsa_parser::Result;

fn main() -> Result<()> {
    // parse args
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        println!("Usage: {} <file_path>", args[0]);
        return Ok(())
    }

    // parse file using guesser
    let mut parser = BSAParser::file(&args[1])?;
    parser.v104()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use assert_cmd::prelude::*;
    use std::process::Command;

    #[test]
    fn misc() {
        let mut cmd = Command::cargo_bin("bsa-parser").unwrap();
        cmd.arg("data/Misc.bsa");
        cmd.assert().success();
    }
}
