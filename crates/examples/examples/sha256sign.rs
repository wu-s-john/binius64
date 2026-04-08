// Copyright 2025 Irreducible Inc.
use anyhow::Result;
use binius_examples::{Cli, circuits::sha256sign::Sha256SignExample};

fn main() -> Result<()> {
	Cli::<Sha256SignExample>::new("sha256sign")
		.about("ECDSA signature verification with SHA-256")
		.run()
}
