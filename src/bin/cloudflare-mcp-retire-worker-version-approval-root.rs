use std::path::PathBuf;

fn main() {
    let mut args = std::env::args_os().skip(1);
    let Some(root) = args.next() else {
        fail("usage: cloudflare-mcp-retire-worker-version-approval-root ROOT GENERATION");
    };
    let Some(generation) = args.next() else {
        fail("usage: cloudflare-mcp-retire-worker-version-approval-root ROOT GENERATION");
    };
    if args.next().is_some() {
        fail("usage: cloudflare-mcp-retire-worker-version-approval-root ROOT GENERATION");
    }
    let generation = generation
        .into_string()
        .unwrap_or_else(|_| fail("generation must be UTF-8"));
    if let Err(error) =
        cloudflare_mcp::retire_worker_version_approval_root(&PathBuf::from(root), &generation)
    {
        fail(&error);
    }
    println!("{{\"status\":\"retired\",\"provider_calls\":0}}");
}

fn fail(message: &str) -> ! {
    eprintln!("{message}");
    std::process::exit(1)
}
