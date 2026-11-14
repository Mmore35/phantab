#![forbid(unsafe_code)] // SR-58: unsafe lives only in phantab-window's OS modules.
use std::process::ExitCode;

use phantab::mode::Mode;

fn exit(code: i32) -> ExitCode {
    ExitCode::from(u8::try_from(code).unwrap_or(1))
}

fn main() -> ExitCode {
    // First of all: a DLL loaded by name from here on comes from System32 only (SR-58).
    phantab_window::restrict_dll_search();
    // Before any child exists: a child holding our stdio open keeps a stdio client from seeing EOF.
    phantab_window::disable_std_handle_inheritance();
    // SR-59: a panic prints its location only.
    phantab::panic_hook::install();
    #[cfg(feature = "test-seams")]
    std::hint::black_box(&TEST_SEAMS_MARKER);
    #[cfg(all(feature = "test-seams", target_os = "macos"))]
    use_test_keychain();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mode = Mode::of(&args);
    if mode == Mode::Install {
        return match phantab::install::run(&args[1..], args[0] == "uninstall") {
            Ok(code) => exit(code),
            Err(e) => {
                eprintln!("phantab: {e:#}");
                ExitCode::FAILURE
            }
        };
    }
    run_async(mode, &args)
}

/// In a `test-seams` build only, and kept (used, and read in `main`): `scripts/release.sh`'s path gate
/// refuses a binary that holds these bytes, or `PHANTAB_TEST_KEYCHAIN`, so a build with the test seams is
/// never released.
#[cfg(feature = "test-seams")]
#[used]
static TEST_SEAMS_MARKER: [u8; 24] = *b"phantab-test-seams-build";

/// Test builds only (`test-seams`, which a release build cannot turn on, so this code is not in one): a
/// test build never opens the login keychain, and its Keychain calls use the scratch keychain a test made
/// and named in `PHANTAB_TEST_KEYCHAIN`, unlocked with `PHANTAB_TEST_KEYCHAIN_PASSWORD`. With none, every
/// Keychain call fails.
#[cfg(all(feature = "test-seams", target_os = "macos"))]
fn use_test_keychain() {
    let path = std::env::var_os("PHANTAB_TEST_KEYCHAIN");
    let password = std::env::var("PHANTAB_TEST_KEYCHAIN_PASSWORD");
    if let (Some(path), Ok(password)) = (path, password)
        && let Err(e) = phantab_window::secret_store::test_keychain::use_for_process(
            std::path::Path::new(&path),
            &password,
        )
    {
        eprintln!("phantab: PHANTAB_TEST_KEYCHAIN: {e}");
    }
}

/// Every mode but install talks to the service, so it runs on tokio, on the runtime its mode gets.
fn run_async(mode: Mode, args: &[String]) -> ExitCode {
    let runtime = match mode.runtime() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("phantab: {e}");
            return ExitCode::FAILURE;
        }
    };
    let code = runtime.block_on(async {
        match mode {
            Mode::Host => phantab::host::run(&args[0]).await,
            Mode::Mcp => phantab::mcp::run(&args[1..]).await,
            Mode::Serve => phantab::service::run().await,
            Mode::Bitwarden => phantab::bitwarden::run(&args[1..]).await,
            Mode::Install | Mode::Cli => phantab::cli::run(args).await,
        }
    });
    exit(code)
}
