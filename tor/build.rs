use std::env;
use std::path::Path;

const LIBRARIES: [&str; 47] = [
    "tor-app",
    "tor-compress",
    "tor-evloop",
    "tor-tls",
    "tor-crypt-ops",
    "curve25519_donna",
    "tor-geoip",
    "tor-process",
    "tor-time",
    "tor-fs",
    "tor-encoding",
    "tor-sandbox",
    "tor-container",
    "tor-net",
    "tor-thread",
    "tor-memarea",
    "tor-math",
    "tor-meminfo",
    "tor-osinfo",
    "tor-log",
    "tor-lock",
    "tor-fdio",
    "tor-string",
    "tor-term",
    "tor-smartlist-core",
    "tor-malloc",
    "tor-wallclock",
    "tor-err",
    "tor-intmath",
    "tor-ctime",
    "tor-trace",
    "keccak-tiny",
    "ed25519_ref10",
    "ed25519_donna",
    "or-trunnel",
    "tor-buf",
    "tor-version",
    "tor-pubsub",
    "tor-dispatch",
    "tor-container",
    "tor-confmgt",
    "tor-metrics",
    "tor-llharden",
    // the following libs are Tor dependencies
    "event",
    "z",
    "ssl",
    "crypto",
];

const WIN_LIBRARIES: [&str; 4] = [
    "shlwapi", "iphlpapi", "crypt32",
    // this library is required because cargo does not link into standard libaries
    // it uses the -nodefaultlibs compiler option.
    "shell32",
];

fn main() {
    let target = env::var("TARGET").unwrap_or(String::new());
    let is_windows = target.eq("x86_64-pc-windows-gnu");

    let static_libs = if is_windows {
        "windows-static-libs"
    } else {
        "linux-static-libs"
    };

    if !Path::new(static_libs).exists() {
        panic!(
            "Missing directory with static libraries at: {}",
            static_libs
        );
    }

    println!("cargo:rustc-link-search=all=tor/{}", static_libs);

    for lib in LIBRARIES {
        println!("cargo:rustc-link-lib={}", lib);
    }

    if is_windows {
        for lib in WIN_LIBRARIES {
            println!("cargo:rustc-link-lib={}", lib);
        }
    }
}
