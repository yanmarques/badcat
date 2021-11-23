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

// build.rs, in the project root folder
fn main() {
    println!("cargo:rustc-link-search=all=tor/shared-libs");

    for lib in LIBRARIES {
        println!("cargo:rustc-link-lib=static={}", lib);
    }
}