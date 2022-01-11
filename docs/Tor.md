# Tor

## How to Access the Tor Network from the _Victim_ Machine

My goal starting badcat was to develop a simple yet stealth transport for C2 engagements. And I chose Tor for anonymous communication. Now, how to access the Tor network from the _victim_ machine? 

### Initial PoC

Among other ways, one could pack the official Tor client inside the _backdoor_ and unpack it at runtime, then start a new process with the unpacked executable. In the initial PoC, I make it that way, [this](https://github.com/yanmarques/badcat/blob/51c1a2df8634b81653ba8afd18d264170c855635/victim/build.rs#L119) function bundles Tor client, [this](https://github.com/yanmarques/badcat/blob/51c1a2df8634b81653ba8afd18d264170c855635/victim/src/setting.rs#L61) function unpack it, [this](https://github.com/yanmarques/badcat/blob/51c1a2df8634b81653ba8afd18d264170c855635/victim/src/main.rs#L50) function start Tor process. Although I do not like the idea of touching the disk with Tor executable and spawning new processes from unpacked data, that way it makes easier for Anti-Virus solutions to create behaviour profiles.

### Static Linking

So I decided to link Tor code in `C` into `Rust`. I reasearched some repositories, like from [cretz](https://github.com/cretz/tor-static), and re-used lots of contents. I could finally create Tor static libraries using [build-tor](https://github.com/yanmarques/badcat/blob/dev/scripts/build-tor) script, then I created `tor` workspace to abstract calling Tor C functions from Rust. [This](https://github.com/yanmarques/badcat/blob/489f760eb6584abb151a51107cdd17083532e467/tor/src/lib.rs#L39) line shows all imported Tor functions. 

With the ability to start Tor in the same process just calling Tor directly, this can make badcat even stealthier.

## Nice, Packing Executables and Starting New Processes is in the Past. How About the TCP Server Socket?

Yeah, badcat is designed to have the server on the _victim_. Because of that, badcat needs to open a TCP server so that incoming connections through Tor reach the _backdoor_. At some point in time, badcat was implemented that way, see [here](https://github.com/yanmarques/badcat/blob/9d286e080d44c0f46c5e2359950a6672fc0ba709/victim/src/main.rs#L75), a TCP listener was started locally at any available port. I prefer not to open listeners, again it's stealthier without noisy TCP listener sockets.

So I defined the problem as: how to make Tor pass incoming data to Rust code? The TCP listener is just that, a transport for communication between Tor code and Rust code.

Since Tor is already reachable from Rust code, I managed to create an interface where Tor code could call a Rust function whenever data was received from a connection, and so on. Of course, I had to patch Tor source code, see the patch [here](https://github.com/yanmarques/badcat/blob/dev/scripts/rust_hs.patch). The whole implementation of this new mechanism of communication with Tor is at the [streaming](https://github.com/yanmarques/badcat/blob/dev/tor/src/stream.rs) module.

### Tor Streaming Interface

The main issue with Tor Streaming Interface is trying to transform the asynchronous nature of Tor connections into a synchronous one in Rust. The solution was to use the ugly polling algorithm. All connections have an unique identifier assigned by Tor. So when reading or writing data, Rust and Tor code uses this unique identifier to access the connection object and take some action. In the Rust part, there are 3 static objects shared by all the threads that makes the magic happen. They are the following:

1. [Connection Buffers](https://github.com/yanmarques/badcat/blob/489f760eb6584abb151a51107cdd17083532e467/tor/src/stream.rs#L18): Holds incoming and outgoing data of each connection. It's used for I/O operations.
2. [Servers](https://github.com/yanmarques/badcat/blob/489f760eb6584abb151a51107cdd17083532e467/tor/src/stream.rs#L23): It's used to know whether or not there's someone listening for a connection in a given port.
3. [Connection Lock](https://github.com/yanmarques/badcat/blob/489f760eb6584abb151a51107cdd17083532e467/tor/src/stream.rs#L28): It's used to verify whether or not a connection to server port has arrived, and release a call to [Server::incoming](https://github.com/yanmarques/badcat/blob/489f760eb6584abb151a51107cdd17083532e467/tor/src/stream.rs#L79).  

Tor code executes 3 main Rust functions, each one for a very specific purpose:

1. [Connection arrived](https://github.com/yanmarques/badcat/blob/489f760eb6584abb151a51107cdd17083532e467/tor/src/stream.rs#L357): Someone connected, check whether or not there is a server listening and dispatch the server handler. 
2. [A connection sent data](https://github.com/yanmarques/badcat/blob/489f760eb6584abb151a51107cdd17083532e467/tor/src/stream.rs#L311): Add the received data to the connection buffer.
3. [A connection wants to write data](https://github.com/yanmarques/badcat/blob/489f760eb6584abb151a51107cdd17083532e467/tor/src/stream.rs#L337): Read data from connection buffer and return to Tor code.

Example of the streaming interface:

```rust
let server = Server::listen(80)?;

loop {
    let mut connection = server.incoming();

    connection.write(b"Hello there!");
    
    let mut response = [0; 1024];
    connection.read(&mut response);
}
```