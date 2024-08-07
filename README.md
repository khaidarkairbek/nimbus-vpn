# Nimbus VPN

Nimbus VPN is a command-line application for client- and server-side VPN communication using Rust. It handles TUN devices, socket communication, and secure key exchange using the Diffie-Hellman algorithm.

## Features

- Secure key exchange using Diffie-Hellman algorithm
- Support for TUN device creation and management
- Cross-platform compatibility (macOS and Linux)
- Graceful shutdown handling
- Command-line interface for easy configuration
  
## Architecture

### Components

<table>
  <tr>
    <th>Component</th>
    <th>File</th>
    <th>Purpose</th>
  </tr>
  <tr>
    <td>Command-Line Interface (CLI)</td>
    <td><code>cli.rs</code></td>
    <td>Parses command-line arguments to determine the mode (client or server) and configuration options.</td>
  </tr>
  <tr>
    <td>Main Entry Point</td>
    <td><code>main.rs</code></td>
    <td>Initializes the VPN in either client or server mode based on parsed CLI arguments.</td>
  </tr>
  <tr>
    <td>Communication Handling</td>
    <td><code>comm.rs</code></td>
    <td>Implements core communication logic for both client and server sides.</td>
  </tr>
  <tr>
    <td>Device Management</td>
    <td><code>dev.rs</code></td>
    <td>Manages client and server states, key management, and message processing.</td>
  </tr>
  <tr>
    <td>TUN Device Handling</td>
    <td><code>tun.rs</code></td>
    <td>Manages TUN device creation, configuration, and I/O operations.</td>
  </tr>
  <tr>
    <td>Cryptographic Operations</td>
    <td><code>crypto.rs</code></td>
    <td>Handles cryptographic operations for key exchanges.</td>
  </tr>
  <tr>
    <td>Error Handling</td>
    <td><code>error.rs</code></td>
    <td>Defines various error types for comprehensive error handling.</td>
  </tr>
</table>

### Workflow

1. **Initialization**
   - Parse command-line arguments to determine mode (client or server).
   - Initialize necessary components based on mode.

2. **Server Operations**
   - Bind to the specified address and port.
   - Enable IP forwarding.
   - Set up a TUN device.
   - Enter event loop to handle incoming connections and data.

3. **Client Operations**
   - Bind to the local address and port.
   - Set up a TUN device.
   - Initiate a handshake with the server to establish a secure connection.
   - Configure the default gateway to route traffic through the VPN.
   - Enter event loop to handle data transmission.

4. **Key Exchange and Data Transmission**
   - Perform a Diffie-Hellman key exchange to establish a shared secret key.
   - Encrypt and decrypt messages exchanged between client and server.
   - Transmit data through the established VPN tunnel.

5. **Graceful Shutdown**
   - Monitor for `Ctrl-C` signals.
     
## Getting Started

### Prerequisites

- Rust (latest stable version)

### Installation



Clone the repository:

```sh
git clone https://github.com/yourusername/nimbus-vpn.git
cd nimbus-vpn
```

Build the project:

```
cargo build --release
```

### Usage

#### Starting the Server

```
./target/release/nimbus-vpn server --port 8080 --key "your_server_private_key"
```

#### Starting the Client

```
./target/release/nimbus-vpn client --address "server_address" --port 8080 --key "your_client_private_key" --local-port 8081
```

## License

This project is licensed under the MIT License. See the [LICENSE](https://github.com/yourusername/project-name/blob/main/LICENSE) file for more details.

