# Wireveil

Wireveil is a firewall designed for A/D CTF competitions. It selectively blocks packets based on configurable regular expressions, providing a flexible and efficient way to enforce network security policies.

## Features

- **Regex-based Packet Filtering**: Define custom regex patterns to block specific packet contents.
- **Service-specific Rules**: Configure rules for individual services running on different ports.
- **NFQueue Integration**: Uses Linux's NFQueue for packet inspection and verdicts.
- **Logging and Tracing**: Provides detailed logs for blocked packets and system events.

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/ZephyrCodesStuff/wireveil.git
   cd wireveil
   ```

2. Install dependencies:
   - Ensure you have Rust installed. If not, install it from [rustup.rs](https://rustup.rs/).
   - Install the required libraries for `libnfnetlink` and `libnetfilter_queue`:
     ```bash
     sudo apt-get install libnfnetlink-dev libnetfilter-queue-dev
     ```

3. Build the project:
   ```bash
   cargo build --release
   ```

## Configuration

WireVeil uses a `wireveil.toml` configuration file to define services and their respective rules. An example configuration file is provided as `wireveil.toml.example`.

### Example Configuration

```toml
[services]

[services.vuln_http_service]
port = 8080
block = [
    "[A-Z0-9]{31}=",
    "flag{[a-zA-Z0-9]+}",
]

[services.vuln_tcp_service]
port = 3000
block = ["[A-Z0-9]{31}="]
```

- **port**: The port number the service listens on.
- **block**: A list of regex patterns to block packets matching these patterns.

Rename `wireveil.toml.example` to `wireveil.toml` and modify it as needed:
```bash
mv wireveil.toml.example wireveil.toml
```

## Usage

1. Run the application:
   ```bash
   sudo ./target/release/wireveil
   ```

2. The application will:
   - Load the configuration file.
   - Set up iptables rules to redirect packets to NFQueue.
   - Start processing packets based on the defined rules.

3. To stop the application, press `Ctrl+C`. The iptables rules will be cleaned up automatically.

## Logging

WireVeil uses the `tracing` crate for logging. You can configure the log level using the `RUST_LOG` environment variable. For example:
```bash
RUST_LOG=debug sudo ./target/release/wireveil
```

## Contributing

Contributions are welcome! Feel free to open issues or submit pull requests on the [GitHub repository](https://github.com/ZephyrCodesStuff/wireveil).

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Built with Rust and powered by NFQueue.
- Inspired by [Firegex](https://github.com/Pwnzer0tt1/firegex)
