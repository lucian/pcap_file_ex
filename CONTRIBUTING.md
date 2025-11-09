# Contributing to PcapFileEx

Thank you for your interest in contributing to PcapFileEx! This document provides guidelines and instructions for contributors.

## Development Setup

### Prerequisites

- **Elixir** 1.18+ and **OTP** 27+
- **Rust** stable toolchain (for native extensions)
- **Git** for version control

### Getting Started

1. **Clone the repository**:
   ```bash
   git clone https://github.com/lucian/pcap_file_ex
   cd pcap_file_ex
   ```

2. **Install dependencies**:
   ```bash
   mix deps.get
   ```

3. **Compile the project** (includes Rust NIFs):
   ```bash
   mix compile
   ```
   Note: First compilation may take a while as Rust dependencies are built.

4. **Run tests**:
   ```bash
   mix test
   ```

## Tidewave MCP Integration

This project uses [Tidewave MCP](https://hexdocs.pm/tidewave/mcp.html) for deep Elixir runtime integration during development.

### Starting Tidewave

You have two options:

**Option 1: Background server (no IEx shell)**
```bash
mix tidewave
```

**Option 2: Interactive IEx shell with MCP server**
```bash
iex -S mix tidewave-iex
```

Both start a Bandit server on port 4000 with the Tidewave plug. Use Option 2 when you want both MCP access and an interactive Elixir shell for manual testing.

### Benefits

- Evaluate Elixir code in project context without restarting IEx
- Get documentation for modules and functions instantly
- Find source locations quickly
- Search dependency documentation
- Check application logs with grep filtering

## Rust Development

The Rust NIFs live in `native/pcap_file_ex/`.

### Linting and Formatting

**Format Rust code**:
```bash
cargo fmt --manifest-path=native/pcap_file_ex/Cargo.toml
```

**Lint with Clippy**:
```bash
cargo clippy --manifest-path=native/pcap_file_ex/Cargo.toml -- -Dwarnings
```

### Local Testing

**Run Rust tests**:
```bash
cargo test --manifest-path=native/pcap_file_ex/Cargo.toml
```

## Testing

This project uses both example-based and property-based testing:

### Running Tests

**All tests** (303 total):
```bash
mix test
```

**Example-based tests only** (193 tests):
```bash
mix test --exclude property
```

**Property-based tests only** (94 properties):
```bash
mix test test/property_test/
```

**CI mode** (1000 iterations per property instead of 100):
```bash
CI=true mix test
```

### Test Organization

- **Example tests**: `test/**/*_test.exs` - Specific scenarios with known inputs/outputs
- **Property tests**: `test/property_test/*_property_test.exs` - Invariants tested across thousands of random inputs
- **Generators**: `test/support/generators.ex` - Reusable data generators for property tests

## Code Quality

**Format Elixir code**:
```bash
mix format
```

**Verify formatting** (used in CI):
```bash
mix format --check-formatted
```

**Run with warnings as errors**:
```bash
mix compile --warnings-as-errors
```

Always run `mix format` and `cargo fmt` before committing to pass CI checks.

## Pull Requests

1. **Create a feature branch**:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes** with tests:
   - Add example tests for specific scenarios
   - Consider property tests for invariants
   - Update documentation if needed

3. **Format your code**:
   ```bash
   mix format
   cargo fmt --manifest-path=native/pcap_file_ex/Cargo.toml
   ```

4. **Ensure tests pass**:
   ```bash
   mix test
   cargo clippy --manifest-path=native/pcap_file_ex/Cargo.toml -- -Dwarnings
   ```

5. **Commit your changes**:
   ```bash
   git add .
   git commit -m "Brief description of your changes"
   ```

6. **Push and open PR**:
   ```bash
   git push origin feature/your-feature-name
   ```
   Then open a pull request on GitHub with a clear description of your changes.

### PR Guidelines

- **Title**: Use descriptive titles (e.g., "Add support for PCAPNG comments")
- **Description**: Explain what changed and why
- **Tests**: Include tests for new functionality
- **Documentation**: Update docs if you change public APIs
- **Breaking changes**: Clearly mark breaking changes in the PR description

## Development Workflow

### Adding New Features

1. Check existing issues or create one to discuss the feature
2. Write tests first (TDD approach recommended)
3. Implement the feature
4. Update documentation
5. Run full test suite
6. Open PR

### Fixing Bugs

1. Write a failing test that reproduces the bug
2. Fix the bug
3. Verify the test passes
4. Check for similar bugs elsewhere
5. Open PR with the test and fix

### Updating Dependencies

**Elixir dependencies**:
```bash
mix deps.update --all
mix test
```

**Rust dependencies**:
```bash
cd native/pcap_file_ex
cargo update
cargo test
cd ../..
mix compile
mix test
```

## CI/CD Pipeline

Our CI runs:
- Elixir tests on multiple Elixir/OTP versions
- Property-based tests with 1000 iterations
- Elixir formatter check
- Rust clippy linting
- Rust formatter check
- Version synchronization check (mix.exs vs Cargo.toml)

Make sure all checks pass before merging.

## Getting Help

- **Issues**: Open an issue on GitHub for bugs or feature requests
- **Discussions**: Use GitHub Discussions for questions

## Code of Conduct

- Be respectful
- Focus on constructive feedback
- Help others learn and grow
- Report unacceptable behavior to maintainers

Thank you for contributing to PcapFileEx!
