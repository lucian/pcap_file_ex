# Cross-Platform Test Fixture Support - Implementation Plan

**Created:** 2025-11-08
**Status:** In Progress
**Priority:** High

## Executive Summary

This document outlines the implementation plan to fix cross-platform compatibility issues in the PcapFileEx test fixture generation system. Currently, tests fail on fresh clones and Linux systems due to hardcoded macOS-specific interface names and missing dumpcap permission handling.

## Problems Identified

### 1. Critical Issues (Blocks Linux)

- **Hardcoded macOS interface**: Scripts default to `lo0` (macOS loopback), but Linux uses `lo`
- **No permission checking**: dumpcap requires elevated privileges on Linux, but scripts don't detect or guide users
- **Tests fail on fresh clones**: Generated fixtures (`new_test.pcap/pcapng`, `test_valid_data.pcap/pcapng`) aren't committed to git

### 2. User Experience Issues

- **No automatic interface detection**: Users must manually specify interfaces with `--interfaces` flag
- **Poor error messages**: Generic failures without platform-specific guidance
- **Missing documentation**: README assumes macOS defaults, doesn't explain Linux setup

### 3. Cross-Platform Compatibility

- **Platform detection**: No OS detection (`uname -s`) to set appropriate defaults
- **Port checking**: Only uses `lsof` (should prefer `ss` on modern Linux)
- **Interface validation**: Doesn't validate interface exists before attempting capture

## Detailed Analysis

### Current Script Behavior

Both `capture_test_traffic.sh` and `capture_heavy_traffic.sh` exhibit these patterns:

```bash
# Line 12: Hardcoded default
INTERFACES=("lo0")  # macOS-specific!

# Lines 37-43: Only checks dumpcap exists, not permissions
if ! command -v dumpcap &>/dev/null; then
  echo "Error: dumpcap not found"
  exit 1
fi
# No permission check here!

# Lines 100-108: lsof for port checking
if lsof -Pi :"$HTTP_PORT" -sTCP:LISTEN -t >/dev/null 2>&1; then
  # Port in use
fi
```

**What happens on Linux:**
1. Script tries to capture on `lo0` → Interface not found error
2. Or if user fixes interface, dumpcap fails with permission denied
3. Error messages don't explain platform differences or solutions

### Interface Naming by Platform

| Platform | Loopback | Ethernet | WiFi |
|----------|----------|----------|------|
| macOS    | `lo0`    | `en0`    | `en0` |
| Linux    | `lo`     | `eth0`, `ens33`, `enp0s3` | `wlan0`, `wlp3s0` |

The variation in Linux ethernet/wifi names (systemd predictable names) makes hardcoding impossible.

### dumpcap Permission Requirements

#### macOS (Darwin)

**Works without sudo IF:**
- ChmodBPF kernel extension is installed (comes with Wireshark via Homebrew)
- Creates `/Library/LaunchDaemons/org.wireshark.ChmodBPF.plist`
- Sets permissions on BPF devices at boot

**Installation:**
```bash
brew install wireshark  # Installs ChmodBPF automatically
```

**Alternative (less common):**
- Grant Terminal Input Monitoring permission
- System Preferences → Security & Privacy → Privacy → Input Monitoring → Add Terminal.app

#### Linux

**Requires one of:**

**Method 1: wireshark group (Recommended)**
```bash
# During wireshark-common install:
sudo dpkg-reconfigure wireshark-common  # Select "Yes" for non-root capture

# Add user to group:
sudo usermod -aG wireshark $USER

# Activate group (or logout/login):
newgrp wireshark
```

This sets capabilities on dumpcap: `CAP_NET_RAW+CAP_NET_ADMIN`

**Method 2: Manual capabilities**
```bash
sudo setcap cap_net_raw,cap_net_admin=eip $(which dumpcap)
```

**Method 3: sudo (Least secure)**
```bash
sudo ./capture_test_traffic.sh
```

**Testing permission status:**
```bash
dumpcap -D >/dev/null 2>&1
if [ $? -eq 0 ]; then
  echo "✓ dumpcap has proper permissions"
else
  echo "✗ dumpcap needs elevated privileges"
fi
```

### Test Fixture Dependency Matrix

**Committed to Git (Always Available):**
- `test/fixtures/sample.pcap` - Basic PCAP format
- `test/fixtures/sample.pcapng` - Basic PCAPNG format
- `test/fixtures/sample_multi_nanosecond.pcap` - Multi-interface nanosecond
- `test/fixtures/sample_multi_nanosecond.pcapng` - Multi-interface nanosecond

**Generated On-Demand (Missing on Fresh Clone):**
- `test/fixtures/new_test.pcap` - Used by pre_filter_test.exs
- `test/fixtures/new_test.pcapng` - **CRITICAL**: 4 tests fail without this
- `test/fixtures/test_valid_data.pcap` - Alternative test data
- `test/fixtures/test_valid_data.pcapng` - Alternative test data
- `test/fixtures/large_capture.pcap` - Benchmark data
- `test/fixtures/large_capture.pcapng` - Benchmark data

**Test Failures on Fresh Clone:**
```
4 failures in PcapFileEx.PreFilterTest:
  - test PCAPNG filtering filtering by protocol works on PCAPNG
  - test PCAPNG filtering filtering by size works on PCAPNG
  - test PCAPNG filtering set_filter/2 succeeds on PCAPNG reader
  - test PCAPNG filtering clear_filter/1 succeeds on PCAPNG reader

All fail with: {:error, "No such file or directory (os error 2)"}
At: @pcapng_fixture = "test/fixtures/new_test.pcapng"
```

### Existing Scripts and Tools

**Automation Scripts (in test/fixtures/):**
- `capture_test_traffic.sh` - Generates basic test fixtures
- `capture_heavy_traffic.sh` - Generates large benchmark data
- Both support `--list-interfaces` flag to show available interfaces

**Python Helper Scripts:**
- `http_server.py` - Simple HTTP server (GET /hello, /json; POST /submit)
- `http_client.py` - Basic HTTP traffic generator
- `http_load_client.py` - Sustained HTTP load generator
- `udp_server.py` - UDP telemetry server
- `udp_client.py` - Basic UDP traffic generator
- `udp_load_client.py` - High-rate UDP load generator

All Python scripts are platform-agnostic (use standard library only).

## Implementation Plan

### Phase 1: Document the Plan ✓

**File:** `docs/FIX_MULTI_OS_SUPPORT.md` (this document)

**Contents:**
- Complete problem analysis
- Platform-specific requirements
- Implementation roadmap
- Reference for contributors

### Phase 2: Fix Capture Scripts (Cross-Platform)

**Files to Modify:**
- `test/fixtures/capture_test_traffic.sh`
- `test/fixtures/capture_heavy_traffic.sh`

**Changes Required:**

#### A. Add Platform Detection

```bash
# Detect operating system
detect_platform() {
  PLATFORM=$(uname -s)
  case "$PLATFORM" in
    Darwin)
      OS_TYPE="macos"
      DEFAULT_LOOPBACK="lo0"
      NEED_SUDO=false
      ;;
    Linux)
      OS_TYPE="linux"
      DEFAULT_LOOPBACK="lo"
      NEED_SUDO=true  # Unless in wireshark group
      ;;
    *)
      echo "Warning: Unsupported platform $PLATFORM"
      OS_TYPE="unknown"
      DEFAULT_LOOPBACK="lo"  # Guess
      ;;
  esac
}
```

#### B. Add Interface Detection

```bash
# Auto-detect loopback interface
detect_loopback() {
  local loopback=""

  # Try to find loopback from dumpcap output
  if command -v dumpcap &>/dev/null; then
    # Parse dumpcap -D output for loopback
    # Example output:
    # 1. lo (Loopback)
    # 2. en0 (Ethernet)
    loopback=$(dumpcap -D 2>/dev/null | grep -i loopback | head -n1 | awk '{print $2}' | tr -d '()')
  fi

  # Fallback to platform defaults
  if [ -z "$loopback" ]; then
    loopback="$DEFAULT_LOOPBACK"
  fi

  echo "$loopback"
}

# Validate interface exists
validate_interface() {
  local iface=$1

  if ! dumpcap -D 2>/dev/null | grep -q "$iface"; then
    echo "Error: Interface '$iface' not found"
    echo ""
    echo "Available interfaces:"
    dumpcap -D 2>/dev/null || echo "(dumpcap failed)"
    echo ""
    echo "Use --interfaces <name> to specify a different interface"
    echo "Use --list-interfaces to see all available interfaces"
    return 1
  fi

  return 0
}
```

#### C. Add Permission Checking

```bash
# Check dumpcap permissions
check_dumpcap_permissions() {
  if ! dumpcap -D >/dev/null 2>&1; then
    echo "Error: dumpcap requires elevated privileges"
    echo ""

    case "$OS_TYPE" in
      macos)
        echo "macOS Setup:"
        echo "  1. Install Wireshark via Homebrew (includes ChmodBPF):"
        echo "     brew install wireshark"
        echo ""
        echo "  2. Or grant Terminal Input Monitoring permission:"
        echo "     System Preferences → Security & Privacy → Privacy → Input Monitoring"
        echo "     → Add Terminal.app"
        ;;

      linux)
        echo "Linux Setup (choose one):"
        echo ""
        echo "  Option 1: Wireshark group (recommended)"
        echo "    sudo dpkg-reconfigure wireshark-common  # Select 'Yes'"
        echo "    sudo usermod -aG wireshark \$USER"
        echo "    newgrp wireshark  # Or logout/login"
        echo ""
        echo "  Option 2: Set capabilities"
        echo "    sudo setcap cap_net_raw,cap_net_admin=eip \$(which dumpcap)"
        echo ""
        echo "  Option 3: Run with sudo"
        echo "    sudo $0 $*"
        ;;
    esac

    return 1
  fi

  return 0
}
```

#### D. Improve Port Checking (Linux-friendly)

```bash
# Check if port is available (prefer ss on Linux, fallback to lsof)
check_port_available() {
  local port=$1

  # Try ss first (modern Linux)
  if command -v ss >/dev/null 2>&1; then
    if ss -ln 2>/dev/null | grep -q ":$port "; then
      return 1  # Port in use
    fi
  # Fallback to lsof (macOS, older Linux)
  elif command -v lsof >/dev/null 2>&1; then
    if lsof -Pi :"$port" -sTCP:LISTEN -t >/dev/null 2>&1; then
      return 1  # Port in use
    fi
  else
    echo "Warning: Neither 'ss' nor 'lsof' available, cannot check port $port"
  fi

  return 0  # Port available or can't check
}
```

#### E. Update Default Interface Assignment

```bash
# Early in script, replace hardcoded INTERFACES=("lo0")
detect_platform
LOOPBACK=$(detect_loopback)
INTERFACES=("$LOOPBACK")  # Use detected interface
```

#### F. Add Validation Before Capture

```bash
# Before starting dumpcap
for iface in "${INTERFACES[@]}"; do
  if ! validate_interface "$iface"; then
    exit 1
  fi
done

if ! check_dumpcap_permissions; then
  exit 1
fi
```

### Phase 3: Automate Fixture Generation

**File:** `lib/mix/tasks/test/fixtures.ex` (NEW)

```elixir
defmodule Mix.Tasks.Test.Fixtures do
  @moduledoc """
  Generates test fixture files for the test suite.

  This task automatically generates PCAP and PCAPNG test fixtures
  required by the test suite. It requires dumpcap to be installed
  and properly configured for packet capture.

  ## Usage

      mix test.fixtures

  ## Requirements

  - dumpcap (from Wireshark package)
  - Python 3
  - Proper permissions for packet capture

  See README.md for platform-specific setup instructions.
  """

  use Mix.Task

  @shortdoc "Generate test fixture files"

  @fixtures_dir "test/fixtures"
  @required_fixtures [
    "new_test.pcap",
    "new_test.pcapng",
    "test_valid_data.pcap",
    "test_valid_data.pcapng"
  ]

  def run(_args) do
    Mix.shell().info("Checking for missing test fixtures...")

    missing = find_missing_fixtures()

    if Enum.empty?(missing) do
      Mix.shell().info("All test fixtures present. Nothing to generate.")
      :ok
    else
      Mix.shell().info("Missing fixtures: #{Enum.join(missing, ", ")}")
      generate_fixtures(missing)
    end
  end

  defp find_missing_fixtures do
    Enum.filter(@required_fixtures, fn fixture ->
      path = Path.join(@fixtures_dir, fixture)
      not File.exists?(path)
    end)
  end

  defp generate_fixtures(missing) do
    unless dumpcap_available?() do
      Mix.shell().error("""
      Error: dumpcap not found in PATH.

      dumpcap is required to generate test fixtures.
      Install Wireshark to get dumpcap:

      macOS:
        brew install wireshark

      Linux (Ubuntu/Debian):
        sudo apt-get install tshark

      Linux (Fedora/RHEL):
        sudo dnf install wireshark-cli

      Linux (Arch):
        sudo pacman -S wireshark-cli

      See README.md for permission setup instructions.
      """)

      exit({:shutdown, 1})
    end

    Mix.shell().info("Generating test fixtures...")
    Mix.shell().info("This may take 30-60 seconds...")

    script_path = Path.join(@fixtures_dir, "capture_test_traffic.sh")

    case System.cmd(script_path, [], cd: @fixtures_dir, stderr_to_stdout: true) do
      {output, 0} ->
        Mix.shell().info("✓ Test fixtures generated successfully")
        Mix.shell().info(output)
        :ok

      {output, exit_code} ->
        Mix.shell().error("✗ Failed to generate fixtures (exit code: #{exit_code})")
        Mix.shell().error(output)
        Mix.shell().error("""

        Troubleshooting:
        - Ensure dumpcap has proper permissions (see README.md)
        - Try running manually: cd test/fixtures && ./capture_test_traffic.sh
        - Check for permission errors or missing interfaces
        """)

        exit({:shutdown, 1})
    end
  end

  defp dumpcap_available? do
    case System.cmd("which", ["dumpcap"], stderr_to_stdout: true) do
      {_, 0} -> true
      _ -> false
    end
  end
end
```

**File:** `test/test_helper.exs` (MODIFY)

```elixir
# Add before ExUnit.start()

# Auto-generate missing test fixtures
defmodule TestFixtureSetup do
  @fixtures_dir "test/fixtures"
  @critical_fixtures ["new_test.pcapng"]  # Fixtures that cause test failures

  def ensure_fixtures do
    missing = find_missing_critical_fixtures()

    unless Enum.empty?(missing) do
      IO.puts("\n⚠️  Missing critical test fixtures: #{Enum.join(missing, ", ")}")
      IO.puts("Attempting to generate them automatically...\n")

      case Mix.Task.run("test.fixtures") do
        :ok ->
          IO.puts("✓ Fixtures generated successfully\n")
        _ ->
          IO.puts("""
          ⚠️  Could not generate fixtures automatically.

          Some tests may be skipped. To fix:
            1. Install dumpcap (see README.md)
            2. Run: mix test.fixtures
          """)
      end
    end
  end

  defp find_missing_critical_fixtures do
    Enum.filter(@critical_fixtures, fn fixture ->
      path = Path.join(@fixtures_dir, fixture)
      not File.exists?(path)
    end)
  end
end

TestFixtureSetup.ensure_fixtures()

ExUnit.start()
```

### Phase 4: Update README.md

**Add "Development Setup" section after "Installation":**

````markdown
## Development Setup

### Prerequisites

For developing and testing PcapFileEx, you'll need:

- **Elixir** ~> 1.19
- **Rust toolchain** (cargo, rustc) - For compiling native extensions
- **Erlang/OTP** 24+
- **dumpcap** - For generating test fixtures (optional but recommended)
- **Python 3** - For test traffic generation scripts

### Installing dumpcap

dumpcap is used to generate test fixtures. While optional, some tests will be skipped without it.

#### macOS

```bash
brew install wireshark
```

This installs dumpcap with ChmodBPF, allowing packet capture without sudo.

#### Linux (Ubuntu/Debian)

```bash
# Install dumpcap
sudo apt-get install tshark

# Setup non-root packet capture (recommended)
sudo dpkg-reconfigure wireshark-common  # Select "Yes"
sudo usermod -aG wireshark $USER
newgrp wireshark  # Or logout/login to activate group
```

#### Linux (Fedora/RHEL)

```bash
sudo dnf install wireshark-cli
sudo usermod -aG wireshark $USER
newgrp wireshark
```

#### Linux (Arch)

```bash
sudo pacman -S wireshark-cli
sudo usermod -aG wireshark $USER
newgrp wireshark
```

### Running Tests

```bash
# Clone repository
git clone https://github.com/yourusername/pcap_file_ex.git
cd pcap_file_ex

# Fetch dependencies
mix deps.get

# Compile (includes Rust NIF)
mix compile

# Run tests (auto-generates fixtures on first run)
mix test
```

**Manual fixture generation:**

```bash
# Generate all fixtures
mix test.fixtures

# Or manually
cd test/fixtures
./capture_test_traffic.sh
```

### Verifying dumpcap Setup

Check if dumpcap has proper permissions:

```bash
dumpcap -D
```

This should list available network interfaces. If you see a permission error, see the Troubleshooting section below.
````

**Add "Troubleshooting" section before "License":**

````markdown
## Troubleshooting

### Tests failing: "No such device" error

**Symptoms:**
```
Error: Interface 'lo0' not found
```

**Cause:** Interface name mismatch between platforms.

**Solution:**

On macOS, loopback is `lo0`. On Linux, it's `lo`. The scripts auto-detect this, but if you're specifying interfaces manually:

```bash
# List available interfaces
cd test/fixtures
./capture_test_traffic.sh --list-interfaces

# Use specific interface
./capture_test_traffic.sh --interfaces en0  # macOS ethernet
./capture_test_traffic.sh --interfaces eth0  # Linux ethernet
```

### Tests failing: "Permission denied" error

**Symptoms:**
```
dumpcap: You don't have permission to capture on that device
```

**Cause:** dumpcap requires elevated privileges for packet capture.

#### macOS Solutions

**Option 1: Install via Homebrew (Recommended)**

```bash
brew install wireshark
```

Wireshark includes ChmodBPF, which grants packet capture permissions automatically.

**Option 2: Grant Terminal Permission**

1. Open System Preferences
2. Go to Security & Privacy → Privacy → Input Monitoring
3. Click the lock to make changes
4. Add Terminal.app (or iTerm.app)

**Verify it works:**

```bash
dumpcap -D  # Should list interfaces without error
```

#### Linux Solutions

**Option 1: Wireshark Group (Recommended)**

```bash
# Configure Wireshark for non-root capture
sudo dpkg-reconfigure wireshark-common  # Select "Yes"

# Add your user to the wireshark group
sudo usermod -aG wireshark $USER

# Activate the group (or logout/login)
newgrp wireshark

# Verify it works
dumpcap -D  # Should list interfaces without error
```

**Option 2: Set Capabilities Manually**

```bash
# Give dumpcap specific capabilities
sudo setcap cap_net_raw,cap_net_admin=eip $(which dumpcap)

# Verify
dumpcap -D
```

**Option 3: Run with sudo (Least Secure)**

```bash
cd test/fixtures
sudo ./capture_test_traffic.sh
```

This works but requires entering your password and running the entire script as root.

### Tests skipped: "Missing dumpcap"

If dumpcap isn't installed, tests that require generated fixtures will be skipped. This is normal.

To fix, install dumpcap (see Development Setup above) and run:

```bash
mix test.fixtures
```

### Fixture generation fails

**Debug steps:**

1. **Check dumpcap is in PATH:**
   ```bash
   which dumpcap
   dumpcap -v
   ```

2. **Check permissions:**
   ```bash
   dumpcap -D  # Should list interfaces
   ```

3. **Try manual generation:**
   ```bash
   cd test/fixtures
   ./capture_test_traffic.sh --list-interfaces
   ./capture_test_traffic.sh
   ```

4. **Check Python is available:**
   ```bash
   python3 --version
   ```

5. **Look at script output:** The capture scripts provide detailed error messages.

### Still Having Issues?

- Check GitHub Issues: https://github.com/yourusername/pcap_file_ex/issues
- Read test/fixtures/README.md for detailed fixture documentation
- Most tests will skip gracefully if fixtures are missing - only 4 tests require generated files
````

### Phase 5: Update test/fixtures/README.md

Enhance existing README with platform-specific guidance.

### Phase 6: Update CHANGELOG.md

Add entry for version with these improvements:

```markdown
## [Unreleased]

### Fixed
- Cross-platform support for test fixture generation scripts
- Auto-detect loopback interface (`lo` on Linux, `lo0` on macOS)
- Permission checking for dumpcap with platform-specific guidance
- Tests now auto-generate missing fixtures on fresh clones (#123)

### Added
- Mix task `mix test.fixtures` for manual fixture generation
- Automatic fixture generation in test setup
- Comprehensive development setup documentation
- Troubleshooting guide for dumpcap permission issues
- Platform-specific installation instructions (macOS, Ubuntu, Fedora, Arch)
- Smart interface detection and validation in capture scripts

### Improved
- Test fixture scripts now work on both macOS and Linux
- Better error messages for missing tools or permissions
- Automatic interface detection and validation
- Port checking now uses `ss` on Linux (faster, more reliable)
- Documentation covers both Git dependencies and future Hex publishing
```

## Testing Plan

### macOS Testing

1. **Fresh clone test:**
   ```bash
   git clone <repo> test-macos
   cd test-macos
   mix deps.get
   mix compile
   mix test  # Should auto-generate fixtures
   ```

2. **Without dumpcap:**
   ```bash
   brew uninstall wireshark  # Temporarily
   mix test  # Should skip 4 tests with clear message
   ```

3. **Manual generation:**
   ```bash
   cd test/fixtures
   ./capture_test_traffic.sh
   ./capture_test_traffic.sh --list-interfaces
   ./capture_heavy_traffic.sh --duration 10
   ```

### Linux Testing (Ubuntu 22.04)

1. **Fresh clone test:**
   ```bash
   git clone <repo> test-linux
   cd test-linux
   mix deps.get
   mix compile
   mix test  # Should auto-generate or skip gracefully
   ```

2. **Permission error handling:**
   ```bash
   # Without wireshark group
   mix test.fixtures  # Should show helpful error

   # After setup
   sudo dpkg-reconfigure wireshark-common
   sudo usermod -aG wireshark $USER
   newgrp wireshark
   mix test.fixtures  # Should work
   ```

3. **Interface detection:**
   ```bash
   cd test/fixtures
   ./capture_test_traffic.sh  # Should use 'lo' not 'lo0'
   ./capture_test_traffic.sh --list-interfaces
   ```

### Validation Checklist

- [ ] Scripts detect correct loopback interface (lo vs lo0)
- [ ] Permission errors show platform-specific help
- [ ] `mix test` works on fresh clone (auto-generates or skips)
- [ ] `mix test.fixtures` generates all required files
- [ ] Error messages are clear and actionable
- [ ] README covers both platforms comprehensively
- [ ] Both macOS and Linux can run all tests with proper setup

## Success Criteria

✅ **Must Have:**
1. Tests pass on fresh clones (macOS and Linux)
2. Scripts auto-detect correct loopback interface
3. Permission errors provide clear, platform-specific guidance
4. Documentation covers installation for macOS and major Linux distros

✅ **Should Have:**
1. Automatic fixture generation in test setup
2. Mix task for manual fixture generation
3. Comprehensive troubleshooting guide
4. CHANGELOG entry documenting improvements

✅ **Nice to Have:**
1. Smart interface selection beyond loopback
2. CI/CD testing on both platforms
3. Docker-based testing environment
4. Windows support (future)

## Future Enhancements

1. **Pre-commit fixtures to git**: Consider committing `new_test.pcapng` to avoid generation requirement
2. **Synthetic fixtures**: Generate test data programmatically without dumpcap for basic tests
3. **CI/CD integration**: Add GitHub Actions workflow to test on Ubuntu and macOS
4. **Windows support**: Add Windows-specific paths and interface detection
5. **Docker testing**: Create containerized test environment with dumpcap pre-configured

## References

- **dumpcap documentation**: https://www.wireshark.org/docs/man-pages/dumpcap.html
- **ChmodBPF info**: https://wiki.wireshark.org/CaptureSetup/CapturePrivileges#macos
- **Linux capabilities**: https://wiki.wireshark.org/CaptureSetup/CapturePrivileges#linux

## Contributors

- Initial analysis and plan: Claude Code (2025-11-08)
- Implementation: TBD
