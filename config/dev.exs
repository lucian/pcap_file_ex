import Config

# Git Hooks Configuration
# Runs quality checks automatically before commits and pushes
config :git_hooks,
  auto_install: true,
  verbose: true,
  hooks: [
    # Pre-commit: Fast checks (~5-10 seconds)
    # These run before every commit to catch formatting and linting issues early
    pre_commit: [
      tasks: [
        {:mix_task, :format, ["--check-formatted"]},
        {:cmd, "cargo fmt --manifest-path=native/pcap_file_ex/Cargo.toml --all --check"},
        {:mix_task, :credo, ["--strict"]}
      ]
    ],

    # Pre-push: Expensive checks (~30-60 seconds)
    # These run before pushing to catch test failures and type errors
    pre_push: [
      tasks: [
        {:mix_task, :test},
        {:mix_task, :dialyzer},
        {:cmd, "cargo clippy --manifest-path=native/pcap_file_ex/Cargo.toml -- -Dwarnings"},
        {:cmd,
         "if command -v cargo-deny >/dev/null 2>&1; then cargo deny check --manifest-path=native/pcap_file_ex/Cargo.toml advisories licenses; else echo '⚠️  cargo-deny not installed. Run: mix setup'; fi"}
      ]
    ]
  ]
