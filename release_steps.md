# Hex.pm Release Process

1. Bump version e.g 0.1.3

```
mix.exs
4:  @version "0.1.3"

native/pcap_file_ex/Cargo.toml
3:version = "0.1.3"

native/pcap_file_ex/Cargo.lock
105:version = "0.1.3"
```

2. Update changelog

3. Commit
```
git commit -m "Prepare v0.1.3 for HEX publication"
```

4. Tag
```
git tag v0.1.3
```

5. Push
```
git push origin master
git push origin v0.1.3
```

6. Wait for CI

7. Download checksums
```
$ PCAP_FILE_EX_BUILD=1 mix rustler_precompiled.download PcapFileEx.Native --all --print
```

8. !! MANUALLY PUBLISH THE RELEASE

- go to https://github.com/lucian/pcap_file_ex/releases
- selecte the release
- add a comment
- publish

9. Publish to Hex
```
$ PCAP_FILE_EX_BUILD=1 mix hex.publish
```

10. Delete checksums
```
$ rm checksum-Elixir.PcapFileEx.Native.exs
```

11. Bump version to -dev

```
mix.exs
4:  @version "0.1.4-dev"
```


## Troubleshoot

- re-tagging - remove existing tag

```
# delete tag on local
git tag -d v0.1.3

# delete tag on on remote
git push origin :refs/tags/v0.1.3
```
