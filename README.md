# PS5 Payload ELF Loader
This is an ELF loader for PS5 systems that have been jailbroken using either the
[BD-J ps5-payload-loader][bdj], or the [webkit approached from Specter][webkit].
Unlike the ELF loaders bundled with those exploits, ps5-payload-elfldr uses the
ptrace syscall to load itself into the `ScePartyDaemon` process, hence will
continue running in the background even when playing games. Furthermore, ELFs
loaded by ps5-payload-elfldr are executed inside the `SceRedisServer` process so
that payloads that crash does not take the ELF loader down with it.

## Building
On Debian-flavored operating systems, one can invoke the following commands to
install dependencies and build the ELF loader.
```console
john@localhost:ps5-payload-elfldr$ sudo apt-get install build-essential clang lld
john@localhost:ps5-payload-elfldr$ make
```

## Usage
To deploy the ELF loader itself, we first bootstrap via the ELF loader bundled
with the exploit of your choise.
```console
john@localhost:ps5-payload-elfldr$ nc -q0 PS5_HOST 9020 < elfldr.elf
```

This will start a new socket server from the `SceRedisServer` process that accepts
ELFs on port 9021:
```console
john@localhost:ps5-payload-elfldr$ nc -q0 PS5_HOST 9021 < hello_world.elf
```

**Note**: `SceShellCore` sends regular heartbeats to the `SceRedisServer` process, 
and will eventually kill and restart it there are no responces being sent back.
So, if you plan to run a payload that takes some time to do its thing (e.g., an
FTP server), launch a thread that does the work, and just return from `main()`.

## Reporting Bugs
If you encounter problems with ps5-payload-elfldr, please [file a github issue][issues].
If you plan on sending pull requests which affect more than a few lines of code,
please file an issue before you start to work on you changes. This will allow us
to discuss the solution properly before you commit time and effort.

[bdj]: https://github.com/john-tornblom/bdj-sdk/tree/master/samples/ps5-payload-loader
[webkit]: https://github.com/Cryptogenic/PS5-IPV6-Kernel-Exploit
[issues]: https://github.com/john-tornblom/ps5-payload-elfldr/issues/new

