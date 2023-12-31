# PS5 Payload ELF Loader
This is an ELF loader for PS5 systems that have been jailbroken using either the
[BD-J ps5-payload-loader][bdj], or the [webkit approached from Specter][webkit].
Unlike the ELF loaders bundled with those exploits, this one uses the ptrace
syscall to load itself into the `ScePartyDaemon` process, hence will continue
running in the background even when playing games. Furthermore, this ELF loader
will also resume its execution when the PS5 returns from rest mode. Payloads that
are loaded are executed in the `SceRedisServer` process, so if the payload crashes,
the ELF loader will keep on running.

## Building
On Debian-flavored operating systems, one can invoke the following commands to
install dependencies and build the ELF loader.
```console
john@localhost:ps5-payload-elfldr$ sudo apt-get install build-essential clang lld
john@localhost:ps5-payload-elfldr$ make
```

## Usage
To deploy the ELF loader itself, we first bootstrap via the ELF loader bundled
with the exploit of your choice.
```console
john@localhost:ps5-payload-elfldr$ nc -q0 PS5_HOST 9020 < elfldr.elf
```
**Note**: recent versions of the [BD-J ps5-payload-loader][bdj] include a binary
version of this ELF loader which can be launched directly from the menu system.

Once the payload has been launched, a new socket server is started from the
`ScePartyDaemon` process that accepts ELFs on port 9021:
```console
john@localhost:ps5-payload-elfldr$ nc -q0 PS5_HOST 9021 < hello_world.elf
```

## Reporting Bugs
If you encounter problems with ps5-payload-elfldr, please [file a github issue][issues].
If you plan on sending pull requests which affect more than a few lines of code,
please file an issue before you start to work on you changes. This will allow us
to discuss the solution properly before you commit time and effort.

[bdj]: https://github.com/john-tornblom/bdj-sdk/tree/master/samples/ps5-payload-loader
[webkit]: https://github.com/Cryptogenic/PS5-IPV6-Kernel-Exploit
[issues]: https://github.com/john-tornblom/ps5-payload-elfldr/issues/new

