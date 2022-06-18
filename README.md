# Novell NetWare 3.12 server

This is a NetWare 3.12 server written in Rust. The main benefit is that it does not rely on an IPX stack, as it uses [libpnet](https://github.com/libpnet/libpnet) to construct and process IPX packets. Only the Ethernet_II IPX frame type is supported.

# Status

Only basic _read only_ file sharing is implemented. There is no authentication support or support for multiple volumes.

Still, this is sufficient to turn your Windows or Linux-based system into a NetWare 3.12-server for your retro computing file transfer needs. The server will advertise itself using SAP and RIP as necessary and will co-operate with existing servers, if any.

# Configuration

You need to edit `config.toml` with your preferred configuration. The most important setting is `interface`, which should correspond with the network interface you want to use for NetWare services.

You'll also want to change the path of the `SYS` volume to wherever the files are that you intend to serve. Only files in uppercase that can be represented using the 8.3 filename standard will be available - all others will be silently ignored.

# Running

```
$ cargo run --release
```

Note that this will not work without the proper dependencies installed - these are covered in the next sections.

If you want to enable logging messages, set the environment variable `RUST_LOG=TRACE`

# Linux dependencies

You need to have the development files for `libpcap` installed. For Debian-based systems, you can install them using `apt install libpcap-dev`.

# Windows dependencies

You need to install [npcap](https://npcap.com/#download) first, specifically:

- Npcap 1.60 installer (you must check the "WinPcap API compatible mode" option during installation)
- Npcap SDK 1.12

After installation, copy `Packet.lib` from the SDK to your Rust's `lib` directory. For example, mine is located in `%USERPROFILE%\.rustup\toolchains\stable-x86_64-pc-windows-msvc\lib\rustlib\x86_64-pc-windows-msvc\lib` but this can differ based on your Rust setup.

Make sure you use the correct `Packet.lib` (32 or 64 bit based on your Rust setup)!

# NetWare client setup

As only the Ethernet_II framing type is supported, you need to make sure your NetWare client uses this. For VLM-based configurations, edit `net.cfg` and add:

```
Link Driver <name>
    FRAME Ethernet_II
```

Where `<name>` is the name of your ODI driver, i.e. `PCNTNW` for AMD PCNet PCI cards such as those found in QEMU.




