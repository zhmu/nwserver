# Novell NetWare 3.12 server

This is a NetWare 3.12 server written in Rust. The main benefit is that it does not rely on an IPX stack, as it uses [libpnet](https://github.com/libpnet/libpnet) to construct and process IPX packets.

This is in very early stages as this point - it should be decent enough to provide simple file sharing without any access control what so ever.