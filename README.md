# keywright

My C++20 monorepo for credential generation. It's currently Windows-first, so Linux 
and macOS support come later. 

## passgen

A small CLI that generates a random password for an account then puts it on the clipboard.

Usage:
```cpp
passgen --user <name> --min-length N [--ns namespace-name] --print
passgen --make-keyfile PATH
```

^^ Keep the keyfile away from the vault because the app writes random 64 bytes to it and will 
refuse to overrwite.

## Build

Standard CMake configuration and build procedure. [vcpkg](https://vcpkg.io/) is required. 
