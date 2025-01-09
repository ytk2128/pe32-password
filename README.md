# 🔐 PE32 Password
Simple password-based PE encryptor for Windows 32-bit executables.

## Core components
* PE32 & [AsmJit](https://github.com/asmjit/asmjit): Windows PE32 executable manipulation and assembly code injection
* [SEED128 ECB](https://seed.kisa.or.kr/kisa/algorithm/EgovSeedInfo.do): Symmetric block cipher developed by [Korea Internet & Security Agency](https://www.kisa.or.kr/EN)

## Principle of encryption
![executable before encryption](https://raw.githubusercontent.com/ytk2128/pe32-password/refs/heads/main/doc/before.svg)
![executable before encryption](https://raw.githubusercontent.com/ytk2128/pe32-password/refs/heads/main/doc/after.svg)

## Build instructions
1. ```git clone https://github.com/ytk2128/pe32-password.git --recurse-submodules```
2. Open **src/pepw.sln**
3. Build the solution

## Related documents
* [PE32_Password.pdf](https://github.com/ytk2128/pe32-password/blob/main/doc/PE32_Password.pdf)
* [PE32_Password.pptx](https://github.com/ytk2128/pe32-password/blob/main/doc/PE32_Password.pptx?raw=true)
* [Demo.mp4](https://github.com/ytk2128/pe32-password/blob/main/doc/Demo.mp4?raw=true)
