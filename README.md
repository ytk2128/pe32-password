# 🔐 pe32-password
Sample project that locks and encrypts windows 32-bit executables with password.

## Libraries used in this project
* PE32
  * made by [ytk2128](https://ytk2128.github.io) for modifying windows pe32 executables and injecting assembly code into executables
* [SEED128 ECB](https://seed.kisa.or.kr/kisa/Board/17/detailView.do)
  * symmetric-key algorithm provided by [Korea Internet & Security Agency](https://www.kisa.or.kr/main.jsp)

## Principle of encryption
![executable before encryption](https://raw.githubusercontent.com/ytk2128/pe32-password/main/doc/before.svg?token=AOLEOH4JRZ4XWXETO5D4BFTBRZVM2)
![executable before encryption](https://raw.githubusercontent.com/ytk2128/pe32-password/main/doc/after.svg?token=AOLEOH6SY2LOYCHE7YG4PFTBRZVJU)

## Build instructions
* Open **pepw.sln**
* Set **Solution Platforms -> x64**
* Set **Project -> Properties -> Advanced -> Character Set -> Use Multi-Byte Character Set**
* Build Solution

## Materials
* [PE32 Password.pdf](https://github.com/ytk2128/pe32-password/blob/main/doc/PE32_Password.pdf)
* [Demo.mp4](https://github.com/ytk2128/pe32-password/blob/main/doc/Demo.mp4?raw=true)
