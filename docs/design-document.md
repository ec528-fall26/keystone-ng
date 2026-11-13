# Design Document

*Due in the `demo-2` branch, updated for `demo-3` and `final-demo`.
**The TA will run this document.** If they cannot follow it, you lose the points.*

## 1. Architecture


## 2. Design decisions


## 3. Setup

_Exact dependencies, versions, and hardware assumptions. Written so that someone
starting from a clean machine can follow it._

Rust will need to be installed on the machine. If using VSCode, instructions are on the official website [here](https://code.visualstudio.com/docs/languages/rust).

1. Install the Rust tool chain [here](https://rustup.rs). This installer is for Windows, MacOS and Linux. 
2. Rust-Anlyzer is also avaliable on the VSCode extensions
3. Check if rust is installed (This workspace requires Rust 1.96 or later):
```
rustc --version
cargo --version
rustup show
```
4. The formatting and lint components can be installed or refreshed with:
```
rustup component add rustfmt clippy
```
5. Clone to Openstack Keystone fork repo: (This is our testing fork). Our code is on the `demo-2` branch, so clone that branch:
```
git clone -b demo-2 https://github.com/millionsouls/keystone.git
cd keystone
git branch --show-current
```
6. The last command should print `demo-2`.
7. Keystone needs `protoc` to build. MacOS: ```brew install protobuf```. Ubuntu: ```sudo apt-get install protobuf-compiler pkg-config 
libssl-dev```.


## 4. Running the experiments
Run every command inside the fork clone from Setup (`millionsouls/keystone`, branch `demo-2`), not in this repo.
