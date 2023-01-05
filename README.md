#  github-hosts-ebpf

基于 eBPF 修改 DNS 响应包加速 GitHub 访问

## 介绍


通过 XDP 解析 DNS 响应包，当发现 DNS 解析域名为 GITHUB 相关域名时，
修改 DNS 响应包中的 A 记录为加速 IP 地址。

加速 IP 地址来源于 [ineo6/hosts](https://github.com/ineo6/hosts) 项目，该项目提供了加速国内 Github 访问的 hosts 文件。


## 使用指南


根据 [aya-rs](https://aya-rs.dev/book/start/development/) 的文档搭建 Rust 和 eBPF 的开发环境。


运行:

```sh
RUST_LOG=debug cargo xtask run
```




