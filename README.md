#  github-hosts-ebpf

基于 eBPF 修改 DNS 响应包加速 GitHub 访问

相关博客：[基于 eBPF+Rust 的 Github DNS 加速](https://b1tg.github.io/post/github-hosts-ebpf/)

## 介绍


通过 XDP 解析 DNS 响应包，当发现 DNS 解析域名为 GITHUB 相关域名时，
修改 DNS 响应包中的 A 记录为加速 IP 地址。

加速 IP 地址来源于 [ineo6/hosts](https://github.com/ineo6/hosts) 项目，该项目提供了加速国内 Github 访问的 hosts 文件。


## 使用指南


根据 [aya-rs](https://aya-rs.dev/book/start/development/) 的文档搭建 Rust 和 eBPF 的开发环境。


运行效果如下，当检测到 GITHUB 相关域名时替换 DNS 响应包中的 IP 地址：

```sh
$ RUST_LOG=debug cargo xtask run
add github hosts: github.io: 185.199.108.153
add github hosts: github.io: 185.199.108.153
add github hosts: github.com: 140.82.113.4
add github hosts: api.github.com: 140.82.114.5
add github hosts: raw.githubusercontent.com: 185.199.108.133
[...]
[2023-01-05T10:33:44Z INFO  github_hosts] Waiting for Ctrl-C...
[2023-01-05T10:33:58Z INFO  github_hosts] received a DNS packet
[2023-01-05T10:33:58Z INFO  github_hosts] found github hosts
[2023-01-05T10:33:58Z INFO  github_hosts] old ip: 185.199.111.133
[2023-01-05T10:33:58Z INFO  github_hosts] new ip: 185.199.108.133

```





