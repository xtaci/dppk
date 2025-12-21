[![GoDoc][1]][2] [![Go Report Card][3]][4] [![CreatedAt][5]][6] 

[1]: https://godoc.org/github.com/xtaci/dppk?status.svg
[2]: https://pkg.go.dev/github.com/xtaci/dppk
[3]: https://goreportcard.com/badge/github.com/xtaci/dppk
[4]: https://goreportcard.com/report/github.com/xtaci/dppk
[5]: https://img.shields.io/github/created-at/xtaci/dppk
[6]: https://img.shields.io/github/created-at/xtaci/dppk

[English](README.md) | 简体中文

# 确定性多项式公钥算法 (DPPK)

一种基于素数伽罗瓦域 GF(p) 的[确定性多项式公钥算法](https://www.researchgate.net/profile/Randy-Kuang/publication/358101087_A_Deterministic_Polynomial_Public_Key_Algorithm_over_a_Prime_Galois_Field_GFp/links/61f95ff44393577abe055af7/A-Deterministic-Polynomial-Public-Key-Algorithm-over-a-Prime-Galois-Field-GFp.pdf)。

DPPK 是一种[密钥封装机制](https://en.wikipedia.org/wiki/Key_encapsulation_mechanism)（Key Encapsulation Mechanism, KEM），提供抗量子攻击的密码学安全保障。

## 概述

古老的[韦达定理](https://en.wikipedia.org/wiki/Vieta%27s_formulas)揭示了 n 次多项式的系数与其根之间的深刻联系。令人惊叹的是，研究者发现了一种全新的公钥加密思想：通过将多项式所有根的乘积（常数项）与系数相分离，可以构建出安全可靠的密钥对系统。

## 核心原理

1. **因式分解依赖性**：DPPK 算法利用了缺少常数项的多项式无法有效因式分解这一数学特性。
2. **密钥对构造**：密钥对生成器将一个可在解密过程中消去的基础多项式与两个可解多项式相结合，创建出两个相互纠缠的多项式。
   - **公钥**：由纠缠多项式的系数向量组成。
   - **私钥**：由纠缠多项式的常数项以及两个可解多项式组成。

## 安全机制

- 仅发布多项式的系数而不发布常数项，可以极大地限制攻击者通过多项式因式分解技术提取私钥的可能性。
- 从公钥中提取私钥的时间复杂度为：
  - **经典计算攻击**：超指数级难度 $O(p^2)$
  - **量子计算攻击**：指数级难度 $O(p)$
- 相比之下，传统多项式因式分解问题（PFP）的复杂度为：
  - **经典计算攻击**：$O(n\sqrt{p})$
  - **量子计算攻击**：$O(\sqrt{p})$，与 Grover 搜索算法的复杂度相当

## 密钥对生成及加解密原理

- 密钥对构造的核心思想源于韦达定理，通过将多项式系数分解为两类：
  - **私有部分**：来自常数项
  - **公开部分**：来自不定元 $x$ 的系数

- DPPK 使用两个纠缠的通用多项式，它们基于一个公共基础多项式 $B_n(x)$ 以及两个可解多项式 $u(x)$ 和 $v(x)$：
  - **公钥**：纠缠多项式的所有系数
  - **私钥**：纠缠多项式的常数项以及两个可解多项式

## 安全性分析

- **确定性时间复杂度**：
  - **经典计算攻击**：$O(\sqrt{p})$（超指数级难度）
  - **量子计算攻击**：$O(p)$（指数级难度）
  
## 安装

使用以下命令安装 DPPK：
```console
go get -u github.com/xtaci/dppk
```

## 使用示例

### 密钥对生成

以下示例展示了如何为 Alice 和 Bob 生成密钥对：

```go
package main

import (
    "github.com/xtaci/dppk"
    "log"
)

func main() {
    // 为 Alice 生成密钥
    alice, err := dppk.GenerateKey(10)
    if err != nil {
        log.Fatal(err)
    }

    // 为 Bob 生成密钥
    bob, err := dppk.GenerateKey(10)
    if err != nil {
        log.Fatal(err)
    }

    log.Println("Alice 的公钥:", alice.PublicKey)
    log.Println("Bob 的公钥:", bob.PublicKey)
}
```

### 加密

以下示例展示了 Bob 如何使用 Alice 的公钥加密消息：

```go
package main

import (
    "github.com/xtaci/dppk"
    "log"
)

func main() {
    // 假设 alice 和 bob 已生成密钥
    alice, _ := dppk.GenerateKey(10)
    bob, _ := dppk.GenerateKey(10)

    // 待加密的消息
    secret := []byte("hello quantum")

    // Bob 使用 Alice 的公钥加密消息
    kem, err := dppk.Encrypt(&alice.PublicKey, secret)
    if err != nil {
        log.Fatal(err)
    }

    log.Printf("KEM: %+v\n", kem)
}
```

### 解密

以下示例展示了 Alice 如何使用私钥解密 Bob 发送的消息：

```go
package main

import (
    "github.com/xtaci/dppk"
    "log"
)

func main() {
    // 假设已生成密钥，且 Bob 已加密消息
    alice, _ := dppk.GenerateKey(10)
    bob, _ := dppk.GenerateKey(10)
    secret := []byte("hello quantum")
    kem, _ := dppk.Encrypt(&alice.PublicKey, secret)

    // Alice 使用私钥解密消息
    plaintext, err := alice.DecryptMessage(kem)
    if err != nil {
        log.Fatal(err)
    }

    log.Println("恢复的消息:", string(plaintext))
}
```

## 贡献

我们欢迎各种形式的贡献！如果您发现错误、有改进建议或希望添加新功能，请随时提交 issue 或 pull request。

## 许可证

本项目采用 GPLv3 许可证。详情请参阅 [LICENSE](LICENSE) 文件。

## 参考文献

如需了解更多技术细节，请参阅[原始研究论文](https://www.researchgate.net/profile/Randy-Kuang/publication/358101087_A_Deterministic_Polynomial_Public_Key_Algorithm_over_a_Prime_Galois_Field_GFp/links/61f95ff44393577abe055af7/A-Deterministic-Polynomial-Public-Key-Algorithm-over-a-Prime-Galois-Field-GFp.pdf)。

## 致谢

特别感谢 DPPK 研究论文的作者们在后量子密码学领域所做的开创性工作。
