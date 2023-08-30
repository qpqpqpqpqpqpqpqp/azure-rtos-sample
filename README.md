---
page_type: sample
languages:
  - c
  - asm
name: 'Azure RTOS Microsoft Learning Samples'
description: 'Sample projects for Azure RTOS Microsoft Learning courses how.'
products:
  - azure-rtos
---

# Azure RTOS Microsoft Learning Samples

This repo contains sample projects for

- [Azure RTOS ThreadX Learning Path](https://learn.microsoft.com/training/paths/azure-rtos-threadx/)
- [Azure RTOS NetX Duo Learning path](https://learn.microsoft.com/training/paths/azure-rtos-netx-duo/)

## Get started

### Use GitHub Codespaces

[GitHub Codespaces](https://github.com/features/codespaces) is the preferred way to building and run these sample if you have your GitHub account enabled for this feature. Otherwise, you can still use it with the [local dev container](https://code.visualstudio.com/docs/remote/containers) or set up the toolchain by your own.

Follow the [Set up environment](https://learn.microsoft.com/training/modules/introduction-azure-rtos/2-set-up-environment) unit to get started with the samples.

#### Directory layout

    .
    ├── cmake                        # CMakelist files for building the project
    ├── docs                         # Documentation supplements
    ├── courses                      # Source code for learning paths
    │   ├── netxduo                  # NetX Duo samples
    │   └── threadx                  # ThreadX samples
    ├── libs                         # Submoduled ThreadX and NetX Duo source code
    └── tools                        # Required scripts for using NetX Duo within the container

### Use Visual Studio

You can also find the sample projects that can be built and run with Visual Studio in the [release page](https://github.com/Azure-Samples/azure-rtos-learn-samples/releases/tag/vs). An alternative for using the sample projects. Follow the [get started](#get-started) section above or the readme file in the `.zip` to learn how to use it.

## Resources

- [Azure RTOS](https://aka.ms/rtos)
- [Azure RTOS on GitHub](https://github.com/azure-rtos)
- [PDF: Real-Time Embedded Multithreading Using ThreadX 4th Edition](https://github.com/Azure-Samples/azure-rtos-learn-samples/releases/download/book/Real-Time_Embedded_Multithreading_with_ThreadX_4th_Edition.pdf)

For some common issues we found, please visit [Wiki](https://github.com/Azure-Samples/azure-rtos-learn-samples/wiki).

<br>
<br>
<br>

# TLS通信サンプルプログラムの動作手順

## 準備するモノ
* PC
* ネットワーク環境
* GitHubアカウント(Codespaces使用時に必要)



## 手順

* 下記へアクセスする。  
  https://github.com/qpqpqpqpqpqpqpqp/azure-rtos-sample

* 「<> Code ▽」→「Codespaces」の順にクリックし、Codespacesを起動させる。

* エクスプローラーを開き、順に「TASK EXPLORER」→「vscode」→「Build NetX Projects」→「ProjectHTTPSServer」をクリックし、ビルドを実行する。

* 同様に、「TASK EXPLORER」→「vscode」→「Build NetX Projects」→「ProjectHTTPSClient」をクリックし、ビルドを実行する。

* 下記コマンドを実行し、"courses/netxduo"にある"ProjectHTTPSServer"を実行する。
``` bash
$ sudo ./tools/init_network.sh>/dev/null 2>&1 && exe=./courses/netxduo/ProjectHTTPSServer/build/ProjectHTTPSServer && echo $exe && sudo setcap cap_net_raw,cap_net_admin=eip $exe && $exe
```

* 下記コマンドを実行し、"courses/netxduo"にある"ProjectHTTPSClient"を実行する。
``` bash
$ sudo ./tools/init_network.sh>/dev/null 2>&1 && exe=./courses/netxduo/ProjectHTTPSClient/build/ProjectHTTPSClient && echo $exe && sudo setcap cap_net_raw,cap_net_admin=eip $exe && $exe
```

* 下記出力を確認する。
  
  (1) Client側で
    ``` text
    Received data: HTTP/1.1 200 OK
    Date: Tue, 19 May 2020 23:59:59 GMT
    Content-Type: text/html
    Content-Length: 200
    ```
    が出力されている。  
    → Serverとの通信が成功している。

  (2) Server/Client両方で、各関数の処理結果が全て"0"又は"0x00"である。  
      → 処理が全て正常終了している。



## 鍵生成方法

自分で鍵を生成する場合に、下記方法を順に実行する事。  
サンプルプログラムでは、鍵と証明書はDER形式で直接コード内に埋め込んでいる為、新規生成する場合は書き換える事。

1. 秘密鍵(.key)を作成する [ RSA2048 ]
``` bash
$ openssl genrsa -out key/server_private.key
```

2. 証明書署名要求(.csr)を作成する [ SHA-256 ]
``` bash
$ openssl req -new -sha256 -key server_private.key -out server.csr
```

3. 自己署名証明書(.crt)を作成する [ X509形式 ]
``` bash
$ openssl x509 -req -in server.csr -signkey server_private.key -out server.crt -days 3650
```

4. 自己署名証明書(.crt) → DER(.der) 変換
``` bash
$ openssl x509 -in server.crt -out server.crt.der -outform der
```

5. 秘密鍵(.key) → DER変換
~~~ bash
$ openssl rsa -in server_private.key -out server_private.key.der -outform der
~~~

## 参照
【参照】
第 2 章 - Azure RTOS NetX Secure のインストールと使用  
https://learn.microsoft.com/ja-jp/azure/rtos/netx-duo/netx-secure-tls/chapter2

RSA鍵、証明書のファイルフォーマットについて  
https://qiita.com/kunichiko/items/12cbccaadcbf41c72735

オレオレ証明書作ってみる  
https://qiita.com/miyuki_samitani/items/b19aa5ac3b3c6e312bd5



