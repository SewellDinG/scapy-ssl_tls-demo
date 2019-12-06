## 目的

1、使用pcapSplitter将数据包按connection分割。

2、使用 Python3 的scapy库提取SSL/TLS流量特征。

## 环境搭建

系统：类Unix环境均可，建议CentOS和Ubuntu。

Bash shell：脚本pcapSplitter，将当前目录下的所有*.pcap文件按会话拆分为Session流并单独保存，直接使用./ pcapSplitter执行即可。

Python：使用Python 3.7.x，脚本main.py和gettls.py，字节码对照文件目录protocal，标准库csv，第三方库scapy 2.4.3，以及针对scapy ssl/tls layer的第三方拓展包。 

相应实验代码所在目录tree：

```
[Sewell]: ~/Downloads/XDU
➜  tree
├── gettls.py
├── main.py
├── pcapSplitter
└── protocol
    ├── ETHER
    ├── FILES
    ├── IP
    ├── PORT
    ├── TCP
    ├── UDP
    └── WARN
```

由于scapy天生并不支持SSL/TLS解析，且旧的[scapy-ssl_tls](https://github.com/tintinweb/scapy-ssl_tls)拓展不支持Python3，因此拓展代码使用的是kalidasya更改后的scapy-ssl_tls拓展，项目地址：[https://github.com/kalidasya/scapy-ssl_tls/tree/py3_update](https://github.com/kalidasya/scapy-ssl_tls/tree/py3_update)

1、查看Python版本，解压缩scapy-ssl_tls-py3_update.zip，利用pip安装scapy及相关依赖包，查看scapy包安装位置，将zip解压的指定内容导入相应位置，最后修改scapy的配置文件，将ssl_tls添加进load_layers列表中，完成导入：

```
[Sewell]: ~/Downloads/XDU
➜  which python
/usr/local/bin/python
[Sewell]: ~/Downloads/XDU
➜  unzip scapy-ssl_tls-py3_update.zip
[Sewell]: ~/Downloads/XDU
➜  cd scapy-ssl_tls-py3_update
[Sewell]: ~/Downloads/XDU/scapy-ssl_tls-py3_update
➜  pip install -r requirements.txt
Requirement already satisfied: pycryptodomex>=3.4 in /usr/local/lib/python3.7/site-packages (from -r requirements.txt (line 1)) (3.9.4)
Requirement already satisfied: scapy==2.4.* in /usr/local/lib/python3.7/site-packages (from -r requirements.txt (line 2)) (2.4.3)
Requirement already satisfied: tinyec>=0.3.1 in /usr/local/lib/python3.7/site-packages (from -r requirements.txt (line 3)) (0.3.1)
[Sewell]: ~/Downloads/XDU/scapy-ssl_tls-py3_update
➜  python -c "import scapy; print(scapy.__file__)"
/usr/local/lib/python3.7/site-packages/scapy/__init__.py
[Sewell]: ~/Downloads/XDU/scapy-ssl_tls-py3_update
➜  cp scapy_ssl_tls/* /usr/local/lib/python3.7/site-packages/scapy/layers/
[Sewell]: ~/Downloads/XDU/scapy-ssl_tls-py3_update
➜  vim /usr/local/lib/python3.7/site-packages/scapy/config.py
```

注：配置信息修改可查看scapy-ssl_tls-py3_update文件夹下的README.md。

2、验证配置结果：进入python交互页面，或使用ipython。

```
In [1]: from scapy.all import *
In [2]: TLS
Out[2]: scapy.layers.ssl_tls.SSL
```

无报错，且成功识别出TLS即配置成功。

## 特征提取

测试使用的原始pcap数据包来自Stratosphere Lab公开的恶意软件捕获结果集，目前公开有349个恶意样本集，涵盖了大多数恶意软件家族的原始流量数据及相应的二进制恶意软件。

1、将原始pcap数据集放到当前目录，赋予pcapSplitter脚本执行权限，并执行脚本，分割的结果会输出到session_pcap目录下以相应家族名命名的文件夹里：

```
[Sewell]: ~/Downloads/XDU
➜  ls *pcap
Cobalt.pcap	DownloadGuide.pcap	Dridex.pcap	Dynamer.pcap	Razy.pcap	Trojan.pcap
[Sewell]: ~/Downloads/XDU
➜  chmod +x pcapSplitter
[Sewell]: ~/Downloads/XDU
➜  ./pcapSplitter
./Cobalt.pcap is file
Started...
Finished. Read and written 1471709 packets to 1877 files
./DownloadGuide.pcap is file
Started...
Finished. Read and written 298724 packets to 3979 files
./Dridex.pcap is file
Started...
Finished. Read and written 1384446 packets to 42397 files
./Dynamer.pcap is file
Started...
Finished. Read and written 1492896 packets to 47016 files
./Razy.pcap is file
Started...
Finished. Read and written 86869 packets to 5310 files
./Trojan.pcap is file
Started...
Finished. Read and written 1353685 packets to 24488 files
```

2、分别进入各个家族分割好的文件夹中，将大型数据包（size >=10k）、小型数据包（size <= 1k）以及不含SSL/TLS流量的数据包进行人工剔除。这一步目的是减少特征提取程序运行的时间，因此手工剔除不需要太精细。

3、回到主目录，修改main.py里的root_path变量，使用Python3运行main.py脚本，输出每个数据流的特征，程序会依据文件名（即家族名）打标签，保存为csv格式，文件名为家族名.csv。

```
[Sewell]: ~/Downloads/XDU
➜  python main.py
['192.168.1.118:50048-52.32.214.155:443', 'Dynamer', 16, 0.842875, 4401, 338.53846153846155, 6864, 858.0, 49199, 0, 17, 65281, 769]
['192.168.1.118:51337-54.201.61.25:443', 'Dynamer', 14, 1.270383, 4080, 370.90909090909093, 6201, 1033.5, 49199, 0, 17, 65281, 769]
['192.168.1.118:50805-52.38.152.98:443', 'Dynamer', 14, 0.831688, 4080, 370.90909090909093, 6201, 1033.5, 49199, 0, 17, 65281, 769]
......
```

注：特征字段名及含义见附录1。

4、使用shell重定向功能将所有csv文件合并为一个文件，文件名为feature.csv。

```
[Sewell]: ~/Downloads/XDU
➜  ls *.csv
Dynamer.csv Dridex.csv Cobalt.csv DownloadGuide.csv Razy.csv Trojan.csv
[Sewell]: ~/Downloads/XDU
➜  cat *.csv >> feature.csv
[Sewell]: ~/Downloads/ XDU
➜  tail feature.csv
192.168.1.119:54683-185.26.182.117:443,Trojan,12,0.039839,3511,390.1111111111111,55154,11030.8,49191,0,8,11,771
192.168.1.119:49872-185.26.182.104:443,Trojan,14,5.127901,3518,319.8181818181818,11569,2313.8,49199,0,36,65281,769
192.168.1.119:54413-185.26.182.117:443,Trojan,21,3.856706,4831,268.3888888888889,15468,1718.6666666666667,49199,0,36,65281,769
......
```

## 附录1 特征结构

特征字段名及相应描述：

| 字段名               | 特征描述                |
| ----------------- | ------------------- |
| si_sport_di_dport | 源IP、端口及目的IP、端口      |
| label             | 恶意软件所属家族名           |
| sessn_dur         | Session流持续时长        |
| pkts_cnt          | Session流中数据包数量      |
| total_bytes       | Session流总字节数        |
| pkts_len_avg      | Session流中数据包平均包长    |
| tls_vers          | TLS版本号              |
| tls_cip           | TLS使用的密码套件          |
| tls_step          | TLS阶段号              |
| tls_extlen        | TLS拓展组件长度           |
| tls_exttype       | TLS使用的拓展组件类型        |
| tls_comp          | TLS使用的压缩方法          |
| tls_len           | TLS数据包字节数           |
| total_bytes_tls   | Session流中TLS数据包总字节数 |
| tlss_len_avg      | Session流中TLS数据包平均长度 |

特征输出格式：

```
si_sport_di_dport, label, pkts_cnt, sessn_dur, total_bytes, pkts_len_avg, total_bytes_tls, tlss_len_avg, tls_cip, tls_comp, tls_extlen, tls_exttype, tls_vers
```

## 附录2 其他

1、scapy帮助文档：[https://www.osgeo.cn/scapy](https://www.osgeo.cn/scapy)   

2、SSL/TLS Cipher Suites 对照表：`openssl ciphers -V | column -t`

3、debug程序，程序名为tls_debug.py，可以根据此代码学习利用scapy解码数据包的过程，数据包示例为tcp_ssl_demo_0.pcap，包含了完整的TCP三次握手、TLS握手和数据交换过程。

```
[Sewell]: ~/Downloads/XDU 
➜  python tls_debug.py
--------------- Packet: 1 ---------------
{
  "time": "1970-01-01 08:06:19.514986",
  "len": 66,
  "IP": {
    "source": "192.168.1.123:49158",
    "destination": "198.100.127.43:443",
    "TCP": {
      "Procotol": "HTTPS"
    }
  }
}
......
--------------- Packet: 6 ---------------
{
  "time": "1970-01-01 08:06:19.853669",
  "len": 1514,
  "IP": {
    "source": "198.100.127.43:443",
    "destination": "192.168.1.123:49158",
    "TCP": {
      "Procotol": "HTTPS",
      "TLS": {
        "tls_vers": 771,
        "tls_len": 84,
        "tls_step": 2,
        "tls_cip": 49191,
        "tls_comp": 0,
        "tls_extlen": 8,
        "tls_exttype": 11
      }
    }
  }
}
......
{'si_sport_di_dport': '192.168.1.123:49158-198.100.127.43:443', 'pkts_cnt': 22, 'sessn_dur': 1.041785, 'total_bytes': 6100, 'pkts_len_avg': 321.05263157894734, 'total_bytes_tls': 66878, 'tlss_len_avg': 6687.8, 'tls_cip': 49191, 'tls_comp': 0, 'tls_extlen': 8, 'tls_exttype': 11}
```

接受一个Session会话流，依次解析流中的数据包，并输出从当前数据包获取到的相应内容，最后会输出此Session流的相关信息。

## 感谢

特征提取部分的代码逻辑参考项目：[Pcap-Analyzer](https://github.com/HatBoy/Pcap-Analyzer)