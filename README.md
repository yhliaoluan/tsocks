---

Async i/o socks5 proxy that can cross firewall. Compatible with ss client.

Tested on Ubuntu 14.04

---

## 1.Dependencies

# libevent
```
apt-get install libevent-dev
```

# openssl
```
apt-get install libssl-dev
```

## 2.Make

```
git clone https://github.com/yhliaoluan/tsocks.git
cd tsocks
make

#to run server on port 1308 with encrypt method rc4
./server -p 1308 -k password -m rc4

#to run server with ss client (only support table encryption)
./server -p 1308 -k password -m sstable

#to run server directly with web browser using socks v5 protocal
./server -p 1308 -m plain

#run local on port 5555
./local -p 5555 -r 1308 -m rc4 -k password
```



	
