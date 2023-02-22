# Petunia

Petunia is a set of script to aid in writing TC-flower ACLS for
DENT/switchdev devices.

## Documentation

Current documentation is on the
[GitHub Wiki](https://github.com/dentproject/petunia/wiki).

## To create the debian package
```
$ git clone https://github.com/dentproject/dentOS.git
$ cd dentOS
$ sudo docker/tools/onlbuilder
$ apt update
$ apt install python3-pip python3-all -y
$ pip3 install stdeb
$ python3 setup.py --command-packages=stdeb.command bdist_deb
$ ls bdist_deb/python3-petunia_1.0-1_all.deb

```