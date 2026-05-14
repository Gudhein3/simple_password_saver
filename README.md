# Program
## Compilation
```shell
$ make
```
What else did you expect to see here?

## Installation
```shell
$ make local_install # Installs to ~/.local/bin/sps
```
Or
```shell
# make global_install # Installs to /usr/bin/sps
```

## Disclaimer
* All passwords shown in this demonstration as far as I know don't belong to any person and shown here for demonstration purposes only.
* This program doesn't actually provide enough any warranties that it cannot be decrypted without knowing the master password. however it's literally described in the terms of the MIT license, I want to make it clear for everybody

## Usage
Create a secret:
```shell
$ sps encrypt accounts.ѕыҏ.co
>> Please, enter your master password
<< DomShorthair2018^
>> Enter secret you want to save(press ^D^D to finish)
<< I7B1ov8]ioo_L!ZkI^#Z&qLAh!y40ax7
<< ^D^D
```

Read a secret:
```shell
$ sps decrypt accounts.ѕыҏ.co
>> Please, enter your master password
<< DomShorthair2018^
>> I7B1ov8]ioo_L!ZkI^#Z&qLAh!y40ax7
```

List secrets:
```shell
$ sps list
. accounts!ѕыҏ!co
. very-good-pancake-recipe
. gpg-private-key
. plans-on-2026!04!26
```

Remove a secret:
```shell
$ sps remove plans-on-2026!04!26
>> Do You REALLY WANT to REMOVE THE SECRET? Type 49406 if so
<< 49406
```
