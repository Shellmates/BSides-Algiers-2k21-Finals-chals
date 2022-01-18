# The Pursuit

## Write-up
### 1- check Statistics 

`Statistics` -> `Protocol hierarchy`

![IMG](./hierarchy.png)

There is some specious SMB traffic, let's check it out by filtering `smb2` packets

![IMG](./smb.png)

Well! someone is transferring files !

### 2- Extract the files
Go to `File` -> `Export Objects` -> `SMB..`

![IMG](./objects.png)

there is a ```zip``` compressed file, select then save.

### 3- Crack the ZIP file

- the file is a password protected ZIP, `zip2john` will do the job! 
- Next, lets convert it to `JtR`’s cracking format

```console
zip2john CrackMe.zip > Crackme.zip.hash

```
- Attack! using the Dictionary: `rockyou.txt`

```console
john --wordlist=/usr/share/wordlists/rockyou.txt Crackme.zip.hash
```

  
![IMG](./zip2john.png)

Password : `PINKPANTHER`

- Extract Files..

```console
7z x CrackMe.zip -p"PINKPANTHER"
```
![IMG](./7zip.png)

output files: `whoami`
### 4- Bringing out the evidence
- analyze the file

```console
file whoami
```
![IMG](./file.png)
- check for some hidden files with `binwalk`

```console
binwalk --dd='.*' whoami
```

![IMG](./binwalk.png)

Here we are ! 

![IMG](./flag.gif)
## Flag

`shellmates{Y0U_w0n_th3_pur5u1t}`
