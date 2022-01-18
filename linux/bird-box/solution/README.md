# bird-box

**`Author:`** [Ouxs](https://github.com/ouxs-19)

## Solution

After playing a little bit with this challenge, you will notice that it shows GOOD when the command is right and BAD in the other case in another way it just write the content of $? after running a command.  
First thing you can try is getting a reverse shell but it seems to be impossible because words like python, nc, bash ... seems to blocked. The idea is since when know path of the flag we can use regex to get the flag char by char.
we start like this `cat /Flag | grep shellmates{$(char)*` and now we gonna itereate through our chars the grep , if the char is wrong grep will return 1 thus outputing BAD and if we find GOOD in our result we know that it's the correct char and we can proceed to the next one.

### Flag

`shellmates{FiN3_I_WIlL_D0_I7_BLiNdLyy}`
