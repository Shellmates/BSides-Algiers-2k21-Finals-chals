# passparser

Description:
All we know is that there are critical internal services on the ports [9000-9030]

## Write-up

### Inspiration

If there's anything I've learned about the Log4Shell vulnerability, it's that people don't pay the right amount of attention to security conferences like the Black Hat conference, and that understanding URL Parsing Confusion is a must today.

### Solution 

The first thing that we can notice is the main.js source code with two hints:
	- A comment that leak backend lib `cURL`
	- /verify.php endpoint with a parameter `URL`
This parameter is commonly related to the SSRF vulnerability.

```
//update cURL!!!
  axios
    .get('verify.php?url=http://passparser.web.ctf.shellmates.club/data.html', {
      timeout: 5000
    })
    .then(res => showOutput(res))
    .catch(err => console.error(err));
}
```

And another hint is on the response header of the /verify.php endpoint:

```
X-Powered-By: PHP/7.0.33
```

The description has mentioned that there are internal services, so let us try to request the localhost:

```
Response:
You don't have permesion
```
It's obvious that there is a whitelisting going on, and we have to look for a bypass...

With all the hints that we have (cURL, parser, SSRF, PHP) google will lead us to:
[A New Era Of SSRF](https://www.blackhat.com/docs/us-17/thursday/us-17-Tsai-A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages.pdf) by Orange Tsai

After reading the paper, you will find a payload related to cURL:

```
http://foo@evil.com:80@google.com/
```

Modifying the payload according to our needs, we'll get an empty response, which means we bypassed it successfully:


```
http://@localhost:9009@passparser.web.ctf.shellmates.club

```

The next step is just to brute force the port from `9000` to `9030` which will take us to port `9009` with the flag:

`shellmates{SsRF_iS_THE_B3St}`

## Flag

`shellmates{SsRF_iS_THE_B3St}`
