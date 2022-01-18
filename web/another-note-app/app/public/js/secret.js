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
