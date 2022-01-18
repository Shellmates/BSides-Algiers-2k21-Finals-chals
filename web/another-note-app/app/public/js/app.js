var url = new URL(window.location.href)

function debounce(func, wait, immediate) {
  var timeout;

  return function() {
    var context = this,
      args = arguments;

    var callNow = immediate && !timeout;
    clearTimeout(timeout);
    timeout = setTimeout(function() {

    timeout = null;

    if (!immediate) {
	func.apply(context, args);
      }
    }, wait);

    if (callNow) func.apply(context, args);
  }
}

function process() {
  var note = input.value

  if (note !== "") {
    var output = document.getElementById("output")
    if (output !== null) {
      document.getElementById("container-output").removeChild(output)
    }

    var div = document.createElement("div")
    div.id = "output"
    var sanitized = DOMPurify.sanitize(note)
    console.log(sanitized)
    div.innerHTML = sanitized
    document.getElementById("container-output").appendChild(div)

    var secretScript = document.getElementById("secret")
    if (secretScript !== null) {
      document.body.removeChild(secretScript)
    }

    var script = document.createElement("script")
    script.id = "secret"
    script.src = "/js/secret.js"
    document.body.appendChild(script)
  }
}

input.value = url.searchParams.get("note")

window.debouncedProcess = debounce(process, 100)
debouncedProcess()
