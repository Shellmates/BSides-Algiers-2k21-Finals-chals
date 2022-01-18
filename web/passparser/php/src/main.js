// AXIOS GLOBALS
axios.defaults.headers.common['X-Auth-Token'] =
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';

// GET REQUEST
function getData() {


//update cURL!!!
  axios
    .get('verify.php?url=http://passparser.web.ctf.shellmates.club/data.html', {
      timeout: 5000
    })
    .then(res => showOutput(res))
    .catch(err => console.error(err));
}


// Show output in browser
function showOutput(res) {
  document.getElementById('res').innerHTML = res.data;
}

// Event listeners
document.getElementById('get').addEventListener('click', getData);
