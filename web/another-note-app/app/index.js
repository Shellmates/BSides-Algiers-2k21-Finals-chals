const dotenv = require("dotenv")
dotenv.config()

const env = {
  NODE_ENV: process.env.NODE_ENV || "development",
  NODE_PORT: process.env.NODE_PORT || 5000,
  STATIC_FOLDER: process.env.STATIC_FOLDER || "public",
  APP_DOMAIN: process.env.APP_DOMAIN
}

const visiter = require("./visiter")

const express = require("express")
const morgan = require("morgan")

const app = express()

app.use(express.urlencoded({
  extended: false
}))
app.use(express.static(env.STATIC_FOLDER))
app.use(morgan("combined"))

app.get("/", (req, res) => {
  return res.redirect("/index.html")
})

app.post("/report", async (req, res) => {
  try {
    const { url } = req.body

    if (url) {
      const matched = url.match(/^http:\/\/(.*?)\//)

      if (matched !== null && matched[1] === env.APP_DOMAIN) {
	await visiter.visit(url)

	return res.status(200).send("Reported to admin")
      } else {
	return res.status(400).send("Invalid url")
      }
    } else {
      return res.status(400).send("Page url not specified")
    }
  } catch(err) {
    console.error(err)
    return res.status(500).send("Internal error")
  }
})

app.listen(env.NODE_PORT, () => {
  console.log(`App listening on http://localhost:${env.NODE_PORT}`)
})
