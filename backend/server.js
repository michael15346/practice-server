
//const express = require('express')
import express from 'express'

const app = express()
const port = process.env.PORT


app.get('/', (req, res) => {
    res.send('Hello World!');
})

app.listen(port, () => {
    console.log(`Example app listening at http://localhost:${port}`)
})

