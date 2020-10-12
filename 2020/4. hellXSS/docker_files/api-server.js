const express = require('express');
const fs = require('fs');
const path = require('path');

var app = express();
app.use(express.urlencoded({ extended: true }))

var commentsFile = './comments.txt';
fs.appendFileSync(commentsFile, "");
var contents = fs.readFileSync(commentsFile, 'utf8');

app.get('/js', function(req, res){
  res.set('Content-Type', 'text/javascript');
  res.send(`${req.query.cb}([${contents.slice(0,-1)}]);`);
});

app.post('/add', function(req, res){
  if (req.headers.referer && req.headers.referer.toLowerCase().includes("reviews")){
    res.send("Cannot post reviews from /reviews page");
  } else if (!("author" in req.body) || !("body" in req.body)){
    res.send("Error");
  } else {
    var feedback = JSON.stringify({
      'author': req.body.author,
      'body': req.body.body,
    });
    fs.appendFile(commentsFile, `${feedback},`, (err) => {});
    contents = `${feedback},${contents}`;
    res.send("Comment Added!");
  }
});

app.get('/flush', function(req, res){
  fs.unlink(commentsFile, (err) => {});
  contents="";
  res.send("Comments flushed!");
});

app.listen(9999);
