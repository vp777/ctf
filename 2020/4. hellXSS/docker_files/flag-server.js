var express = require('express');
var cors = require('cors')

var app = express();

app.use(cors())

app.get('/flag', function(req, res, next){
  res.send("CTF{n07_50_un70uch4bl3_4f73r_4ll}");
});

app.listen(1337);
