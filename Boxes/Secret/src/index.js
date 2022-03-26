const express = require('express');
const app = express();
const mongoose = require('mongoose');
const dotenv = require('dotenv')
const privRoute = require('./routes/private')
const bodyParser = require('body-parser')

app.use(express.static('public'))
app.use('/assets', express.static(__dirname + 'public/assets'))
app.use('/download', express.static(__dirname + 'public/source'))

app.set('views', './src/views')
app.set('view engine', 'ejs')


// import routs 
const authRoute = require('./routes/auth');
const webroute = require('./src/routes/web')

dotenv.config();
//connect db 

mongoose.connect(process.env.DB_CONNECT, { useNewUrlParser: true }, () =>
    console.log("connect to db!")
);

//middle ware 
app.use(express.json());
app.use('/api/user',authRoute)
app.use('/api/', privRoute)
app.use('/', webroute)

app.listen(3000, () => console.log("server up and running"));

