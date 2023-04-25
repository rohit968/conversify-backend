const express = require('express');
const app = express();
const mongoose = require('mongoose');
const bodyparser = require('body-parser');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const dotenv = require('dotenv');
const multer = require('multer');
const ws = require('ws');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

const User = require('./models/User');
const Message = require('./models/Message');

app.use(express.json());
app.use(cookieParser());
app.use(express.static('public'));
app.use(cors({
  origin: true,
  credentials: true,
}));
dotenv.config();
mongoose.connect(process.env.MONGO_CONNECT_URL);
const jwtSecret = process.env.JWT_SECRET
const storage = multer.diskStorage({
  destination: function (req, file, callback) {
    callback(null, 'public/uploads/');
  },
  filename: function (req, file, callback) {
    callback(null, Date.now() + path.extname(file.originalname));
  }
});
const upload = multer({ storage: storage });

app.post('/register', upload.single('photo'), async (req, res) => {
  const { name, gender, email, password } = req.body;
  const { filename } = req.file;
  const securePass = bcrypt.hashSync(password, 15);
  try {
    const createdUser = await User.create({ name, gender, email, photo: filename, password: securePass });
    jwt.sign({ userId: createdUser._id, name: createdUser.name, gender: createdUser.gender, photo: createdUser.photo, email: createdUser.email }, jwtSecret, {}, (err, token) => {
      if (err) throw err;
      res.cookie('token', token, { httpOnly: true, secure: true, sameSite: 'none', path: '/' }).status(201).json({ name: createdUser.name, gender: createdUser.gender, email: createdUser.email });
    })
  } catch (err) {
    res.json("Error");
  }
})

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const findUser = await User.findOne({ email: email });
    if (findUser) {
      const passOk = bcrypt.compareSync(password, findUser.password);
      if (passOk) {
        jwt.sign({ userId: findUser._id, name: findUser.name, gender: findUser.gender, email: findUser.email, photo: findUser.photo }, jwtSecret, {}, (err, token) => {
          if (err) throw err;
          res.cookie('token', token, { httpOnly: true, secure: true, sameSite: 'none', path: '/' }).status(201).json(findUser);
        });
      } else {
        res.json("Password not matched");
      }
    } else {
      res.status(401).json('User not found');
    }
  }
  catch (err) {
    res.status(500).json('Internal Server Error');
  }
});

const getUserDataByToken = async (req, res) => {
  return new Promise((resolve, reject) => {
    const { token } = req.cookies;
    if (token) {
      jwt.verify(token, jwtSecret, {}, (err, data) => {
        if (err) throw err;
        resolve(data);
      });
    } else {
      reject('no token');
    };
  })
}

app.get('/people', async (req, res) => {
  const allPeople = await User.find({}, { '_id': 1, 'name': 1, photo: 1 });
  res.json(allPeople);
})

app.get('/profile', (req, res) => {
  const { token } = req.cookies;
  if (token) {
    jwt.verify(token, jwtSecret, {}, (err, data) => {
      if (err) throw err;
      res.json(data);
    })
  } else {
    res.status(401).json('no token');
  }
})

app.get('/messages/:userId', async (req, res) => {
  const { userId } = req.params;
  const userData = await getUserDataByToken(req);
  const ourUserId = userData.userId;
  const retrievedMsgs = await Message.find({
    sender: { $in: [userId, ourUserId] },
    recipient: { $in: [userId, ourUserId] },
  });
  res.json(retrievedMsgs)
})

app.post('/logout', (req, res) => {
  res.cookie('token', '').json("Logged Out");
})

app.post("/test", (req, res) => {
  res.json("ok")
})

const server = app.listen(4000);

//Connecting to a web socket server
const wsserver = new ws.WebSocketServer({ server });


wsserver.on('connection', (connection, req) => {

  //get id, name and photo of the user from the cookie
  const cookies = req.headers.cookie;
  if (cookies) {
    const tokenString = cookies.split(';').find((str) => str.startsWith('token='));
    if (tokenString) {
      const token = tokenString.split('=')[1]
      if (token) {
        jwt.verify(token, jwtSecret, {}, (err, userData) => {
          if (err) throw err;
          const { userId, name, photo } = userData;
          connection.userId = userId;
          connection.name = name;
          connection.photo = photo;
        })
      }
    }
  }

  connection.on('message', async (message) => {
    const { recipient, text } = JSON.parse(message.toString());
    if (recipient && text) {
      const messageDoc = await Message.create({
        sender: connection.userId,
        recipient, text
      });
      [...wsserver.clients].filter(client => client.userId === recipient).forEach(client => client.send(JSON.stringify({ text, recipient, sender: connection.userId, id: messageDoc._id })))
    }
  });

  //get all the user that are online 
  [...wsserver.clients].forEach((client) => {
    client.send(JSON.stringify({
      online: [...wsserver.clients].map(c => ({ userId: c.userId, name: c.name, photo: c.photo }))
    }
    ))
  })


});