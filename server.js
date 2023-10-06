const express = require('express');
const fs = require('fs');
const https = require('https');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const path = require('path');
require('dotenv').config();

const admin = require('firebase-admin');

const serviceAccount = require('./images-push-message-example-firebase-adminsdk-w1hl3-0a48a1e988.json');

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});

const topic = 'images_completed';


const app = express();

let refreshTokenStore = [];

const users = [
    {
        username: process.env.JWT_USERNAME,
        password: bcrypt.hashSync(process.env.JWT_PASSWORD, 10)  // en bcrypt-hashet version af adgangskoden
    }
];


app.use(express.json()); // For at kunne læse JSON data fra POST requests

app.use((req, res, next) => {
    const cert = req.socket.getPeerCertificate();
    if (req.client.authorized) {
      //console.log('Authorized');
      next();
    } else if (cert) {
      console.log('Certificate from peer:', cert);
      res.writeHead(401);
      res.end('unauthorized');
    } else {
      res.writeHead(400);
      res.end('Fatal user error');

    }
});

//login endpoint
app.post('/login', async (req, res) => {
    console.log('login called... ')
    const username = req.body.username;
    const password = req.body.password;
    
    const user = users.find(user => user.username === username);

    if (user == null || password == null) {
        return res.status(400).send('Username and password must be supplied!');
    }

    try {
        if (await bcrypt.compare(password, user.password)) {
            const userForToken = { name: user.username };

            const accessToken = generateAccessToken(userForToken);
            const refreshToken = jwt.sign(userForToken, process.env.JWT_REFRESH_SECRET, {expiresIn: '1h'});

            refreshTokenStore.push(refreshToken);
            res.json({ accessToken, refreshToken });
        } else {
            res.status(401).send('Username or Password is incorrect');
        }
    } catch {
        res.status(500).send();
    }
});


// En rute til at forny access tokens
app.post('/token/refresh', (req, res) => {

    console.log('token/refresh called... ')
    const refreshToken = req.body.token;

    if (!refreshToken) return res.sendStatus(401);
    if (!refreshTokenStore.includes(refreshToken)) return res.sendStatus(403);

    jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);

        const newAccessToken = generateAccessToken({ name: user.name });
        
        // Genererer en ny refresh-token
        const newRefreshToken = jwt.sign({ name: user.name }, process.env.JWT_REFRESH_SECRET, {expiresIn: '1h'});
        
        // Opdaterer refreshTokenStore (Du vil muligvis gøre dette mere sofistikeret i en rigtig applikation)
        refreshTokenStore = refreshTokenStore.filter(token => token !== refreshToken);
        refreshTokenStore.push(newRefreshToken);

        res.json({ accessToken: newAccessToken, refreshToken: newRefreshToken });
    });
});

app.post('/validate-token', authenticateToken, (req, res) => {
    console.log('validate-token called... ')
    // Hvis middleware 'authenticateToken' passerer, er token gyldig
    res.status(200).json({ valid: true, user: req.user });
});

app.get('/ping', (req,res) => {
    res.status(200).send('This is the only endpoint besides login accepted without token registration!');
})

// Vores /images endpoint, beskyttet af JWT
app.get('/images', authenticateToken, (req, res) => {
    console.log('images called... ')
    // Antager at billederne ligger i en "images" mappe i projektets rod
    const imagesDirectory = path.join(__dirname, 'images');
    fs.readdir(imagesDirectory, (err, files) => {
        if (err) {
            res.status(500).json({ error: "Failed to read directory" });
            return;
        }

        // Vælg 3 tilfældige billeder
        const randomFiles = [];
        while (randomFiles.length < 3 && files.length > 0) {
            const randomIndex = Math.floor(Math.random() * files.length);
            const removedFile = files.splice(randomIndex, 1)[0]; // Fjerner og henter et enkelt element
            randomFiles.push(removedFile);
        }
        // Konverter disse billeder til base64
        const base64Images = randomFiles.map(file => {
            const filePath = path.join(imagesDirectory, file);
            console.log('file extension: %s', path.extname(filePath).split('.')[1])
            const fileData = fs.readFileSync(filePath);
            return {
                image: Buffer.from(fileData).toString('base64')
            };
        });

        const fileExtensions = randomFiles.map(file => {
            const filePath = path.join(imagesDirectory, file);
            return {
                extension: path.extname(filePath).split('.')[1]
            };
        });
        
        console.log(JSON.stringify(fileExtensions));

        // Send responsen tilbage som en liste af base64-kodede strenge
        res.status(200).json({ images: base64Images });

        //  FCM messaging

        const message = {
            notification: {
                title: 'Image Process',
                body: 'Images have been succesfully processed',
            }, 
            data: {
                extensions: JSON.stringify(fileExtensions)
            },
            topic: topic,
            
            android:{
                priority:'high'
              },
              apns:{
                headers:{
                  "apns-priority": '5'
                }
              },
              webpush: {
                headers: {
                  Urgency: 'high'
                }
              }
        };    

        admin.messaging().send(message)
            .then((response) => {
                console.log('Successfully sent message:', response);
            })
            .catch((error) => {
                console.log('Error sending message:', error);
            });
            
    });
});

function generateAccessToken(user) {
    return jwt.sign(user, process.env.JWT_SECRET_KEY, { expiresIn: '15m' });
}

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.sendStatus(401);

    jwt.verify(token, process.env.JWT_SECRET_KEY, (err, user) => {
        if (err) return res.sendStatus(403);

        req.user = user;
        next();
    });
}

//console.log(process.env.KEY_PATH);  // Skal udskrive stien til din key fil


const httpsOptions = {
    key: fs.readFileSync(process.env.JWT_KEY_PATH),
    cert: fs.readFileSync(process.env.JWT_CERT_PATH),
    ca: [ fs.readFileSync(process.env.JWT_CA_ROOT) ],  
    requestCert: true,
    rejectUnauthorized: false,
};



const server = https.createServer(httpsOptions, app);

server.on('secureConnection', (tlsSocket) => {
  console.log('secureConnection event:', tlsSocket.getCipher());
  if (!tlsSocket.authorized) {
    console.error('secureConnection', tlsSocket.authorizationError);
  }
});

server.listen(process.env.JWT_PORT, () => {
  console.log(`Server running at https://localhost:${process.env.JWT_PORT}`);
});


