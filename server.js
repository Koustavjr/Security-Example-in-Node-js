const fs=require('fs');
const https=require('https');
const path=require('path');
const express=require('express');
const helmet = require('helmet');
const passport=require('passport');
const cookieSession=require('cookie-session');
const{Strategy}=require('passport-google-oauth20'); 


const PORT =3000;
const app = express();


require('dotenv').config();



const config={
    CLIENT_ID: process.env.CLIENT_ID,
    CLIENT_SECRET:process.env.CLIENT_SECRET,
    COOKIE_KEY_1:process.env.COOKIE_KEY_1,
    COOKIE_KEY_2:process.env.COOKIE_KEY_2,
}

app.use(helmet());
app.use(cookieSession({
    name:'session',
    maxAge:24*60*60*1000,
    keys:[config.COOKIE_KEY_1,config.COOKIE_KEY_2],
}));

app.use(passport.initialize());
app.use(passport.session()); // setting up req.user

const AUTH_OPTIONS={
    callbackURL:'/auth/google/callback',
    clientID:config.CLIENT_ID,
    clientSecret:config.CLIENT_SECRET
}

function verifyCallback(accessToken,refreshToken,profile,done)
{
    console.log('Google Profile',profile);
    done(null,profile);
}

passport.use(new Strategy(AUTH_OPTIONS,verifyCallback))
// to store session into a cookie
passport.serializeUser((user,done)=>{
    //done(null,user);
    //if we want only to store session id
    done(null,user.id);
});

// to read session from a cookie
passport.deserializeUser((obj,done)=>{
    done(null,obj)
});


function checkLoggedIn(req,res,next)
{
    console.log('User is:',req.user);
    //const isLoggedIn=true;
    const isLoggedIn=req.isAuthenticated() && req.user;
    if(!isLoggedIn)
    {
        return res.status(401).json({
            error:'You must log in!',
        });
    }
    next();
}



app.get('/auth/google',passport.authenticate('google',{
    scope:['email'],
}));

app.get('/auth/google/callback',passport.authenticate('google',{
    failureRedirect:'/failure',
    successRedirect:'/',
    //session:false,
    session:true,
}),(req,res)=>{
    console.log('Google called us back!');
});


app.get('/auth/logout',(req,res)=>{
    req.logOut();

    return res.redirect('/');

});

app.get('/secret',checkLoggedIn,(req,res)=>{
    res.send('Secuirty code!');
});

app.get('/failure',(req,res)=>{
    return res.send('Failed to log in!');
})
app.get('/',(req,res)=>{
    res.sendFile(path.join(__dirname,'public','index.html'));
});

https.createServer({
    key:fs.readFileSync('key.pem'),
    cert:fs.readFileSync('cert.pem'),
},app).listen(PORT,()=>{
    console.log(`Listening on Port ${PORT}...`);
});