const express = require('express');
const path = require ('path');
const mongoose = require('mongoose');
const User = require('./model/user');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const ejs = require('ejs');
const cookieParser = require('cookie-parser');

const JWT_SECRET = '42KLrandomstring';

//Connects to MongoDB Atlas
mongoose.connect('mongodb+srv://openthygates:TestPassword13@cluster0.mnmph.mongodb.net/SunwayMallAssessment?retryWrites=true&w=majority', {
	useNewUrlParser: true,
	useUnifiedTopology: true,
	useCreateIndex: true
})

const app = express();
app.set('view engine', 'ejs');
app.use('/', express.static(path.join(__dirname, 'main')));
app.use(cookieParser());
app.use(express.json());

//Displays user's current message and username
app.get('/user/profile.html', async (req, res) => {
	//Uses JWT in cookies to verify user
	const token = req.cookies.token;
	try {
		const user = jwt.verify(token, JWT_SECRET);
		const _id = user.id;
		const userMessage = await User.findOne({ _id }, 'message');
		const userName = await User.findOne({ _id }, 'username');
		res.render('profile', {
			userMessage: userMessage.message,
			userName: userName.username
		});
	} catch(error) {
		//Redirects user to homepage if token cannot be authenticated
		res.redirect('/');
	}
})

//Updates user's message in the database, also uses JWT in cookies
app.post('/api/profile', async (req, res) => {
	const { message } = req.body;
	const token = req.cookies.token;

	try {
		const user = jwt.verify(token, JWT_SECRET);
		const _id = user.id;
		await User.updateOne({ _id }, {
			$set: { message }
		})
		res.json({ status: 'ok' });
	} catch(error) {
		//Redirects user to homepage if token cannot be authenticated
		res.redirect('/');
	}
})

//Logs in the user
app.post('/api/login', async (req, res) => {
	const { username, password } = req.body;
	const user = await User.findOne({ username }).lean();

	if(!user) {
		return res.json({ status: 'error', error: 'Invalid username/password'});
	}
	//Compares plaintextpassword to the hashed one stored in DB
	if(await bcrypt.compare(password, user.password)) {
		const token = jwt.sign({
			id: user._id, 
			username: user.username
		}, JWT_SECRET);
		//Storing JWT in a cookie for later verification, expires in 12 hours
		res.cookie('token', token, { expires: new Date(Date.now() + (12 * 3600000)), httpOnly: true });
		return res.json({ status: 'ok'});
	}
	res.json({ status: 'error' , error: 'Invalid username/password' });
})

//Logs out the user by clearing JWT in cookie
app.post('/api/logout', async (req, res) => {
	try {
		res.clearCookie('token');
		res.json({ status: 'ok' });
	} catch(error) {
		res.json({ status: 'error', error: 'Failed to logout'});
	}
})

//Creates a new entry in the DB with certain requirements
app.post('/api/register', async (req, res) => {
	const { firstName, lastName, email, username, password: plainTextPassword } = req.body;

	//Checks if username/password was entered and is of type string
	if(!username || typeof username !== 'string') {
		return res.json({ status: 'error', error: 'Invalid username' });
	}
	if(!plainTextPassword || typeof plainTextPassword !== 'string') {
		return res.json({ status: 'error', error: 'Invalid password' });
	}

	//Checks if password is at least 8 characters long
	if(plainTextPassword.length < 8){
		return res.json({ status: 'error', error: 'Password needs to be 8 characters minimum' });
	}

	//Hashes the password before storing it into mongoDB
	const password = await bcrypt.hash(plainTextPassword, 10);

	try {
		const response = await User.create({
			firstName,
			lastName,
			email,
			username,
			password
		});
	} catch(error) {
		if (error.code === 11000) {
			//Duplicate user ID
			return res.json({ status: 'error', error: 'Username already taken' });
		}
		throw error;
	}
	res.json({ status: 'ok' });
})

//Starts app on port 3000
app.listen(process.env.PORT || 3000, () => {
	console.log('Server up at 3000');
})