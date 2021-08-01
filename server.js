const express = require('express');
const path = require ('path');
const mongoose = require('mongoose');
const User = require('./model/user');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const JWT_SECRET = '42KLrandomstring';

mongoose.connect('mongodb://localhost:27017/login-app-db', {
	useNewUrlParser: true,
	useUnifiedTopology: true,
	useCreateIndex: true
})

const app = express();
app.use('/', express.static(path.join(__dirname, 'register-login')));
app.use(express.json());

app.post('/api/change-password', async (req, res) => {
	const { token, newpassword: plainTextPassword} = req.body;

	if(!plainTextPassword || typeof plainTextPassword !== 'string') {
		return res.json({ status: 'error', error: 'Invalid password' });
	}

	if(plainTextPassword.length < 8){
		return res.json({ status: 'error', error: 'Password needs to be 8 characters minimum' });
	}

	try {
		const user = jwt.verify(token, JWT_SECRET);
		const _id = user.id;
		const password = await bcrypt.hash(plainTextPassword, 10);
		await User.updateOne({ _id }, {
			$set: { password }
		})
		res.json({ status: 'ok' });
	} catch(error) {
		res.json({ status: 'error', error: 'Hehe' });
	}
})

app.post('/api/login', async (req, res) => {
	const { username, password } = req.body;
	const user = await User.findOne({ username }).lean();

	if(!user) {
		return res.json({ status: 'error', error: 'Invalid username/password'});
	}
	if(await bcrypt.compare(password, user.password)) {
		const token = jwt.sign({
			id: user._id, 
			username: user.username
		}, JWT_SECRET);
		return res.json({ status: 'ok', data: token});
	}
	res.json({ status: 'error' , error: 'Invalid username/password' });
})

app.post('/api/register', async (req, res) => {
	const { username, password: plainTextPassword } = req.body;

	//Checks if username/password was entered and is of type string
	if(!username || typeof username !== 'string') {
		return res.json({ status: 'error', error: 'Invalid username' });
	}
	if(!plainTextPassword || typeof plainTextPassword !== 'string') {
		return res.json({ status: 'error', error: 'Invalid password' });
	}

	if(plainTextPassword.length < 8){
		return res.json({ status: 'error', error: 'Password needs to be 8 characters minimum' });
	}

	const password = await bcrypt.hash(plainTextPassword, 10);

	try {
		const response = await User.create({
			username,
			password
		});
		console.log('User created successfully' + response);
	} catch(error) {
		if (error.code === 11000) {
			//Duplicate user ID
			return res.json({ status: 'error', error: 'Username already taken' });
		}
		throw error;
	}
	res.json({ status: 'ok' });
})

app.listen(3000, () => {
	console.log('Server up at 3000');
})