const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
	firstName: { type: String, required: true },
	lastName: { type: String, required: true },
	email: { type: String, required: true, unique: true },
	username: { type: String, required: true, unique: true },
	password: { type: String, required: true }
}, { collection: 'users' }
)

const model = mongoose.model('UserSchema', UserSchema)

module.exports = model