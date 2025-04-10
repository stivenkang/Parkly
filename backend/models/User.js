const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const Schema = mongoose.Schema;

const userSchema = new Schema(
	{
		firstName: {
			type: String,
			required: true,
		},
		lastName: {
			type: String,
			required: true
		},
		email: {
			type: String,
			required: true,
			unique: true,
		},
		hashedPassword: {
			type: String,
			required: true,
		},
		phoneNumber: {
			type: Number,
			required: true
		}
		// profileImageUrl: {
		// 	type: String,
		// 	required: true
		// }
	},
	{
		timestamps: true,
	}
);

userSchema.pre("save", async function (next) {
	if (this.isModified("hashedPassword")) {
		try {
			const salt = await bcrypt.genSalt(10);
			this.hashedPassword = await bcrypt.hash(this.hashedPassword, salt);
		} catch (err) {
			return next(err);
		}
	}
	next();
});

userSchema.methods.comparePassword = async function (password) {
	return bcrypt.compare(password, this.hashedPassword);
};

module.exports = mongoose.model("User", userSchema);
