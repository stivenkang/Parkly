const passport = require("passport");
const LocalStrategy = require("passport-local");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");
const User = mongoose.model("User");
const { secretOrKey } = require("./keys");
const { Strategy: JwtStrategy, ExtractJwt } = require("passport-jwt");

passport.use(
	new LocalStrategy(
		{
			session: false,
			usernameField: "email",
			passwordField: "password",
		},
		async function (email, password, done) {
			// const user = await User.findOne({ email });
			// if (user) {
			// 	bcrypt.compare(
			// 		password,
			// 		user.hashedPassword,
			// 		(err, isMatch) => {
			// 			if (err || !isMatch) done(null, false);
			// 			else done(null, user);
			// 		}
			// 	);
			// } else done(null, false);

			try {
				const user = await User.findOne({email});
				if (user) {
					const isMatch = await user.comparePassword(password);
					if (isMatch) {
						return done(null, user);
					} else {
						return done(null, false, {message: "Invalid credentials"});
					}
				} else {
					return done(null, false, { message: "User not found"});
				}
			} catch (err) {
				return done(err);
			}
		}
	)
);

exports.loginUser = async function (user) {
	const userInfo = {
		_id: user._id,
		username: user.username,
		profileImageUrl: user.profileImageUrl,
		email: user.email,
	};
	const token = await jwt.sign(
		userInfo, // payload
		secretOrKey, // sign with secret key
		{ expiresIn: 3600 } // tell the key to expire in one hour
	);
	return {
		user: userInfo,
		token,
	};
};



const options = {};
options.jwtFromRequest = ExtractJwt.fromAuthHeaderAsBearerToken();
options.secretOrKey = secretOrKey;

passport.use(
	new JwtStrategy(options, async (jwtPayload, done) => {
		try {
			const user = await User.findById(jwtPayload._id);
			if (user) {
				// return the user to the frontend
				return done(null, user);
			}
			// return false since there is no user
			return done(null, false);
		} catch (err) {
			done(err);
		}
	})
);

exports.requireUser = passport.authenticate("jwt", { session: false });

exports.restoreUser = (req, res, next) => {
	return passport.authenticate(
		"jwt",
		{ session: false },
		function (err, user) {
			if (err) return next(err);
			if (user) req.user = user;
			next();
		}
	)(req, res, next);
};
