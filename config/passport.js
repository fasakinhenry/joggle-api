const passport = require('passport');
const FacebookStrategy = require('passport-facebook').Strategy;
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const GitHubStrategy = require('passport-github2').Strategy;
const LinkedInStrategy = require('passport-linkedin-oauth2').Strategy;
const User = require('../models/user'); // Adjust path to your User model
require('dotenv').config();

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err, null);
  }
});

// Facebook Strategy
passport.use(
  new FacebookStrategy(
    {
      clientID: process.env.FACEBOOK_APP_ID,
      clientSecret: process.env.FACEBOOK_APP_SECRET,
      callbackURL: `${process.env.BACKEND_URL}/auth/facebook/callback`,
      profileFields: ['id', 'displayName', 'email'],
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        let user = await User.findOne({ 'facebook.id': profile.id });
        if (user) {
          return done(null, user);
        }
        user = new User({
          facebook: {
            id: profile.id,
            token: accessToken,
            name: profile.displayName,
            email: profile.emails ? profile.emails[0].value : null,
          },
          email: profile.emails ? profile.emails[0].value : null,
          name: profile.displayName,
          isVerified: true, // OAuth users are auto-verified
        });
        await user.save();
        done(null, user);
      } catch (err) {
        done(err, null);
      }
    }
  )
);

// Google Strategy
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: `${process.env.BACKEND_URL}/auth/google/callback`,
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        let user = await User.findOne({ 'google.id': profile.id });
        if (user) {
          return done(null, user);
        }
        user = new User({
          google: {
            id: profile.id,
            token: accessToken,
            name: profile.displayName,
            email: profile.emails[0].value,
          },
          email: profile.emails[0].value,
          name: profile.displayName,
          isVerified: true,
        });
        await user.save();
        done(null, user);
      } catch (err) {
        done(err, null);
      }
    }
  )
);

// GitHub Strategy
passport.use(
  new GitHubStrategy(
    {
      clientID: process.env.GITHUB_CLIENT_ID,
      clientSecret: process.env.GITHUB_CLIENT_SECRET,
      callbackURL: `${process.env.BACKEND_URL}/auth/github/callback`,
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        let user = await User.findOne({ 'github.id': profile.id });
        if (user) {
          return done(null, user);
        }
        user = new User({
          github: {
            id: profile.id,
            token: accessToken,
            name: profile.displayName || profile.username,
            email: profile.emails ? profile.emails[0].value : null,
          },
          email: profile.emails ? profile.emails[0].value : null,
          name: profile.displayName || profile.username,
          isVerified: true,
        });
        await user.save();
        done(null, user);
      } catch (err) {
        done(err, null);
      }
    }
  )
);

// LinkedIn Strategy
passport.use(
  new LinkedInStrategy(
    {
      clientID: process.env.LINKEDIN_CLIENT_ID,
      clientSecret: process.env.LINKEDIN_CLIENT_SECRET,
      callbackURL: `${process.env.BACKEND_URL}/auth/linkedin/callback`,
      scope: ['r_emailaddress', 'r_liteprofile'],
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        let user = await User.findOne({ 'linkedin.id': profile.id });
        if (user) {
          return done(null, user);
        }
        user = new User({
          linkedin: {
            id: profile.id,
            token: accessToken,
            name: profile.displayName,
            email: profile.emails ? profile.emails[0].value : null,
          },
          email: profile.emails ? profile.emails[0].value : null,
          name: profile.displayName,
          isVerified: true,
        });
        await user.save();
        done(null, user);
      } catch (err) {
        done(err, null);
      }
    }
  )
);

module.exports = passport;
