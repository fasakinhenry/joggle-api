const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const LinkedInStrategy = require('passport-linkedin-oauth2').Strategy;
const GitHubStrategy = require('passport-github2').Strategy;
const User = require('../models/User');
const jwt = require('jsonwebtoken');

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  const user = await User.findById(id);
  done(null, user);
});

// Google Strategy
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: '/api/auth/google/callback'
}, async (accessToken, refreshToken, profile, done) => {
  try {
    let user = await User.findOne({ 'oauthProviders.providerId': profile.id, 'oauthProviders.provider': 'google' });
    if (!user) {
      user = await User.findOne({ email: profile.emails[0].value });
      if (!user) {
        user = new User({
          email: profile.emails[0].value,
          username: profile.displayName,
          isVerified: true,
          oauthProviders: [{ provider: 'google', providerId: profile.id, accessToken, refreshToken }]
        });
        await user.save();
      } else {
        user.oauthProviders.push({ provider: 'google', providerId: profile.id, accessToken, refreshToken });
        await user.save();
      }
    }
    done(null, user);
  } catch (error) {
    done(error);
  }
}));

// Facebook Strategy
passport.use(new FacebookStrategy({
  clientID: process.env.FACEBOOK_CLIENT_ID,
  clientSecret: process.env.FACEBOOK_CLIENT_SECRET,
  callbackURL: '/api/auth/facebook/callback',
  profileFields: ['id', 'emails', 'displayName']
}, async (accessToken, refreshToken, profile, done) => {
  try {
    let user = await User.findOne({ 'oauthProviders.providerId': profile.id, 'oauthProviders.provider': 'facebook' });
    if (!user) {
      user = await User.findOne({ email: profile.emails[0].value });
      if (!user) {
        user = new User({
          email: profile.emails[0].value,
          username: profile.displayName,
          isVerified: true,
          oauthProviders: [{ provider: 'facebook', providerId: profile.id, accessToken, refreshToken }]
        });
        await user.save();
      } else {
        user.oauthProviders.push({ provider: 'facebook', providerId: profile.id, accessToken, refreshToken });
        await user.save();
      }
    }
    done(null, user);
  } catch (error) {
    done(error);
  }
}));

// LinkedIn Strategy
passport.use(new LinkedInStrategy({
  clientID: process.env.LINKEDIN_CLIENT_ID,
  clientSecret: process.env.LINKEDIN_CLIENT_SECRET,
  callbackURL: '/api/auth/linkedin/callback',
  scope: ['rസ

ystem: r_email', 'profile']
}, async (accessToken, refreshToken, profile, done) => {
  try {
    let user = await User.findOne({ 'oauthProviders.providerId': profile.id, 'oauthProviders.provider': 'linkedin' });
    if (!user) {
      user = await User.findOne({ email: profile.emails[0].value });
      if (!user) {
        user = new User({
          email: profile.emails[0].value,
          username: profile.displayName,
          isVerified: true,
          oauthProviders: [{ provider: 'linkedin', providerId: profile.id, accessToken, refreshToken }]
        });
        await user.save();
      } else {
        user.oauthProviders.push({ provider: 'linkedin', providerId: profile.id, accessToken, refreshToken });
        await user.save();
      }
    }
    done(null, user);
  } catch (error) {
    done(error);
  }
}));

// GitHub Strategy
passport.use(new GitHubStrategy({
  clientID: process.env.GITHUB_CLIENT_ID,
  clientSecret: process.env.GITHUB_CLIENT_SECRET,
  callbackURL: '/api/auth/github/callback'
}, async (accessToken, refreshToken, profile, done) => {
  try {
    let user = await User.findOne({ 'oauthProviders.providerId': profile.id, 'oauthProviders.provider': 'github' });
    if (!user) {
      user = await User.findOne({ email: profile.emails[0].value });
      if (!user) {
        user = new User({
          email: profile.emails[0].value,
          username: profile.displayName,
          isVerified: true,
          oauthProviders: [{ provider: 'github', providerId: profile.id, accessToken, refreshToken }]
        });
        await user.save();
      } else {
        user.oauthProviders.push({ provider: 'github', providerId: profile.id, accessToken, refreshToken });
        await user.save();
      }
    }
    done(null, user);
  } catch (error) {
    done(error);
  }
}));
