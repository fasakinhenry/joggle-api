const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema(
  {
    email: {
      type: String,
      required: true,
      unique: true,
      trim: true,
      lowercase: true,
    },
    username: {
      type: String,
      required: true,
      trim: true,
    },
    password: {
      type: String,
      required: function () {
        return (
          !this.socialProfiles.google &&
          !this.socialProfiles.facebook &&
          !this.socialProfiles.github &&
          !this.socialProfiles.linkedin
        );
      },
    },
    isVerified: {
      type: Boolean,
      default: false,
    },
    verificationToken: {
      type: String,
    },
    resetPasswordToken: {
      type: String,
    },
    resetPasswordExpires: {
      type: Date,
    },
    refreshToken: {
      type: String,
    },
    oauthProviders: [
      {
        provider: String,
        providerId: String,
        accessToken: String,
        refreshToken: String,
      },
    ],
    courses: [
      {
        courseId: { type: mongoose.Schema.Types.ObjectId, ref: 'Course' },
        progress: Number,
        tasks: [{ taskId: mongoose.Schema.Types.ObjectId, completed: Boolean }],
      },
    ],
    socialProfiles: {
      google: String,
      facebook: String,
      github: String,
      linkedin: String,
    },
    community: {
      friends: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
      followers: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
      groupsJoined: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Group' }],
      eventsAttended: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Event' }],
    },
    badges: [
      {
        type: String,
        enum: [
          'Nova Explorer',
          'Stellar Pioneer',
          'Galactic Scholar',
          'Cosmic Voyager',
        ],
      },
    ],
    languages: [
      {
        type: String,
      },
    ],
    activity: [
      {
        type: { type: String },
        timestamp: { type: Date, default: Date.now },
      },
    ],
  },
  { timestamps: true }
);

// Indexes for performance
userSchema.index({ email: 1 });
userSchema.index({ verificationToken: 1 });
userSchema.index({ resetPasswordToken: 1 });

// Hash password before saving
userSchema.pre('save', async function (next) {
  if (this.isModified('password') && this.password) {
    this.password = await bcrypt.hash(this.password, 10);
  }
  next();
});

// Method to compare passwords
userSchema.methods.comparePassword = async function (candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

userSchema.methods.generateVerificationToken = function () {
  this.verificationToken = crypto.randomBytes(32).toString('hex');
  return this.verificationToken;
};

module.exports = mongoose.model('User', userSchema);
