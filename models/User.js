import mongoose from 'mongoose';

const userSchema = new mongoose.Schema(
  {
    email: { type: String, required: true, unique: true, lowercase: true },
    password: { type: String, required: true },
    walletAddress: { type: String, default: '', unique: true, sparse: true },
    hasVoted: { type: Boolean, default: false },         // for active election shortcut
    isAdmin: { type: Boolean, default: false },
    isActive: { type: Boolean, default: true },
    // MFA
    mfaEnabled: { type: Boolean, default: false },
    mfaSecret: { type: String, default: '' }
  },
  { timestamps: true }
);

export default mongoose.model('User', userSchema);
