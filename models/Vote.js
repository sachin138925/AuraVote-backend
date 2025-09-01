import mongoose from 'mongoose';

const voteSchema = new mongoose.Schema(
  {
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    election: { type: mongoose.Schema.Types.ObjectId, ref: 'Election', required: true, index: true },
    candidateName: { type: String, required: true },
    txHash: { type: String, default: '' },     // on-chain tx hash
    network: { type: String, default: '' }
  },
  { timestamps: true }
);

voteSchema.index({ user: 1, election: 1 }, { unique: true });

export default mongoose.model('Vote', voteSchema);
