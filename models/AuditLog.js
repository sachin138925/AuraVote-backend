import mongoose from 'mongoose';

const auditLogSchema = new mongoose.Schema(
  {
    actor: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    action: { type: String, required: true }, // e.g., 'LOGIN', 'CAST_VOTE', 'CREATE_ELECTION'
    metadata: { type: Object, default: {} }
  },
  { timestamps: true }
);

export default mongoose.model('AuditLog', auditLogSchema);
