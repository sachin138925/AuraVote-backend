// server/server.js
const dotenv = require('dotenv');
dotenv.config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { ethers, Interface } = require('ethers');
const axios = require('axios');
const crypto = require('crypto');
const nodemailer = require('nodemailer');

const app = express();
app.use(express.json());
app.use(helmet());
app.use(cors({ origin: process.env.CLIENT_ORIGIN || '*' }));
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 200 }));

// ---------- ENV ----------
const PORT = process.env.PORT || 4000;
const MONGO_URI = process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/hybridvote';
const JWT_SECRET = process.env.JWT_SECRET || 'change_this_in_prod';
const ADMIN_INVITE_CODE = process.env.ADMIN_INVITE_CODE || 'ADMIN2025';
const RECAPTCHA_SECRET = process.env.RECAPTCHA_SECRET || '';
const RPC_URL = process.env.RPC_URL_BSC_TESTNET || 'https://data-seed-prebsc-1-s1.binance.org:8545/';
const CONTRACT_ADDRESS = process.env.CONTRACT_ADDRESS || '';
const DEPLOYER_PRIVATE_KEY = process.env.DEPLOYER_PRIVATE_KEY || '';
const EMAIL_FROM = process.env.EMAIL_FROM || 'no-reply@hybridvote.example';

// ---------- MONGOOSE MODELS ----------
mongoose.set('strictQuery', false);

const userSchema = new mongoose.Schema({
  email: { type: String, index: true, unique: true, sparse: true },
  passwordHash: String,
  name: String,
  emailVerified: { type: Boolean, default: false },
  role: { type: String, enum: ['user','admin'], default: 'user' },
  walletAddress: { type: String, default: null, index: true, sparse: true },
  hasVotedOn: { type: Map, of: Boolean, default: {} },
  walletNonce: { type: String, default: null },
  emailVerificationToken: { type: String, default: null },
  emailVerificationExpires: { type: Date, default: null }
}, { timestamps: true });

const walletNonceSchema = new mongoose.Schema({
  address: { type: String, index: true },
  nonce: String,
  expiresAt: Date,
}, { timestamps: true });

const blacklistedTokenSchema = new mongoose.Schema({
  token: { type: String, index: true },
  expiresAt: Date,
}, { timestamps: true });

const candidateSub = new mongoose.Schema({
  onChainId: String,
  name: String,
  party: String,
  votes: { type: Number, default: 0 }
}, { _id: false });

const electionSchema = new mongoose.Schema({
  title: String,
  description: String,
  onChainId: String,
  startAt: Date,
  endAt: Date,
  closed: { type: Boolean, default: false },
  candidates: [candidateSub],
  votesTotal: { type: Number, default: 0 },
}, { timestamps: true });

const User = mongoose.model('User', userSchema);
const WalletNonce = mongoose.model('WalletNonce', walletNonceSchema);
const BlacklistedToken = mongoose.model('BlacklistedToken', blacklistedTokenSchema);
const Election = mongoose.model('Election', electionSchema);

// ---------- EMAIL (nodemailer) ----------
const smtpTransport = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT || 587),
  secure: false,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS
  }
});

async function sendVerificationEmail(email, token) {
  const url = `${process.env.CLIENT_ORIGIN || 'http://localhost:3000'}/verify-email?token=${token}`;
  const info = await smtpTransport.sendMail({
    from: EMAIL_FROM,
    to: email,
    subject: 'Verify your email for HybridVote',
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2 style="color: #4f46e5;">Verify Your Email</h2>
        <p>Hi there,</p>
        <p>Please verify your email address by clicking the button below:</p>
        <div style="text-align: center; margin: 30px 0;">
          <a href="${url}" style="background-color: #4f46e5; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; font-weight: bold;">Verify Email</a>
        </div>
        <p>If you didn't create an account with HybridVote, you can safely ignore this email.</p>
        <p>This link expires in 24 hours.</p>
        <p>Thanks,<br>The HybridVote Team</p>
      </div>
    `
  });
  console.log('Sent verification email:', info.messageId);
}

// ---------- CONTRACT SETUP ----------
const contractABI = [
  "function createElection(string,string,uint256,uint256) returns (uint256)",
  "function addCandidate(uint256,string,string)",
  "function toggleCloseElection(uint256,bool)",
  "function vote(uint256,uint256)",
  "function getElectionBasic(uint256) view returns (uint256,string,string,uint256,uint256,bool,uint256)",
  "function getCandidate(uint256,uint256) view returns (uint256,string,string,uint256)",
  "event ElectionCreated(uint256 indexed electionId,string title,uint256 startAt,uint256 endAt)",
  "event CandidateAdded(uint256 indexed electionId,uint256 indexed candidateId,string name,string party)",
  "event Voted(uint256 indexed electionId,uint256 indexed candidateId,address indexed voter)",
  "event ElectionClosed(uint256 indexed electionId)"
];

const provider = new ethers.JsonRpcProvider(RPC_URL);
const wallet = DEPLOYER_PRIVATE_KEY ? new ethers.Wallet(DEPLOYER_PRIVATE_KEY, provider) : null;
const contract = (CONTRACT_ADDRESS && wallet) ? new ethers.Contract(CONTRACT_ADDRESS, contractABI, wallet) : null;
const contractRead = CONTRACT_ADDRESS ? new ethers.Contract(CONTRACT_ADDRESS, contractABI, provider) : null;

// ---------- HELPERS ----------
function signToken(user) {
  return jwt.sign({ id: user._id.toString(), role: user.role, email: user.email || null }, JWT_SECRET, { expiresIn: '7d' });
}

async function authMiddleware(req, res, next) {
  try {
    const auth = req.headers.authorization;
    if (!auth) return res.status(401).json({ msg: 'No token provided' });
    const token = auth.replace('Bearer ', '');
    const black = await BlacklistedToken.findOne({ token });
    if (black) return res.status(401).json({ msg: 'Token revoked' });
    const payload = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(payload.id);
    if (!user) return res.status(401).json({ msg: 'Invalid token' });
    req.user = user;
    req.token = token;
    next();
  } catch (err) {
    return res.status(401).json({ msg: 'Unauthorized', error: err.message });
  }
}

function adminOnly(req, res, next) {
  if (!req.user || req.user.role !== 'admin') return res.status(403).json({ msg: 'Admin access required' });
  next();
}

// ---------- ROUTES ----------
app.get('/api/health', (req,res) => res.json({ ok: true, timestamp: new Date() }));

app.post('/api/auth/register', async (req,res) => {
  try {
    const { name, email, password, role, inviteCode, recaptchaToken } = req.body;
    if (!name || !email || !password) return res.status(400).json({ msg: 'Name, email, and password are required' });
    
    if (process.env.RECAPTCHA_SECRET) {
      if (!recaptchaToken) return res.status(400).json({ msg: 'reCAPTCHA token required' });
      const verifyURL = `https://www.google.com/recaptcha/api/siteverify?secret=${encodeURIComponent(RECAPTCHA_SECRET)}&response=${encodeURIComponent(recaptchaToken)}`;
      const captchaRes = await axios.post(verifyURL).then(r => r.data).catch(() => null);
      if (!captchaRes || !captchaRes.success) return res.status(400).json({ msg: 'reCAPTCHA verification failed' });
    }
    
    if (role === 'admin' && inviteCode !== ADMIN_INVITE_CODE) return res.status(403).json({ msg: 'Invalid admin invite code' });
    
    const exists = await User.findOne({ email });
    if (exists) return res.status(400).json({ msg: 'User with this email already exists' });
    
    const salt = await bcrypt.genSalt(10);
    const hash = await bcrypt.hash(password, salt);
    const emailVerificationToken = crypto.randomBytes(20).toString('hex');
    const emailVerificationExpires = new Date(Date.now() + 24 * 60 * 60 * 1000);
    
    const user = new User({ 
      name, 
      email, 
      passwordHash: hash, 
      role: role || 'user', 
      emailVerified: false, 
      emailVerificationToken, 
      emailVerificationExpires 
    });
    
    await user.save();
    sendVerificationEmail(email, emailVerificationToken).catch(err => console.error('Email sending error:', err));
    
    return res.json({ 
      msg: 'Registration successful. Please check your email to verify your account.' 
    });
  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).json({ msg: 'Server error during registration' });
  }
});

app.get('/api/auth/verify-email', async (req,res) => {
  try {
    const token = req.query.token;
    if (!token) return res.status(400).json({ msg: 'Verification token is required' });
    
    const user = await User.findOne({ 
      emailVerificationToken: token, 
      emailVerificationExpires: { $gt: new Date() } 
    });
    
    if (!user) return res.status(400).json({ msg: 'Invalid or expired verification token' });
    
    user.emailVerified = true;
    user.emailVerificationToken = undefined;
    user.emailVerificationExpires = undefined;
    await user.save();
    
    return res.json({ ok: true, msg: 'Email verified successfully' });
  } catch (err) {
    console.error('Email verification error:', err);
    res.status(500).json({ msg: 'Server error during email verification' });
  }
});

app.post('/api/auth/login', async (req,res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ msg: 'Email and password are required' });
    
    const user = await User.findOne({ email });
    if (!user || !user.passwordHash) return res.status(400).json({ msg: 'Invalid credentials' });
    
    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(400).json({ msg: 'Invalid credentials' });
    
    if (!user.emailVerified) return res.status(403).json({ msg: 'Please verify your email before logging in' });
    
    const token = signToken(user);
    const { _id, name, role, walletAddress } = user;
    
    res.json({ 
      token, 
      user: { id: _id, email: user.email, name, role, walletAddress } 
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ msg: 'Server error during login' });
  }
});

app.post('/api/auth/logout', authMiddleware, async (req,res) => {
  try {
    const token = req.token;
    const decoded = jwt.decode(token);
    const exp = decoded && decoded.exp ? new Date(decoded.exp * 1000) : new Date(Date.now() + 7*24*60*60*1000);
    await BlacklistedToken.create({ token, expiresAt: exp });
    return res.json({ ok: true, msg: 'Logged out successfully' });
  } catch (err) {
    console.error('Logout error:', err);
    res.status(500).json({ msg: 'Server error during logout' });
  }
});

app.get('/api/auth/me', authMiddleware, (req, res) => {
    const { _id, name, email, role, walletAddress, hasVotedOn, emailVerified } = req.user;
    res.json({ id: _id, name, email, role, walletAddress, hasVotedOn, emailVerified });
});

app.post('/api/auth/challenge', authMiddleware, async (req,res) => {
  try {
    const nonce = crypto.randomBytes(16).toString('hex');
    req.user.walletNonce = nonce;
    await req.user.save();
    const message = `Link your wallet to HybridVote by signing this message. Nonce: ${nonce}`;
    return res.json({ message });
  } catch (err) {
    console.error('Challenge generation error:', err); 
    res.status(500).json({ msg: 'Server error generating challenge' });
  }
});

app.post('/api/auth/verify-link', authMiddleware, async (req,res) => {
  try {
    const { signature } = req.body;
    if (!signature) return res.status(400).json({ msg: 'Signature is required' });
    
    const nonce = req.user.walletNonce;
    if (!nonce) return res.status(400).json({ msg: 'No challenge issued. Please request a challenge first.' });
    
    const message = `Link your wallet to HybridVote by signing this message. Nonce: ${nonce}`;
    let recovered;
    try { 
      recovered = ethers.verifyMessage(message, signature); 
    } catch (e) { 
      return res.status(400).json({ msg: 'Invalid signature format.' }); 
    }
    
    // Check if another user already has this wallet linked
    const existingUser = await User.findOne({ walletAddress: recovered.toLowerCase() });
    if (existingUser && existingUser._id.toString() !== req.user._id.toString()) {
        return res.status(400).json({ msg: 'This wallet is already linked to another account.' });
    }
    
    req.user.walletAddress = recovered.toLowerCase();
    req.user.walletNonce = undefined;
    await req.user.save();
    
    return res.json({ 
      ok: true, 
      walletAddress: req.user.walletAddress,
      msg: 'Wallet linked successfully'
    });
  } catch (err) { 
    console.error('Wallet linking error:', err); 
    res.status(500).json({ msg: 'Server error linking wallet' }); 
  }
});

app.get('/api/elections', async (req,res) => {
  try {
    const list = await Election.find().sort({ createdAt: -1 }).lean();
    res.json(list);
  } catch (err) {
    console.error('Error fetching elections:', err);
    res.status(500).json({ msg: 'Error fetching elections' });
  }
});

app.get('/api/elections/active', async (req,res) => {
  try {
    const el = await Election.findOne({ 
      closed: false, 
      startAt: { $lte: new Date() }, 
      $or: [{ endAt: null }, { endAt: { $gte: new Date() }}]
    }).sort({ createdAt: -1 }).lean();
    
    if (!el) return res.status(404).json({ msg: 'No active election found' });
    res.json(el);
  } catch (err) {
    console.error('Error fetching active election:', err);
    res.status(500).json({ msg: 'Error fetching active election' });
  }
});

app.get('/api/elections/results', async (req, res) => {
    try {
        const el = await Election.findOne({ 
          $or: [{ closed: true }, { endAt: { $ne: null, $lt: new Date() }}]
        }).sort({ createdAt: -1 }).lean();
        
        if (!el) return res.status(404).json({ msg: 'No completed election results found.' });
        res.json({ title: el.title, results: el.candidates });
    } catch(err) {
        console.error('Error fetching election results:', err);
        res.status(500).json({ msg: 'Error fetching election results' });
    }
});

app.post('/api/admin/elections', authMiddleware, adminOnly, async (req,res) => {
  try {
    if (!contract) return res.status(500).json({ msg: 'Contract not configured on server.' });
    
    const { title, description, startAt, endAt } = req.body;
    const s = startAt ? Math.floor(new Date(startAt).getTime()/1000) : 0;
    const e = endAt ? Math.floor(new Date(endAt).getTime()/1000) : 0;
    
    const tx = await contract.createElection(title || 'Untitled Election', description || '', s, e);
    const receipt = await tx.wait();
    
    const iface = new Interface(contractABI);
    let onChainId = null;
    
    for (const log of receipt.logs) {
      try {
        const parsed = iface.parseLog(log);
        if (parsed && parsed.name === 'ElectionCreated') { 
          onChainId = parsed.args.electionId.toString(); 
          break; 
        }
      } catch {}
    }
    
    if (!onChainId) throw new Error("Could not find ElectionCreated event in transaction logs.");
    
    const doc = new Election({ 
      title, 
      description, 
      onChainId, 
      startAt: startAt ? new Date(startAt) : null, 
      endAt: endAt ? new Date(endAt) : null, 
      closed: false, 
      candidates: [] 
    });
    
    await doc.save();
    res.json({ 
      ok: true, 
      txHash: receipt.hash, 
      onChainId,
      msg: 'Election created successfully'
    });
  } catch (err) { 
    console.error('Error creating election:', err); 
    res.status(500).json({ 
      msg: 'Failed to create election', 
      error: err.message 
    }); 
  }
});

app.post('/api/admin/elections/:onChainId/candidates', authMiddleware, adminOnly, async (req,res) => {
  try {
    const { onChainId } = req.params;
    const { name, party } = req.body;
    
    if (!contract) return res.status(500).json({ msg: 'Contract not configured' });
    if (!name) return res.status(400).json({ msg: 'Candidate name is required' });
    
    const tx = await contract.addCandidate(onChainId, name, party || '');
    const receipt = await tx.wait();
    
    res.json({ 
      ok: true, 
      txHash: receipt.hash,
      msg: 'Candidate added successfully'
    });
  } catch (err) { 
    console.error('Error adding candidate:', err); 
    res.status(500).json({ 
      msg: 'Failed to add candidate', 
      error: err.message 
    }); 
  }
});

app.post('/api/verify/vote', authMiddleware, async (req,res) => {
  try {
    const { txHash, electionId, candidateId } = req.body;
    if (!txHash) return res.status(400).json({ msg: 'Transaction hash is required' });
    
    const receipt = await provider.getTransactionReceipt(txHash);
    if (!receipt || receipt.status === 0) return res.status(400).json({ msg:'Transaction failed or not found' });
    
    const iface = new Interface(contractABI);
    const votedLog = receipt.logs.map(log => {
        try { return iface.parseLog(log); } catch { return null; }
    }).find(log => log && log.name === 'Voted');
    
    if (!votedLog) return res.status(400).json({ msg: 'No Voted event found in transaction' });
    
    const { electionId: evElectionId, candidateId: evCandidateId, voter: evVoter } = votedLog.args;
    if (evElectionId.toString() !== electionId.toString() || evCandidateId.toString() !== candidateId.toString()) {
        return res.status(400).json({ msg:'Event data does not match request' });
    }
    
    if (!req.user.walletAddress) return res.status(400).json({ msg:'User has no linked wallet' });
    if (req.user.walletAddress.toLowerCase() !== evVoter.toLowerCase()) {
        return res.status(400).json({ msg:'Vote was cast by a different wallet' });
    }
    
    req.user.hasVotedOn.set(electionId.toString(), true);
    await User.findByIdAndUpdate(req.user._id, { $set: { [`hasVotedOn.${electionId}`]: true } });
    
    await Election.updateOne(
        { onChainId: electionId.toString(), 'candidates.onChainId': candidateId.toString() },
        { $inc: { votesTotal: 1, 'candidates.$.votes': 1 } }
    );
    
    res.json({ 
      ok: true,
      msg: 'Vote verified and recorded successfully'
    });
  } catch (err) { 
    console.error('Vote verification error:', err); 
    res.status(500).json({ 
      msg: 'Vote verification failed', 
      error: err.message 
    }); 
  }
});

// ---------- EVENT LISTENER ----------
if (contractRead) {
  console.log('Starting contract event listeners...');
  contractRead.on('CandidateAdded', async (electionId, candidateId, name, party) => {
    try {
      const onChainId = electionId.toString();
      const candidateChainId = candidateId.toString();
      const el = await Election.findOne({ onChainId });
      
      if (el && !el.candidates.some(c => c.onChainId === candidateChainId)) {
        el.candidates.push({ 
          onChainId: candidateChainId, 
          name: name.toString(), 
          party: party.toString(), 
          votes: 0 
        });
        await el.save();
        console.log(`[EVENT] Synced CandidateAdded: Election ${onChainId}, Candidate ${candidateChainId}`);
      }
    } catch (err) { 
      console.error('[EVENT] CandidateAdded error:', err); 
    }
  });
}

// ---------- START ----------
mongoose.connect(MONGO_URI).then(() => {
  console.log('MongoDB connected successfully');
  app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
}).catch(err => {
  console.error('MongoDB connection error:', err);
  process.exit(1);
});