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

const app = express();
app.set('trust proxy', 1);
app.use(express.json());
app.use(helmet());
app.use(cors({ origin: process.env.CLIENT_ORIGIN || '*' }));
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 200 }));

// ---------- ENV ----------
const PORT = process.env.PORT || 5000;
const MONGO_URI = process.env.MONGO_URI;
const JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_INVITE_CODE = process.env.ADMIN_INVITE_CODE;
const RECAPTCHA_SECRET = process.env.RECAPTCHA_SECRET;
const RPC_URL = process.env.RPC_URL_BSC_TESTNET;
const CONTRACT_ADDRESS = process.env.CONTRACT_ADDRESS;
const DEPLOYER_PRIVATE_KEY = process.env.DEPLOYER_PRIVATE_KEY;

// ---------- MONGOOSE MODELS ----------
mongoose.set('strictQuery', false);

const userSchema = new mongoose.Schema({
  email: { type: String, index: true, unique: true, sparse: true },
  passwordHash: String,
  name: String,
  role: { type: String, enum: ['user','admin'], default: 'user' },
  walletAddress: { type: String, default: null, index: true, sparse: true },
  hasVotedOn: { type: Map, of: Boolean, default: {} },
  walletNonce: { type: String, default: null },
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
const BlacklistedToken = mongoose.model('BlacklistedToken', blacklistedTokenSchema);
const Election = mongoose.model('Election', electionSchema);

// ---------- CONTRACT SETUP ----------
const contractABI =[
    {
      "inputs": [],
      "stateMutability": "nonpayable",
      "type": "constructor"
    },
    {
      "inputs": [
        {
          "internalType": "address",
          "name": "owner",
          "type": "address"
        }
      ],
      "name": "OwnableInvalidOwner",
      "type": "error"
    },
    {
      "inputs": [
        {
          "internalType": "address",
          "name": "account",
          "type": "address"
        }
      ],
      "name": "OwnableUnauthorizedAccount",
      "type": "error"
    },
    {
      "anonymous": false,
      "inputs": [
        {
          "indexed": true,
          "internalType": "uint256",
          "name": "electionId",
          "type": "uint256"
        },
        {
          "indexed": true,
          "internalType": "uint256",
          "name": "candidateId",
          "type": "uint256"
        },
        {
          "indexed": false,
          "internalType": "string",
          "name": "name",
          "type": "string"
        },
        {
          "indexed": false,
          "internalType": "string",
          "name": "party",
          "type": "string"
        }
      ],
      "name": "CandidateAdded",
      "type": "event"
    },
    {
      "anonymous": false,
      "inputs": [
        {
          "indexed": true,
          "internalType": "uint256",
          "name": "electionId",
          "type": "uint256"
        }
      ],
      "name": "ElectionClosed",
      "type": "event"
    },
    {
      "anonymous": false,
      "inputs": [
        {
          "indexed": true,
          "internalType": "uint256",
          "name": "electionId",
          "type": "uint256"
        },
        {
          "indexed": false,
          "internalType": "string",
          "name": "title",
          "type": "string"
        },
        {
          "indexed": false,
          "internalType": "uint256",
          "name": "startAt",
          "type": "uint256"
        },
        {
          "indexed": false,
          "internalType": "uint256",
          "name": "endAt",
          "type": "uint256"
        }
      ],
      "name": "ElectionCreated",
      "type": "event"
    },
    {
      "anonymous": false,
      "inputs": [
        {
          "indexed": true,
          "internalType": "address",
          "name": "previousOwner",
          "type": "address"
        },
        {
          "indexed": true,
          "internalType": "address",
          "name": "newOwner",
          "type": "address"
        }
      ],
      "name": "OwnershipTransferred",
      "type": "event"
    },
    {
      "anonymous": false,
      "inputs": [
        {
          "indexed": true,
          "internalType": "uint256",
          "name": "electionId",
          "type": "uint256"
        },
        {
          "indexed": true,
          "internalType": "uint256",
          "name": "candidateId",
          "type": "uint256"
        },
        {
          "indexed": true,
          "internalType": "address",
          "name": "voter",
          "type": "address"
        }
      ],
      "name": "Voted",
      "type": "event"
    },
    {
      "inputs": [
        {
          "internalType": "uint256",
          "name": "_electionId",
          "type": "uint256"
        },
        {
          "internalType": "string",
          "name": "_name",
          "type": "string"
        },
        {
          "internalType": "string",
          "name": "_party",
          "type": "string"
        }
      ],
      "name": "addCandidate",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "string",
          "name": "_title",
          "type": "string"
        },
        {
          "internalType": "string",
          "name": "_description",
          "type": "string"
        },
        {
          "internalType": "uint256",
          "name": "_startAt",
          "type": "uint256"
        },
        {
          "internalType": "uint256",
          "name": "_endAt",
          "type": "uint256"
        }
      ],
      "name": "createElection",
      "outputs": [
        {
          "internalType": "uint256",
          "name": "",
          "type": "uint256"
        }
      ],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "uint256",
          "name": "",
          "type": "uint256"
        }
      ],
      "name": "elections",
      "outputs": [
        {
          "internalType": "uint256",
          "name": "id",
          "type": "uint256"
        },
        {
          "internalType": "string",
          "name": "title",
          "type": "string"
        },
        {
          "internalType": "string",
          "name": "description",
          "type": "string"
        },
        {
          "internalType": "uint256",
          "name": "startAt",
          "type": "uint256"
        },
        {
          "internalType": "uint256",
          "name": "endAt",
          "type": "uint256"
        },
        {
          "internalType": "bool",
          "name": "closed",
          "type": "bool"
        },
        {
          "internalType": "uint256",
          "name": "nextCandidateId",
          "type": "uint256"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "uint256",
          "name": "_electionId",
          "type": "uint256"
        },
        {
          "internalType": "uint256",
          "name": "_candidateId",
          "type": "uint256"
        }
      ],
      "name": "getCandidate",
      "outputs": [
        {
          "internalType": "uint256",
          "name": "",
          "type": "uint256"
        },
        {
          "internalType": "string",
          "name": "",
          "type": "string"
        },
        {
          "internalType": "string",
          "name": "",
          "type": "string"
        },
        {
          "internalType": "uint256",
          "name": "",
          "type": "uint256"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "uint256",
          "name": "_electionId",
          "type": "uint256"
        }
      ],
      "name": "getElectionBasic",
      "outputs": [
        {
          "internalType": "uint256",
          "name": "",
          "type": "uint256"
        },
        {
          "internalType": "string",
          "name": "",
          "type": "string"
        },
        {
          "internalType": "string",
          "name": "",
          "type": "string"
        },
        {
          "internalType": "uint256",
          "name": "",
          "type": "uint256"
        },
        {
          "internalType": "uint256",
          "name": "",
          "type": "uint256"
        },
        {
          "internalType": "bool",
          "name": "",
          "type": "bool"
        },
        {
          "internalType": "uint256",
          "name": "",
          "type": "uint256"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "nextElectionId",
      "outputs": [
        {
          "internalType": "uint256",
          "name": "",
          "type": "uint256"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "owner",
      "outputs": [
        {
          "internalType": "address",
          "name": "",
          "type": "address"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "renounceOwnership",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "uint256",
          "name": "_electionId",
          "type": "uint256"
        },
        {
          "internalType": "bool",
          "name": "_isClosed",
          "type": "bool"
        }
      ],
      "name": "toggleCloseElection",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "address",
          "name": "newOwner",
          "type": "address"
        }
      ],
      "name": "transferOwnership",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "uint256",
          "name": "_electionId",
          "type": "uint256"
        },
        {
          "internalType": "uint256",
          "name": "_candidateId",
          "type": "uint256"
        }
      ],
      "name": "vote",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    }
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
    if (!auth) return res.status(401).json({ msg: 'No token' });
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
  if (!req.user || req.user.role !== 'admin') return res.status(403).json({ msg: 'Admin only' });
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
        if (!captchaRes || !captchaRes.success) return res.status(400).json({ msg: 'reCAPTCHA failed' });
    }

    if (role === 'admin' && inviteCode !== ADMIN_INVITE_CODE) return res.status(403).json({ msg: 'Invalid admin invite code' });

    const exists = await User.findOne({ email });
    if (exists) return res.status(400).json({ msg: 'A user with that email already exists' });

    const salt = await bcrypt.genSalt(10);
    const hash = await bcrypt.hash(password, salt);

    const user = new User({ name, email, passwordHash: hash, role: role || 'user' });
    await user.save();

    return res.json({ msg: 'Registration successful! You can now log in.' });
  } catch (err) {
    console.error('register err', err);
    res.status(500).json({ msg: 'Server error during registration' });
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

    const token = signToken(user);
    const { _id, name, role, walletAddress, hasVotedOn } = user;

    res.json({ token, user: { id: _id, email: user.email, name, role, walletAddress, hasVotedOn } });
  } catch (err) {
    console.error('login err', err);
    res.status(500).json({ msg: 'Server error' });
  }
});

app.post('/api/auth/logout', authMiddleware, async (req,res) => {
  try {
    const token = req.token;
    const decoded = jwt.decode(token);
    const exp = decoded && decoded.exp ? new Date(decoded.exp * 1000) : new Date(Date.now() + 7*24*60*60*1000);
    await BlacklistedToken.create({ token, expiresAt: exp });
    return res.json({ ok:true });
  } catch (err) {
    console.error('logout err', err);
    res.status(500).json({ msg: 'Server error' });
  }
});

app.get('/api/auth/me', authMiddleware, (req, res) => {
    const { _id, name, email, role, walletAddress, hasVotedOn } = req.user;
    res.json({ id: _id, name, email, role, walletAddress, hasVotedOn });
});

app.post('/api/auth/challenge', authMiddleware, async (req,res) => {
  try {
    const nonce = crypto.randomBytes(16).toString('hex');
    req.user.walletNonce = nonce;
    await req.user.save();
    const message = `Link your wallet to AuraVote by signing this message. Nonce: ${nonce}`;
    return res.json({ message });
  } catch (err) {
    console.error('challenge err', err);
    res.status(500).json({ msg: 'Server error' });
  }
});

app.post('/api/auth/verify-link', authMiddleware, async (req,res) => {
  try {
    const { signature } = req.body;
    if (!signature) return res.status(400).json({ msg: 'Signature is required' });

    const nonce = req.user.walletNonce;
    if (!nonce) return res.status(400).json({ msg: 'No challenge issued. Please request a challenge first.' });

    // NOTE: The message here MUST EXACTLY MATCH the one in your frontend `linkWallet` function.
    // I noticed your old code said "HybridVote". I've kept it as "AuraVote" from the challenge endpoint.
    const message = `Link your wallet to AuraVote by signing this message. Nonce: ${nonce}`;
    let recovered;
    try {
      recovered = ethers.verifyMessage(message, signature);
    } catch (e) {
      return res.status(400).json({ msg: 'Invalid signature format.' });
    }

    const existingUser = await User.findOne({ walletAddress: recovered.toLowerCase() });
    if (existingUser && existingUser._id.toString() !== req.user._id.toString()) {
        return res.status(400).json({ msg: 'This wallet is already linked to another account.' });
    }

    req.user.walletAddress = recovered.toLowerCase();
    req.user.walletNonce = undefined;
    await req.user.save();

    return res.json({ ok:true, walletAddress: req.user.walletAddress });
  } catch (err) {
    console.error('verify-link err', err);
    res.status(500).json({ msg: 'Server error' });
  }
});

app.get('/api/elections', async (req,res) => {
  const list = await Election.find().sort({ createdAt: -1 }).lean();
  res.json(list);
});

app.get('/api/elections/active', async (req,res) => {
  const el = await Election.findOne({
    closed: false,
    startAt: { $lte: new Date() },
    $or: [{ endAt: null }, { endAt: { $gte: new Date() }}]
  }).sort({ createdAt: -1 }).lean();

  if (!el) return res.status(404).json({ msg: 'No active election' });
  res.json(el);
});

app.get('/api/elections/results', async (req, res) => {
    try {
        const { id } = req.query;
        const now = new Date();
        let election;

        if (id) {
            election = await Election.findOne({ onChainId: id }).lean();
        } else {
            election = await Election.findOne({ 
                closed: false,
                $or: [{ startAt: null }, { startAt: { $lte: now } }],
                $or: [{ endAt: null }, { endAt: { $gte: now }}]
            }).sort({ createdAt: -1 }).lean();
            if (!election) {
                election = await Election.findOne({
                    $or: [{ closed: true }, { endAt: { $ne: null, $lt: now }}]
                }).sort({ endAt: -1 }).lean();
            }
        }
        
        if (!election) return res.status(404).json({ msg: 'No election results found.' });
        
        let status = 'Finished';
        if (election.closed) {
            status = 'Closed';
        } else {
            const start = election.startAt ? new Date(election.startAt) : null;
            const end = election.endAt ? new Date(election.endAt) : null;
            if (start && now < start) status = 'Scheduled';
            else if (end && now > end) status = 'Finished';
            else status = 'Live';
        }
        res.json({ title: election.title, results: election.candidates, status });
    } catch(err) {
        console.error('results err', err);
        res.status(500).json({ msg: 'Server error' });
    }
});

app.get('/api/elections/history', async (req, res) => {
    try {
        const now = new Date();
        const finishedElections = await Election.find({
            $or: [{ closed: true }, { endAt: { $ne: null, $lt: now }}]
        })
        .sort({ endAt: -1 })
        .select('title onChainId')
        .lean();
        res.json(finishedElections);
    } catch (err) {
        console.error('history err', err);
        res.status(500).json({ msg: 'Server error' });
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
      title, description, onChainId,
      startAt: startAt ? new Date(startAt) : null,
      endAt: endAt ? new Date(endAt) : null,
      closed: false, candidates: []
    });
    await doc.save();
    res.json({ ok:true, txHash: receipt.hash, onChainId });
  } catch (err) {
    console.error('create election err', err);
    res.status(500).json({ msg: 'Failed to create election', error: err.message });
  }
});

app.post('/api/admin/elections/:onChainId/candidates', authMiddleware, adminOnly, async (req,res) => {
  try {
    const { onChainId } = req.params;
    const { name, party } = req.body;
    if (!contract) return res.status(500).json({ msg: 'Contract not configured' });
    const tx = await contract.addCandidate(onChainId, name || 'Candidate', party || '');
    const receipt = await tx.wait();
    res.json({ ok:true, txHash: receipt.hash });
  } catch (err) {
    console.error('add candidate err', err);
    res.status(500).json({ msg:'Failed to add candidate', error: err.message });
  }
});

app.post('/api/admin/elections/:onChainId/close', authMiddleware, adminOnly, async (req, res) => {
  try {
    const { onChainId } = req.params;
    if (!contract) return res.status(500).json({ msg: 'Contract not configured' });
    const tx = await contract.toggleCloseElection(onChainId, true);
    const receipt = await tx.wait();
    await Election.updateOne({ onChainId }, { $set: { closed: true } });
    res.json({ ok: true, txHash: receipt.hash });
  } catch (err) {
    console.error('close election err', err);
    res.status(500).json({ msg: 'Failed to close election', error: err.message });
  }
});

app.post('/api/verify/vote', authMiddleware, async (req,res) => {
  try {
    const { txHash, electionId, candidateId } = req.body;
    if (!txHash) return res.status(400).json({ msg: 'txHash required' });
    const receipt = await provider.getTransactionReceipt(txHash);
    if (!receipt || receipt.status === 0) return res.status(400).json({ msg:'Transaction failed or not found' });
    const iface = new Interface(contractABI);
    const votedLog = receipt.logs.map(log => { try { return iface.parseLog(log); } catch { return null; } }).find(log => log && log.name === 'Voted');
    if (!votedLog) return res.status(400).json({ msg: 'No Voted event found in transaction' });
    const { electionId: evElectionId, candidateId: evCandidateId, voter: evVoter } = votedLog.args;
    if (evElectionId.toString() !== electionId.toString() || evCandidateId.toString() !== candidateId.toString()) { return res.status(400).json({ msg:'Event data does not match request' }); }
    if (!req.user.walletAddress) return res.status(400).json({ msg:'User has no linked wallet' });
    if (req.user.walletAddress.toLowerCase() !== evVoter.toLowerCase()) return res.status(400).json({ msg:'Vote was cast by a different wallet' });
    req.user.hasVotedOn.set(electionId.toString(), true);
    await User.findByIdAndUpdate(req.user._id, { $set: { [`hasVotedOn.${electionId}`]: true } });
    await Election.updateOne({ onChainId: electionId.toString(), 'candidates.onChainId': candidateId.toString() }, { $inc: { votesTotal: 1, 'candidates.$.votes': 1 } });
    res.json({ ok:true });
  } catch (err) {
    console.error('verify vote err', err);
    res.status(500).json({ msg: 'Verification failed', error: err.message });
  }
});

// --- THIS IS THE NEW, CORRECTLY PLACED BLOCK ---
app.post('/api/auth/disconnect-wallet', authMiddleware, async (req, res) => {
    try {
        req.user.walletAddress = null;
        await req.user.save();
        const { _id, name, email, role, walletAddress, hasVotedOn } = req.user;
        res.json({ id: _id, name, email, role, walletAddress, hasVotedOn });
    } catch (err) {
        console.error('Disconnect wallet error:', err);
        res.status(500).json({ msg: 'Server error while disconnecting wallet.' });
    }
});
// --- END OF NEW BLOCK ---

// ---------- EVENT LISTENER ----------
if (contractRead) {
  console.log('Starting contract event listeners...');
  contractRead.on('CandidateAdded', async (electionId, candidateId, name, party) => {
    try {
      const onChainId = electionId.toString();
      const candidateChainId = candidateId.toString();
      const el = await Election.findOne({ onChainId });
      if (el && !el.candidates.some(c => c.onChainId === candidateChainId)) {
        el.candidates.push({ onChainId: candidateChainId, name: name.toString(), party: party.toString(), votes: 0 });
        await el.save();
        console.log(`[EVENT] Synced CandidateAdded: Election ${onChainId}, Candidate ${candidateChainId}`);
      }
    } catch (err) { console.error('[EVENT] CandidateAdded err', err); }
  });
}

// ---------- START ----------
mongoose.connect(MONGO_URI).then(() => {
  console.log('Mongo connected');
  app.listen(PORT, () => console.log(`Server listening on ${PORT}`));
}).catch(err => {
  console.error('Mongo connect error', err);
  process.exit(1);
});