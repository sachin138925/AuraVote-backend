import { Router } from 'express';
import { ethers } from 'ethers';
import auth from '../middleware/auth.js';
import Election from '../models/Election.js';

const router = Router();

const CONTRACT_ABI = JSON.parse(process.env.CONTRACT_ABI_JSON || '[]');

router.get('/', auth, async (_req, res) => {
  const active = await Election.findOne({ isActive: true });
  if (!active) return res.status(404).json({ msg: 'There is no active election to show results for.' });

  const contractAddress = process.env.CONTRACT_ADDRESS;
  if (!contractAddress) return res.status(500).json({ msg: 'Contract address missing' });

  const rpc = process.env.RPC_URL || 'http://localhost:8545';
  const provider = new ethers.JsonRpcProvider(rpc);
  const contract = new ethers.Contract(contractAddress, CONTRACT_ABI, provider);

  const count = Number(await contract.candidatesCount());
  const results = [];
  for (let i = 1; i <= count; i++) {
    const c = await contract.candidates(i);
    const dbCand = active.candidates.find(x => x.name === c.name);
    results.push({
      name: c.name,
      party: dbCand?.party || 'N/A',
      votes: Number(c.voteCount)
    });
  }
  res.json({ title: active.title, results });
});

export default router;
