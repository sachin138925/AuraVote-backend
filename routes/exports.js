import { Router } from 'express';
import { createObjectCsvStringifier } from 'csv-writer';
import PDFDocument from 'pdfkit';
import Election from '../models/Election.js';
import auth from '../middleware/auth.js';
import admin from '../middleware/admin.js';

const router = Router();

router.get('/results/csv', [auth, admin], async (_req, res) => {
  const election = await Election.findOne({ isActive: true });
  if (!election) return res.status(404).json({ msg: 'No active election' });

  const csv = createObjectCsvStringifier({ header: [
    { id: 'name', title: 'Candidate' },
    { id: 'party', title: 'Party' },
    { id: 'votes', title: 'Votes' }
  ]});
  const header = csv.getHeaderString();
  const records = election.candidates.map(c => ({ name: c.name, party: c.party || '', votes: 0 }));
  const body = csv.stringifyRecords(records);

  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', `attachment; filename="results.csv"`);
  res.send(header + body);
});

router.get('/results/pdf', [auth, admin], async (_req, res) => {
  const election = await Election.findOne({ isActive: true });
  if (!election) return res.status(404).json({ msg: 'No active election' });

  const doc = new PDFDocument({ size: 'A4', margin: 50 });
  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', 'attachment; filename="results.pdf"');
  doc.pipe(res);

  doc.fontSize(18).text(`Election Results: ${election.title}`, { underline: true });
  doc.moveDown();

  election.candidates.forEach((c, idx) => {
    doc.fontSize(12).text(`${idx + 1}. ${c.name} (${c.party || 'N/A'}) — Votes: from chain`);
  });

  doc.end();
});

export default router;
