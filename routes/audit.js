// routes/audit.js
const express = require('express');
const router = express.Router();
const { createClient } = require('@supabase/supabase-js');

if (!process.env.SUPABASE_URL || !process.env.SUPABASE_SERVICE_ROLE_KEY) {
  console.error('Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY in environment');
}

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);

router.get('/audit-logs', async (req, res) => {
  try {
    const limit = Number(req.query.limit) || 50;
    const { data, error } = await supabase
      .from('audit_logs')
      .select('*')
      .order('created_at', { ascending: false })
      .limit(limit);

    if (error) {
      console.error('Supabase error fetching audit_logs:', error);
      return res.status(500).json({ error: error.message || 'supabase error' });
    }

    return res.json(data);
  } catch (err) {
    console.error('Unexpected error in /api/audit-logs:', err);
    return res.status(500).json({ error: 'server error' });
  }
});

module.exports = router;
