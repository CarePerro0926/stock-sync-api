//routes/categorias.js
const express = require('express');
const router = express.Router();
const { createClient } = require('@supabase/supabase-js');

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);

router.get('/', async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('categorias')
      .select('id,nombre,deleted_at')
      .order('nombre', { ascending: true });

    if (error) {
      console.error('[categorias GET] supabase error:', error);
      return res.status(500).json({
        success: false,
        message: 'Error al obtener categorías',
        error: error.message || String(error)
      });
    }

    const items = (data || []).map((row, idx) => ({
      idx,
      nombre: row.nombre ?? '',
      id: row.id ?? null,
      deleted_at: row.deleted_at ?? null
    }));

    return res.json(items);
  } catch (err) {
    console.error('[categorias GET] error inesperado:', err);
    return res.status(500).json({
      success: false,
      message: 'Error al obtener categorías',
      error: String(err)
    });
  }
});

module.exports = router;