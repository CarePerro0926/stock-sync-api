// productos.js
const express = require('express');
const router = express.Router();
const { createClient } = require('@supabase/supabase-js');

// Usa la clave SERVICE_ROLE en backend para evitar bloqueos por RLS
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);

// GET: activos por defecto; include_inactive=true devuelve todos
router.get('/', async (req, res) => {
  const includeInactive = String(req.query.include_inactive || '').toLowerCase() === 'true';
  try {
    let query = supabase.from('productos').select('*').order('nombre', { ascending: true });
    if (!includeInactive) query = query.is('deleted_at', null);

    const { data, error } = await query;
    if (error) return res.status(500).json({ message: 'Error al obtener productos', error: error.message });
    res.json(data || []);
  } catch (err) {
    res.status(500).json({ message: 'Error inesperado', error: String(err) });
  }
});

// POST nuevo producto
router.post('/', async (req, res) => {
  try {
    const { data, error } = await supabase.from('productos').insert(req.body).select();
    if (error) return res.status(500).json({ message: 'Error al crear producto', error: error.message });
    res.status(201).json({ message: 'Producto creado', data });
  } catch (err) {
    res.status(500).json({ message: 'Error inesperado', error: String(err) });
  }
});

// PUT actualizar producto
router.put('/:id', async (req, res) => {
  const { id } = req.params;
  try {
    const { data, error } = await supabase.from('productos').update(req.body).eq('id', id).select();
    if (error) return res.status(500).json({ message: `Error al actualizar producto ${id}`, error: error.message });
    res.json({ message: `Producto ${id} actualizado`, data });
  } catch (err) {
    res.status(500).json({ message: 'Error inesperado', error: String(err) });
  }
});

// DELETE eliminar producto (físico)
router.delete('/:id', async (req, res) => {
  const { id } = req.params;
  try {
    const { error } = await supabase.from('productos').delete().eq('id', id);
    if (error) return res.status(500).json({ message: `Error al eliminar producto ${id}`, error: error.message });
    res.json({ message: `Producto ${id} eliminado` });
  } catch (err) {
    res.status(500).json({ message: 'Error inesperado', error: String(err) });
  }
});

// PATCH inhabilitar producto (borrado lógico)
router.patch('/:id/disable', async (req, res) => {
  const { id } = req.params;
  try {
    const { data: exists, error: errCheck } = await supabase
      .from('productos').select('id').eq('id', id).single();
    if (errCheck) return res.status(500).json({ message: 'Error comprobando producto', error: errCheck.message || errCheck });
    if (!exists) return res.status(404).json({ message: 'Producto no encontrado' });

    const { data, error } = await supabase
      .from('productos')
      .update({ deleted_at: new Date().toISOString() })
      .eq('id', id)
      .select();
    if (error) return res.status(500).json({ message: 'No se pudo inhabilitar', error: error.message });

    res.json({ ok: true, data });
  } catch (err) {
    res.status(500).json({ message: 'Error inesperado', error: String(err) });
  }
});

// PATCH reactivar producto
router.patch('/:id/enable', async (req, res) => {
  const { id } = req.params;
  try {
    const { data, error } = await supabase
      .from('productos')
      .update({ deleted_at: null })
      .eq('id', id)
      .select();
    if (error) return res.status(500).json({ message: 'No se pudo reactivar', error: error.message });

    res.json({ ok: true, data });
  } catch (err) {
    res.status(500).json({ message: 'Error inesperado', error: String(err) });
  }
});

module.exports = router;