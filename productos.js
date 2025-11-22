// productos.js
const express = require('express');
const router = express.Router();

// GET todos los productos
router.get('/', (req, res) => {
  res.json([{ id: 1, nombre: 'Producto de ejemplo', deleted_at: null }]);
});

// POST nuevo producto
router.post('/', (req, res) => {
  const nuevo = req.body;
  res.status(201).json({ message: 'Producto creado', data: nuevo });
});

// PUT actualizar producto
router.put('/:id', (req, res) => {
  const { id } = req.params;
  const actualizado = req.body;
  res.json({ message: `Producto ${id} actualizado`, data: actualizado });
});

// DELETE eliminar producto
router.delete('/:id', (req, res) => {
  const { id } = req.params;
  res.json({ message: `Producto ${id} eliminado` });
});

// PATCH inhabilitar producto (borrado lógico)
router.patch('/:id/disable', async (req, res) => {
  const { id } = req.params;
  try {
    // TODO: actualiza en tu BD: set deleted_at = new Date().toISOString()
    // Simulación:
    res.json({ ok: true, id, deleted_at: new Date().toISOString(), message: `Producto ${id} inhabilitado` });
  } catch (err) {
    res.status(500).json({ message: 'No se pudo inhabilitar', error: String(err) });
  }
});

// PATCH reactivar producto
router.patch('/:id/enable', async (req, res) => {
  const { id } = req.params;
  try {
    // TODO: actualiza en tu BD: set deleted_at = null
    // Simulación:
    res.json({ ok: true, id, deleted_at: null, message: `Producto ${id} reactivado` });
  } catch (err) {
    res.status(500).json({ message: 'No se pudo reactivar', error: String(err) });
  }
});

module.exports = router;