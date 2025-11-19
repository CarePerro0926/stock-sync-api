// productos.js
const express = require('express');
const router = express.Router();

// GET todos los productos
router.get('/', (req, res) => {
  res.json([{ id: 1, nombre: 'Producto de ejemplo' }]);
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

module.exports = router;