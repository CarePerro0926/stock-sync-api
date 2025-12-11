// api/productos.js
const express = require('express');
const router = express.Router();
const { createClient } = require('@supabase/supabase-js');

// Usa la clave SERVICE_ROLE en backend para evitar bloqueos por RLS
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);

/**
 * Helper: normaliza un registro de producto para que el frontend reciba siempre
 * los mismos campos mínimos que espera (id, nombre, categoria_nombre, cantidad, precio, deleted_at).
 * Convierte id a string para evitar inconsistencias entre "1" y 1.
 * Convierte precio a número cuando sea posible.
 */
function normalizeProductoRow(row = {}) {
  const idRaw = row?.id ?? row?.product_id ?? null;
  const id = idRaw === null || idRaw === undefined ? '' : String(idRaw);
  const deletedAtRaw = row?.deleted_at ?? row?.deletedAt ?? null;
  const deleted_at = (deletedAtRaw === null || deletedAtRaw === undefined) ? null : String(deletedAtRaw).trim();
  const nombre = row?.nombre ?? row?.name ?? row?.display_name ?? '';
  const categoria_nombre = row?.categoria_nombre ?? row?.categoria ?? row?.category_name ?? '';
  const cantidad = (typeof row?.cantidad === 'number')
    ? row.cantidad
    : (typeof row?.stock === 'number' ? row.stock : 0);

  // Normalizar precio: puede venir como number o string con separadores
  let precio = null;
  if (typeof row?.precio === 'number') {
    precio = row.precio;
  } else if (typeof row?.precio === 'string' && row.precio.trim() !== '') {
    // eliminar caracteres no numéricos excepto punto y guion
    const cleaned = String(row.precio).replace(/[^\d.-]/g, '');
    const parsed = Number(cleaned);
    precio = Number.isFinite(parsed) ? parsed : null;
  } else if (typeof row?.precio_unitario === 'number') {
    precio = row.precio_unitario;
  } else if (typeof row?.unit_price === 'number') {
    precio = row.unit_price;
  } else {
    precio = null;
  }

  return {
    id,
    nombre: nombre || 'Sin nombre',
    categoria_nombre: categoria_nombre || 'Sin Categoría',
    cantidad,
    precio,
    deleted_at: (deleted_at === '' || deleted_at === 'null' || deleted_at === 'undefined') ? null : deleted_at,
    // conservar flags si existen
    disabled: !!(row?.disabled === true || String(row?.disabled ?? '').trim().toLowerCase() === 'true'),
    inactivo: !!(row?.inactivo === true || String(row?.inactivo ?? '').trim().toLowerCase() === 'true'),
    _inactive: Boolean(deleted_at) || !!(row?.disabled) || !!(row?.inactivo),
    _raw: row
  };
}

/**
 * OPTIONS handler para permitir preflight CORS en este router.
 * Incluye Cache-Control y Pragma en Access-Control-Allow-Headers para evitar bloqueos
 * cuando el cliente envía esos headers en la preflight.
 *
 * Nota: si ya manejas CORS globalmente (app.use(cors(...))) esto es redundante pero inofensivo.
 */
router.options('*', (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', req.get('Origin') || '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,PATCH,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, Cache-Control, Pragma');
  res.setHeader('Access-Control-Max-Age', '600');
  return res.sendStatus(204);
});

// --- RUTAS DE PRODUCTOS (CRUD) ---

/**
 * GET /api/productos/:id (cuando se monta en /api/productos/) -> /api/productos/:id
 * Obtiene un producto específico por su ID (id o product_id).
 * Por defecto devuelve solo si está activo (deleted_at IS NULL).
 * Si ?include_inactive=true se ignora el estado de borrado lógico.
 * Devuelve el objeto del producto normalizado o un error 404.
 */
router.get('/:id', async (req, res) => {
  const { id } = req.params;
  const includeInactive = String(req.query.include_inactive || '').toLowerCase() === 'true';

  console.log('[productos GET /:id] id=', id, ' include_inactive=', includeInactive);

  if (!id) {
    return res.status(400).json({ message: 'ID de producto es requerido' });
  }

  try {
    let query = supabase
      .from('productos')
      .select('*')
      .or(`id.eq.${id},product_id.eq.${id}`) // Buscar por id o product_id
      .limit(1);

    if (!includeInactive) {
       query = query.is('deleted_at', null);
    }

    const { data, error } = await query;

    if (error) {
      console.error('[productos GET /:id] supabase error:', error);
      return res.status(500).json({ message: 'Error al obtener producto', error: error.message || String(error) });
    }

    if (!data || data.length === 0) {
      return res.status(404).json({ message: 'Producto no encontrado' });
    }

    const normalized = normalizeProductoRow(data[0]);
    res.setHeader('Cache-Control', 'no-store');
    return res.json(normalized); // Devuelve el objeto del producto normalizado
  } catch (err) {
    console.error('[productos GET /:id] error inesperado:', err);
    return res.status(500).json({ message: 'Error inesperado', error: String(err) });
  }
});

/**
 * POST /api/productos (cuando se monta en /api/productos/) -> /api/productos/
 * Crea un nuevo producto. Devuelve el registro creado normalizado.
 */
router.post('/', async (req, res) => {
  try {
    const payload = req.body || {};
    const { data, error } = await supabase.from('productos').insert(payload).select();
    if (error) return res.status(500).json({ message: 'Error al crear producto', error: error.message || String(error) });
    const created = Array.isArray(data) && data.length > 0 ? normalizeProductoRow(data[0]) : null;
    return res.status(201).json({ ok: true, message: 'Producto creado',  created });
  } catch (err) {
    return res.status(500).json({ message: 'Error inesperado', error: String(err) });
  }
});

/**
 * PUT /api/productos/:id (cuando se monta en /api/productos/) -> /api/productos/:id
 * Actualiza un producto por id (buscando por id o product_id). Devuelve el registro actualizado normalizado.
 */
router.put('/:id', async (req, res) => {
  const { id } = req.params;
  try {
    const payload = req.body || {};

    // Verificar si el producto existe antes de actualizar (buena práctica)
    const {  existingData, error: existingError } = await supabase
      .from('productos')
      .select('id')
      .or(`id.eq.${id},product_id.eq.${id}`)
      .limit(1);

    if (existingError) {
        console.error('[productos PUT /:id] supabase select error:', existingError);
        return res.status(500).json({ message: 'Error al verificar producto', error: existingError.message || String(existingError) });
    }

    if (!existingData || existingData.length === 0) {
        return res.status(404).json({ message: `Producto ${id} no encontrado` });
    }

    const { data, error } = await supabase
        .from('productos')
        .update(payload)
        .or(`id.eq.${id},product_id.eq.${id}`) // Actualizar usando or
        .select();
    if (error) return res.status(500).json({ message: `Error al actualizar producto ${id}`, error: error.message || String(error) });
    const updated = Array.isArray(data) && data.length > 0 ? normalizeProductoRow(data[0]) : null;
    return res.json({ ok: true, message: `Producto ${id} actualizado`,  updated });
  } catch (err) {
    return res.status(500).json({ message: 'Error inesperado', error: String(err) });
  }
});

/**
 * DELETE /api/productos/:id (cuando se monta en /api/productos/) -> /api/productos/:id
 * Elimina físicamente un producto (buscando por id o product_id).
 */
router.delete('/:id', async (req, res) => {
  const { id } = req.params;
  try {
    // Verificar si el producto existe antes de eliminar (buena práctica)
    const {  existingData, error: existingError } = await supabase
      .from('productos')
      .select('id')
      .or(`id.eq.${id},product_id.eq.${id}`)
      .limit(1);

    if (existingError) {
        console.error('[productos DELETE /:id] supabase select error:', existingError);
        return res.status(500).json({ message: 'Error al verificar producto', error: existingError.message || String(existingError) });
    }

    if (!existingData || existingData.length === 0) {
        return res.status(404).json({ message: `Producto ${id} no encontrado` });
    }

    const { error } = await supabase
        .from('productos')
        .delete()
        .or(`id.eq.${id},product_id.eq.${id}`); // Eliminar usando or
    if (error) return res.status(500).json({ message: `Error al eliminar producto ${id}`, error: error.message || String(error) });
    return res.json({ ok: true, message: `Producto ${id} eliminado` });
  } catch (err) {
    return res.status(500).json({ message: 'Error inesperado', error: String(err) });
  }
});

// Las rutas disable/enable ya están en server.js, así que no se duplican aquí.

module.exports = router; // Exporta el router para CommonJS