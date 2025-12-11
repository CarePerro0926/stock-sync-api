// productos.js
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

/**
 * GET /api/productos
 * - Por defecto devuelve solo activos (deleted_at IS NULL).
 * - Si ?include_inactive=true devuelve todos.
 * - Intenta usar la vista 'vista_productos_con_categoria' (si existe) para obtener datos enriquecidos.
 * - Normaliza la respuesta para que el frontend reciba siempre los campos esperados.
 */
router.get('/', async (req, res) => {
  const includeInactive = String(req.query.include_inactive || '').toLowerCase() === 'true';
  console.log('[productos GET] include_inactive=', includeInactive);
  try {
    // Intentar leer desde la vista enriquecida primero
    try {
      console.log('[productos GET] intentando leer vista vista_productos_con_categoria con service role key');
      let viewQuery = supabase
        .from('vista_productos_con_categoria')
        .select('*')
        .order('nombre', { ascending: true });

      if (!includeInactive) viewQuery = viewQuery.is('deleted_at', null);

      const { data: viewData, error: viewErr } = await viewQuery;
      console.log('[productos GET] vista result: error=', viewErr, 'rows=', Array.isArray(viewData) ? viewData.length : viewData);

      if (!viewErr && Array.isArray(viewData) && viewData.length > 0) {
        const normalized = viewData.map(normalizeProductoRow);
        res.setHeader('Cache-Control', 'no-store');
        console.log('[productos GET] devolviendo datos desde vista, count=', normalized.length);
        return res.json(normalized);
      }
      console.log('[productos GET] vista no usable (vacía o error), fallback a tabla productos');
    } catch (viewEx) {
      console.error('[productos GET] excepción leyendo vista:', String(viewEx));
    }

    // Fallback: consultar tabla 'productos' directamente
    console.log('[productos GET] consultando tabla productos (fallback)');
    let query = supabase.from('productos').select('*').order('nombre', { ascending: true });
    if (!includeInactive) query = query.is('deleted_at', null);

    const { data, error } = await query;
    console.log('[productos GET] productos result: error=', error, 'rows=', Array.isArray(data) ? data.length : data);
    if (error) {
      return res.status(500).json({ message: 'Error al obtener productos', error: error.message || String(error) });
    }

    const normalized = (data || []).map(normalizeProductoRow);
    res.setHeader('Cache-Control', 'no-store');
    return res.json(normalized);
  } catch (err) {
    console.error('[productos GET] error inesperado:', err);
    return res.status(500).json({ message: 'Error inesperado', error: String(err) });
  }
});

/**
 * POST /api/productos
 * Crea un nuevo producto. Devuelve el registro creado normalizado.
 */
router.post('/', async (req, res) => {
  try {
    const payload = req.body || {};
    const { data, error } = await supabase.from('productos').insert(payload).select();
    if (error) return res.status(500).json({ message: 'Error al crear producto', error: error.message || String(error) });
    const created = Array.isArray(data) && data.length > 0 ? normalizeProductoRow(data[0]) : null;
    return res.status(201).json({ ok: true, message: 'Producto creado', data: created });
  } catch (err) {
    return res.status(500).json({ message: 'Error inesperado', error: String(err) });
  }
});

/**
 * PUT /api/productos/:id
 * Actualiza un producto por id. Devuelve el registro actualizado normalizado.
 */
router.put('/:id', async (req, res) => {
  const { id } = req.params;
  try {
    const payload = req.body || {};
    const { data, error } = await supabase.from('productos').update(payload).eq('id', id).select();
    if (error) return res.status(500).json({ message: `Error al actualizar producto ${id}`, error: error.message || String(error) });
    const updated = Array.isArray(data) && data.length > 0 ? normalizeProductoRow(data[0]) : null;
    return res.json({ ok: true, message: `Producto ${id} actualizado`, data: updated });
  } catch (err) {
    return res.status(500).json({ message: 'Error inesperado', error: String(err) });
  }
});

/**
 * DELETE /api/productos/:id
 * Elimina físicamente un producto.
 */
router.delete('/:id', async (req, res) => {
  const { id } = req.params;
  try {
    const { error } = await supabase.from('productos').delete().eq('id', id);
    if (error) return res.status(500).json({ message: `Error al eliminar producto ${id}`, error: error.message || String(error) });
    return res.json({ ok: true, message: `Producto ${id} eliminado` });
  } catch (err) {
    return res.status(500).json({ message: 'Error inesperado', error: String(err) });
  }
});

/**
 * Helper interno: obtener producto enriquecido desde la vista (si existe)
 * Devuelve null si no se encuentra o si hay error.
 */
async function fetchProductoFromView(id) {
  try {
    const { data, error } = await supabase
      .from('vista_productos_con_categoria')
      .select('*')
      .eq('id', id)
      .limit(1);

    if (error || !Array.isArray(data) || data.length === 0) return null;
    return normalizeProductoRow(data[0]);
  } catch (err) {
    return null;
  }
}

/**
 * PATCH /api/productos/:id/disable
 * Borrado lógico: set deleted_at = now()
 * Devuelve el registro actualizado (normalizado). Intenta devolver la versión enriquecida desde la vista.
 */
router.patch('/:id/disable', async (req, res) => {
  const { id } = req.params;
  try {
    // Actualizar tabla productos
    const { data, error } = await supabase
      .from('productos')
      .update({ deleted_at: new Date().toISOString() })
      .eq('id', id)
      .select();

    if (error) return res.status(500).json({ message: 'No se pudo inhabilitar', error: error.message || String(error) });

    // Intentar devolver la fila enriquecida desde la vista
    const enriched = await fetchProductoFromView(id);
    if (enriched) return res.json({ ok: true, data: enriched });

    // Si no hay vista o no devolvió, normalizar el resultado directo
    const updated = Array.isArray(data) && data.length > 0 ? normalizeProductoRow(data[0]) : null;
    return res.json({ ok: true, data: updated });
  } catch (err) {
    return res.status(500).json({ message: 'Error inesperado', error: String(err) });
  }
});

/**
 * PATCH /api/productos/:id/enable
 * Reactiva producto: deleted_at = null
 * Devuelve el registro actualizado (normalizado). Intenta devolver la versión enriquecida desde la vista.
 */
router.patch('/:id/enable', async (req, res) => {
  const { id } = req.params;
  try {
    const { data, error } = await supabase
      .from('productos')
      .update({ deleted_at: null })
      .eq('id', id)
      .select();

    if (error) return res.status(500).json({ message: 'No se pudo reactivar', error: error.message || String(error) });

    const enriched = await fetchProductoFromView(id);
    if (enriched) return res.json({ ok: true, data: enriched });

    const updated = Array.isArray(data) && data.length > 0 ? normalizeProductoRow(data[0]) : null;
    return res.json({ ok: true, data: updated });
  } catch (err) {
    return res.status(500).json({ message: 'Error inesperado', error: String(err) });
  }
});

module.exports = router;