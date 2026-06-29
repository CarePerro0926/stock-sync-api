// routes/productos.js
import express from 'express';
import { createClient } from '@supabase/supabase-js';

const router = express.Router();

console.log('[productos.js] cargado - ' + new Date().toISOString());

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);

// Normalización de fila
function normalizeProductoRow(row = {}) {
  const idRaw = row?.id ?? row?.product_id ?? null;
  const id = idRaw === null ? '' : String(idRaw);
  const nombre = row?.nombre ?? row?.name ?? '';
  const categoria_nombre = row?.categoria_nombre || row?.categorias?.nombre || row?.categoria || 'Sin Categoría';
  let cantidad = 0;
  if (typeof row?.cantidad === 'number') cantidad = row.cantidad;
  else if (typeof row?.stock === 'number') cantidad = row.stock;
  let precio = null;
  if (typeof row?.precio === 'number') precio = row.precio;
  const deleted_at = row?.deleted_at ?? null;
  return {
    id,
    nombre: nombre || 'Sin nombre',
    categoria_nombre,
    cantidad,
    precio,
    deleted_at,
    disabled: !!(row?.disabled),
    inactivo: !!(row?.inactivo),
    _raw: row
  };
}

function parsePositiveInt(value, fallback) {
  const n = Number(value);
  if (!Number.isFinite(n) || Number.isNaN(n)) return fallback;
  const i = Math.trunc(n);
  return i < 0 ? fallback : i;
}

function isUUID(value) {
  if (typeof value !== 'string') return false;
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value);
}

function applyCommonFilters(queryBuilder, { includeInactive, search, categoria, cantidadFilters = {} }) {
  if (!includeInactive) {
    queryBuilder = queryBuilder.is('deleted_at', null);
  }

  if (search && String(search).trim() !== '') {
    const s = String(search).trim();
    const escaped = s.replace(/%/g, '\\%').replace(/'/g, "''");
    queryBuilder = queryBuilder.or(`nombre.ilike.%${escaped}%,categoria.ilike.%${escaped}%`);
  }

  if (categoria && String(categoria).trim() !== '') {
    const c = String(categoria).trim();
    if (isUUID(c)) {
      queryBuilder = queryBuilder.eq('categoria_id', c);
    } else {
      const escaped = c.replace(/%/g, '\\%').replace(/'/g, "''");
      queryBuilder = queryBuilder.or(`categoria.ilike.%${escaped}%,categoria_nombre.ilike.%${escaped}%`);
    }
  }

  const { cantidad, min_cantidad, max_cantidad } = cantidadFilters || {};
  if (typeof cantidad !== 'undefined' && cantidad !== null && Number.isFinite(Number(cantidad))) {
    queryBuilder = queryBuilder.eq('cantidad', Number(cantidad));
  } else {
    if (typeof min_cantidad !== 'undefined' && min_cantidad !== null && Number.isFinite(Number(min_cantidad))) {
      queryBuilder = queryBuilder.gte('cantidad', Number(min_cantidad));
    }
    if (typeof max_cantidad !== 'undefined' && max_cantidad !== null && Number.isFinite(Number(max_cantidad))) {
      queryBuilder = queryBuilder.lte('cantidad', Number(max_cantidad));
    }
  }

  return queryBuilder;
}

// NOTA: Se eliminó el bloque router.options() aquí, ya que causaba conflictos 
// con path-to-regexp y ya cuentas con un middleware CORS global en server.js.

router.get('/', async (req, res) => {
  const DEFAULT_LIMIT = 20;
  const MAX_LIMIT = 200;

  const activoParam = typeof req.query.activo !== 'undefined' ? String(req.query.activo).toLowerCase() : undefined;
  const includeInactiveParam = typeof req.query.include_inactive !== 'undefined' ? String(req.query.include_inactive).toLowerCase() : undefined;

  let includeInactive = false;
  if (includeInactiveParam === 'true') {
    includeInactive = true;
  } else if (typeof activoParam !== 'undefined') {
    includeInactive = !(activoParam === 'true');
  } else {
    includeInactive = false;
  }

  let limit = parsePositiveInt(req.query.limit, DEFAULT_LIMIT);
  if (limit <= 0) limit = DEFAULT_LIMIT;
  if (limit > MAX_LIMIT) limit = MAX_LIMIT;
  let offset = parsePositiveInt(req.query.offset, 0);
  if (offset < 0) offset = 0;

  const search = typeof req.query.search === 'string' ? req.query.search : (req.query.q || '');
  const categoria = typeof req.query.categoria === 'string' ? req.query.categoria : '';
  const cantidad = typeof req.query.cantidad !== 'undefined' && req.query.cantidad !== '' ? parseInt(req.query.cantidad, 10) : undefined;
  const min_cantidad = typeof req.query.min_cantidad !== 'undefined' && req.query.min_cantidad !== '' ? parseInt(req.query.min_cantidad, 10) : undefined;
  const max_cantidad = typeof req.query.max_cantidad !== 'undefined' && req.query.max_cantidad !== '' ? parseInt(req.query.max_cantidad, 10) : undefined;
  const cantidadFilters = { cantidad, min_cantidad, max_cantidad };

  try {
    let tableQuery = supabase
      .from('productos')
      .select(`
        id,
        product_id,
        nombre,
        precio,
        cantidad,
        categoria_id,
        categoria,
        categoria_nombre,
        deleted_at
      `, { count: 'exact' })
      .order('nombre', { ascending: true });

    tableQuery = applyCommonFilters(tableQuery, { includeInactive, search, categoria, cantidadFilters });

    const from = offset;
    const to = offset + limit - 1;
    tableQuery = tableQuery.range(from, to);

    const { data, count, error } = await tableQuery;

    if (error) {
      return res.status(500).json({ message: 'Error al obtener productos', error: error.message || String(error) });
    }

    const { data: cats } = await supabase.from('categorias').select('id, nombre');
    const catMap = {};
    (cats || []).forEach(c => { catMap[c.id] = c.nombre; });

    const normalized = (data || []).map(row => {
      row.categoria_nombre = catMap[row.categoria_id] || 'Sin Categoría';
      return normalizeProductoRow(row);
    });

    res.setHeader('Cache-Control', 'no-store');
    return res.json({
      items: normalized,
      meta: { total: typeof count === 'number' ? count : normalized.length, limit, offset }
    });
  } catch (err) {
    console.error('[productos GET] error inesperado:', err);
    return res.status(500).json({ message: 'Error inesperado', error: String(err) });
  }
});

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

router.patch('/:id/disable', async (req, res) => {
  const { id } = req.params;
  try {
    const { data, error } = await supabase
      .from('productos')
      .update({ deleted_at: new Date().toISOString() })
      .eq('id', id)
      .select();
    if (error) return res.status(500).json({ message: 'No se pudo inhabilitar', error: error.message || String(error) });
    const enriched = await fetchProductoFromView(id);
    if (enriched) return res.json({ ok: true, data: enriched });
    const updated = Array.isArray(data) && data.length > 0 ? normalizeProductoRow(data[0]) : null;
    return res.json({ ok: true, data: updated });
  } catch (err) {
    return res.status(500).json({ message: 'Error inesperado', error: String(err) });
  }
});

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

export default router;