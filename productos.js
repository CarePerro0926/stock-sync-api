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
 */
router.options('*', (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', req.get('Origin') || '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,PATCH,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, Cache-Control, Pragma');
  res.setHeader('Access-Control-Max-Age', '600');
  return res.sendStatus(204);
});

/**
 * Utilidades internas para parseo y validación de query params
 */
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

/**
 * Construye filtros comunes (activo/includeInactive, search, categoria) sobre una query de supabase.
 * Recibe el objeto queryBuilder devuelto por supabase.from(...).select(...)
 */
function applyCommonFilters(queryBuilder, { includeInactive, search, categoria }) {
  // activo / includeInactive: si includeInactive === false => deleted_at IS NULL
  if (!includeInactive) {
    queryBuilder = queryBuilder.is('deleted_at', null);
  }

  // search: buscar en nombre y descripcion si existe
  if (search && String(search).trim() !== '') {
    const s = String(search).trim();
    // Supabase permite ilike; usar OR para nombre o descripcion
    // .or("nombre.ilike.%s,descripcion.ilike.%s", `%${s}%`, `%${s}%`) no es soportado directamente en builder,
    // así que usamos .or con la sintaxis de PostgREST
    const escaped = s.replace(/%/g, '\\%').replace(/'/g, "''");
    queryBuilder = queryBuilder.or(`nombre.ilike.%${escaped}% , descripcion.ilike.%${escaped}%`);
  }

  // categoria: puede ser UUID (categoria_id) o nombre de categoría
  if (categoria && String(categoria).trim() !== '') {
    const c = String(categoria).trim();
    if (isUUID(c)) {
      queryBuilder = queryBuilder.eq('categoria_id', c);
    } else {
      // intentar por nombre de categoría (campo categoria o categoria_nombre)
      const escaped = c.replace(/%/g, '\\%').replace(/'/g, "''");
      // usar ilike sobre categoria o categoria_nombre
      queryBuilder = queryBuilder.or(`categoria.ilike.%${escaped}% , categoria_nombre.ilike.%${escaped}%`);
    }
  }

  return queryBuilder;
}

/**
 * GET /api/productos
 * - Soporta query params: limit, offset, search, categoria, activo
 * - Devuelve { items: [...], meta: { total, limit, offset } }
 */
router.get('/', async (req, res) => {
  // Paginación y límites
  const DEFAULT_LIMIT = 20;
  const MAX_LIMIT = 200;

  // Interpretación de params:
  // - Si se pasa activo=true => devolver solo activos (deleted_at IS NULL)
  // - Si se pasa include_inactive=true => incluir inactivos (override)
  const activoParam = typeof req.query.activo !== 'undefined' ? String(req.query.activo).toLowerCase() : undefined;
  const includeInactiveParam = typeof req.query.include_inactive !== 'undefined' ? String(req.query.include_inactive).toLowerCase() : undefined;

  // Prioridad: include_inactive explicitamente true => include inactive
  // else if activo provided => activo=true means includeInactive=false
  let includeInactive = false;
  if (includeInactiveParam === 'true') {
    includeInactive = true;
  } else if (typeof activoParam !== 'undefined') {
    includeInactive = !(activoParam === 'true'); // activo=true => includeInactive=false
  } else {
    // default: only active
    includeInactive = false;
  }

  // parse limit/offset
  let limit = parsePositiveInt(req.query.limit, DEFAULT_LIMIT);
  if (limit <= 0) limit = DEFAULT_LIMIT;
  if (limit > MAX_LIMIT) limit = MAX_LIMIT;

  let offset = parsePositiveInt(req.query.offset, 0);
  if (offset < 0) offset = 0;

  const search = typeof req.query.search === 'string' ? req.query.search : (req.query.q || '');
  const categoria = typeof req.query.categoria === 'string' ? req.query.categoria : '';

  console.log('[productos GET] params:', { limit, offset, includeInactive, search, categoria });

  try {
    // Primero intentar leer desde la vista enriquecida
    try {
      console.log('[productos GET] intentando leer vista vista_productos_con_categoria con service role key');

      // Para conteo exacto con supabase: select('*', { count: 'exact' })
      // y luego aplicar range para paginación
      let viewQuery = supabase
        .from('vista_productos_con_categoria')
        .select('*', { count: 'exact' })
        .order('nombre', { ascending: true });

      viewQuery = applyCommonFilters(viewQuery, { includeInactive, search, categoria });

      // rango: supabase.range(from, to) where to = offset + limit - 1
      const from = offset;
      const to = offset + limit - 1;
      viewQuery = viewQuery.range(from, to);

      const { data: viewData, count: viewCount, error: viewErr } = await viewQuery;
      console.log('[productos GET] vista result: error=', viewErr, 'rows=', Array.isArray(viewData) ? viewData.length : viewData, 'count=', viewCount);

      if (!viewErr && Array.isArray(viewData)) {
        // Normalizar y devolver con meta
        const normalized = viewData.map(normalizeProductoRow);
        res.setHeader('Cache-Control', 'no-store');
        return res.json({
          items: normalized,
          meta: { total: typeof viewCount === 'number' ? viewCount : normalized.length, limit, offset }
        });
      }
      console.log('[productos GET] vista no usable (vacía o error), fallback a tabla productos');
    } catch (viewEx) {
      console.error('[productos GET] excepción leyendo vista:', String(viewEx));
    }

    // Fallback: consultar tabla 'productos' directamente con conteo y rango
    console.log('[productos GET] consultando tabla productos (fallback)');

    let tableQuery = supabase
      .from('productos')
      .select('*', { count: 'exact' })
      .order('nombre', { ascending: true });

    tableQuery = applyCommonFilters(tableQuery, { includeInactive, search, categoria });

    const from = offset;
    const to = offset + limit - 1;
    tableQuery = tableQuery.range(from, to);

    const { data, count, error } = await tableQuery;
    console.log('[productos GET] productos result: error=', error, 'rows=', Array.isArray(data) ? data.length : data, 'count=', count);

    if (error) {
      return res.status(500).json({ message: 'Error al obtener productos', error: error.message || String(error) });
    }

    const normalized = (data || []).map(normalizeProductoRow);
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
 */
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

/**
 * PATCH /api/productos/:id/enable
 * Reactiva producto: deleted_at = null
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