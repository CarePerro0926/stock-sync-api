// productos.js
const express = require('express');
const router = express.Router();
const { createClient } = require('@supabase/supabase-js');

// Log para confirmar que la versión del archivo se está cargando
console.log('[productos.js] cargado - ' + new Date().toISOString());

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
  const id = idRaw === null ? '' : String(idRaw);

  const nombre = row?.nombre ?? row?.name ?? '';

  const categoria_nombre = row?.categoria_nombre
    || row?.categorias?.nombre
    || row?.categoria
    || 'Sin Categoría';

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
 * Construye filtros comunes (activo/includeInactive, search, categoria, cantidad) sobre una query de supabase.
 * Recibe el objeto queryBuilder devuelto por supabase.from(...).select(...)
 */
function applyCommonFilters(queryBuilder, { includeInactive, search, categoria, cantidadFilters = {} }) {
  // activo / includeInactive: si includeInactive === false => deleted_at IS NULL
  if (!includeInactive) {
    queryBuilder = queryBuilder.is('deleted_at', null);
  }

 // search: buscar en nombre y en categoria si existe
if (search && String(search).trim() !== '') {
  const s = String(search).trim();
  const escaped = s.replace(/%/g, '\\%').replace(/'/g, "''");
  // Sintaxis PostgREST: sin espacios alrededor de la coma
  queryBuilder = queryBuilder.or(`nombre.ilike.%${escaped}%,categoria.ilike.%${escaped}%`);
}

  // categoria: puede ser UUID (categoria_id) o nombre de categoría
  if (categoria && String(categoria).trim() !== '') {
    const c = String(categoria).trim();
    if (isUUID(c)) {
      queryBuilder = queryBuilder.eq('categoria_id', c);
    } else {
      const escaped = c.replace(/%/g, '\\%').replace(/'/g, "''");
      queryBuilder = queryBuilder.or(`categoria.ilike.%${escaped}%,categoria_nombre.ilike.%${escaped}%`);
    }
  }

  // filtros por cantidad: cantidad (igual), min_cantidad (>=), max_cantidad (<=)
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

/**
 * GET /api/productos
 * - Soporta query params: limit, offset, search, categoria, activo, cantidad, min_cantidad, max_cantidad
 * - Devuelve { items: [...], meta: { total, limit, offset } }
 */
router.get('/', async (req, res) => {
  // Log de req.query para depuración
  console.log('[productos GET] req.query =', req.query);

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

  // parse cantidad filters (asegurar números o undefined)
  const cantidad = typeof req.query.cantidad !== 'undefined' && req.query.cantidad !== '' ? parseInt(req.query.cantidad, 10) : undefined;
  const min_cantidad = typeof req.query.min_cantidad !== 'undefined' && req.query.min_cantidad !== '' ? parseInt(req.query.min_cantidad, 10) : undefined;
  const max_cantidad = typeof req.query.max_cantidad !== 'undefined' && req.query.max_cantidad !== '' ? parseInt(req.query.max_cantidad, 10) : undefined;
  const cantidadFilters = { cantidad, min_cantidad, max_cantidad };

  console.log('[productos GET] params parsed:', { limit, offset, includeInactive, search, categoria, cantidadFilters });

  try {
    // Consultar directamente la tabla 'productos'
    console.log('[productos GET] consultando tabla productos directamente');

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

    // Aplicar filtros comunes
    tableQuery = applyCommonFilters(tableQuery, { includeInactive, search, categoria, cantidadFilters });

    // rango: supabase.range(from, to) where to = offset + limit - 1
    const from = offset;
    const to = offset + limit - 1;
    console.log('[productos GET] tabla range from=', from, 'to=', to);
    tableQuery = tableQuery.range(from, to);

    const { data, count, error } = await tableQuery;
console.log('[productos GET] productos result: error=', error, 'rows=', Array.isArray(data) ? data.length : data, 'count=', count);

if (error) {
  return res.status(500).json({ message: 'Error al obtener productos', error: error.message || String(error) });
}

// ✅ NUEVO: traer categorías y asignar el nombre antes de normalizar
const { data: cats } = await supabase.from('categorias').select('id, nombre');
const catMap = {};
(cats || []).forEach(c => { catMap[c.id] = c.nombre; });
console.log('[productos GET] catMap:', catMap);

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