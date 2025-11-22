// api/server.js
import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import { createClient } from '@supabase/supabase-js';

const app = express();
app.use(express.json());
app.use(helmet());

// CORS: permitir header personalizado x-admin-token y credenciales si se usan
app.use(cors({
  origin: process.env.FRONTEND_ORIGIN || '*',
  allowedHeaders: ['Content-Type', 'x-admin-token', 'authorization'],
  exposedHeaders: ['Content-Type', 'x-admin-token'],
  credentials: true,
  methods: ['GET', 'POST', 'PATCH', 'PUT', 'DELETE', 'OPTIONS']
}));

// Responder OPTIONS para preflight (seguro y explícito)
app.options('*', (req, res) => res.sendStatus(204));

// Soporta ambos nombres de variable por compatibilidad
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY || process.env.SUPABASE_KEY;

if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) {
  console.error('Falta SUPABASE_URL o SUPABASE_SERVICE_KEY en variables de entorno');
  process.exit(1);
}

const supabaseAdmin = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY);

// Validación simple de admin por header x-admin-token (acepta mayúsculas/minúsculas)
const isAdminRequest = (req) => {
  // Express lowercases header names; soportamos también Authorization bearer si se desea
  const token = req.headers['x-admin-token'] || req.headers['X-Admin-Token'] || null;
  if (!process.env.ADMIN_API_TOKEN) {
    // Si no hay token configurado en el entorno, rechazamos y lo dejamos claro en logs
    console.warn('ADMIN_API_TOKEN no está definido en variables de entorno; todas las peticiones admin serán rechazadas.');
    return false;
  }
  return !!token && token === process.env.ADMIN_API_TOKEN;
};

const respondError = (res, status = 500, message = 'Error interno', details = null) => {
  const payload = { success: false, message };
  if (details) payload.error = details;
  return res.status(status).json(payload);
};

// Middleware opcional de logging simple (útil para debugging en Render)
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} ${req.method} ${req.originalUrl}`);
  next();
});

// GET lista de productos
app.get('/api/productos', async (req, res) => {
  try {
    console.log('GET /api/productos - SUPABASE_URL present:', !!SUPABASE_URL);
    console.log('GET /api/productos - SUPABASE_SERVICE_KEY present:', !!SUPABASE_SERVICE_KEY);

    const { data, error } = await supabaseAdmin
      .from('productos')
      .select('id, product_id, nombre, precio, cantidad, categoria_id, deleted_at')
      .order('id', { ascending: true });

    if (error) {
      console.error('GET /api/productos - supabase error:', error.message);
      return respondError(res, 500, 'No se pudo obtener productos', error.message);
    }

    console.log('GET /api/productos - returned rows:', Array.isArray(data) ? data.length : 0);
    return res.status(200).json(data || []);
  } catch (err) {
    console.error('API exception GET /api/productos:', err);
    return respondError(res, 500, 'Error interno', String(err));
  }
});

// GET lista de usuarios (handler mínimo para que el frontend no falle)
app.get('/api/usuarios', async (req, res) => {
  try {
    const { data, error } = await supabaseAdmin
      .from('usuarios')
      .select('*')
      .order('id', { ascending: true });

    if (error) {
      console.warn('GET /api/usuarios - supabase returned error, returning empty array:', error.message);
      return res.status(200).json([]);
    }

    return res.status(200).json(data || []);
  } catch (err) {
    console.warn('GET /api/usuarios - exception, returning empty array:', String(err));
    return res.status(200).json([]);
  }
});

// PATCH disable
app.patch('/api/productos/:id/disable', async (req, res) => {
  if (!isAdminRequest(req)) {
    console.warn('PATCH disable - request rejected as non-admin. x-admin-token present:', !!req.headers['x-admin-token']);
    return respondError(res, 403, 'Forbidden');
  }

  const { id } = req.params;
  try {
    const { data, error } = await supabaseAdmin
      .from('productos')
      .update({ deleted_at: new Date().toISOString() })
      .or(`id.eq.${id},product_id.eq.${id}`)
      .select();

    if (error) {
      console.error('API error updating producto disable:', error);
      return respondError(res, 500, 'No se pudo inhabilitar el producto', error.message);
    }

    const result = Array.isArray(data) ? data : [data];
    return res.status(200).json({ success: true, data: result });
  } catch (err) {
    console.error('API exception PATCH disable:', err);
    return respondError(res, 500, 'Error interno', String(err));
  }
});

// PATCH enable
app.patch('/api/productos/:id/enable', async (req, res) => {
  if (!isAdminRequest(req)) {
    console.warn('PATCH enable - request rejected as non-admin. x-admin-token present:', !!req.headers['x-admin-token']);
    return respondError(res, 403, 'Forbidden');
  }

  const { id } = req.params;
  try {
    const { data, error } = await supabaseAdmin
      .from('productos')
      .update({ deleted_at: null })
      .or(`id.eq.${id},product_id.eq.${id}`)
      .select();

    if (error) {
      console.error('API error updating producto enable:', error);
      return respondError(res, 500, 'No se pudo habilitar el producto', error.message);
    }

    const result = Array.isArray(data) ? data : [data];
    return res.status(200).json({ success: true, data: result });
  } catch (err) {
    console.error('API exception PATCH enable:', err);
    return respondError(res, 500, 'Error interno', String(err));
  }
});

// Health check
app.get('/api/health', (req, res) => res.status(200).json({ ok: true }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`API server listening on port ${PORT}`);
});