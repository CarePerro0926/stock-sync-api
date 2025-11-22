// api/server.js
import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import { createClient } from '@supabase/supabase-js';

const app = express();
app.use(express.json());
app.use(helmet());
app.use(cors({ origin: process.env.FRONTEND_ORIGIN || '*' }));

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY;

if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) {
  console.error('Falta SUPABASE_URL o SUPABASE_SERVICE_KEY en variables de entorno');
  process.exit(1);
}

const supabaseAdmin = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY);

// Validación simple de admin por header x-admin-token
const isAdminRequest = (req) => {
  const token = req.headers['x-admin-token'];
  return token && process.env.ADMIN_API_TOKEN && token === process.env.ADMIN_API_TOKEN;
};

const respondError = (res, status = 500, message = 'Error interno', details = null) => {
  const payload = { success: false, message };
  if (details) payload.error = details;
  return res.status(status).json(payload);
};

// GET lista de productos
app.get('/api/productos', async (req, res) => {
  try {
    console.log('GET /api/productos - SUPABASE_URL present:', !!process.env.SUPABASE_URL);
    console.log('GET /api/productos - SUPABASE_SERVICE_KEY present:', !!process.env.SUPABASE_SERVICE_KEY);

    const { data, error } = await supabaseAdmin
      .from('productos')
      .select('id, product_id, nombre, precio, cantidad, categoria_id, deleted_at')
      .order('id', { ascending: true });

    if (error) {
      console.error('GET /api/productos - supabase error:', error.message);
      return respondError(res, 500, 'No se pudo obtener productos', error.message);
    }

    console.log('GET /api/productos - returned rows:', Array.isArray(data) ? data.length : 0);
    return res.status(200).json(data);
  } catch (err) {
    console.error('API exception GET /api/productos:', err);
    return respondError(res, 500, 'Error interno', String(err));
  }
});

// PATCH disable
app.patch('/api/productos/:id/disable', async (req, res) => {
  if (!isAdminRequest(req)) return respondError(res, 403, 'Forbidden');
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

    // Si la query puede devolver múltiples filas, devolver el array; si solo una, devolver el primer elemento
    const result = Array.isArray(data) ? data : [data];
    return res.status(200).json({ success: true, data: result });
  } catch (err) {
    console.error('API exception PATCH disable:', err);
    return respondError(res, 500, 'Error interno', String(err));
  }
});

// PATCH enable
app.patch('/api/productos/:id/enable', async (req, res) => {
  if (!isAdminRequest(req)) return respondError(res, 403, 'Forbidden');
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