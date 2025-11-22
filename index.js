// server.js
const express = require('express');
const { createClient } = require('@supabase/supabase-js');
const bcrypt = require('bcrypt');
require('dotenv').config();

const app = express();

// Detectar entorno y origen permitido
const isDev = process.env.NODE_ENV === 'development';
const allowedOrigins = isDev
  ? ['http://localhost:3000']
  : ['https://stock-sync-react.vercel.app'];

// CORS manual: garantizar PATCH y respuesta al preflight
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin && allowedOrigins.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
  }
  res.setHeader('Vary', 'Origin');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,PATCH,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With');

  if (req.method === 'OPTIONS') {
    // Preflight OK: no continuar a rutas
    return res.sendStatus(204);
  }
  next();
});

app.use(express.json());

// Supabase
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);

// Rutas
app.get('/', (_, res) => res.send('Bienvenido a la API de Stock Sync'));
app.get('/api/ping', (_, res) => res.json({ message: 'API funcionando correctamente' }));

// Registro
app.post('/api/registro', async (req, res) => {
  const { nombres, apellidos, cedula, fecha, telefono, email, user, pass, role } = req.body;
  if (!nombres || !apellidos || !cedula || !fecha || !telefono || !email || !user || !pass || !role) {
    return res.status(400).json({ message: 'Faltan campos obligatorios' });
  }
  if (role === 'cliente' && email.endsWith('@stocksync.com')) {
    return res.status(400).json({ message: 'Los clientes no pueden usar correos @stocksync.com' });
  }
  if ((role === 'admin' || role === 'administrador') && !email.endsWith('@stocksync.com')) {
    return res.status(400).json({ message: 'Los administradores deben usar correos @stocksync.com' });
  }
  try {
    const hashedPass = await bcrypt.hash(pass, 10);
    const { error } = await supabase.from('usuarios').insert({
      nombres,
      apellidos,
      cedula,
      fecha_nacimiento: fecha,
      telefono,
      email,
      username: user,
      pass: hashedPass,
      role
    });
    if (error) return res.status(500).json({ message: 'Error al registrar', error: error.message });
    res.json({ message: 'Usuario registrado con éxito' });
  } catch (err) {
    res.status(500).json({ message: 'Error inesperado en el servidor', error: err.message });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  const { user, pass } = req.body;
  if (!user || !pass) return res.status(400).json({ message: 'Faltan credenciales' });
  try {
    const { data, error } = await supabase
      .from('usuarios')
      .select('*')
      .or(`email.eq.${user},username.eq.${user}`)
      .single();
    if (error || !data) return res.status(401).json({ message: 'Usuario no encontrado' });
    const match = await bcrypt.compare(pass, data.pass);
    if (!match) return res.status(401).json({ message: 'Contraseña incorrecta' });
    res.json({ message: 'Login exitoso', user: data });
  } catch (err) {
    res.status(500).json({ message: 'Error inesperado en el servidor', error: err.message });
  }
});

// Listar usuarios
app.get('/api/usuarios', async (_, res) => {
  try {
    const { data, error } = await supabase.from('usuarios').select('*');
    if (error) return res.status(500).json({ message: 'Error al obtener usuarios', error: error.message });
    res.json(data);
  } catch (err) {
    res.status(500).json({ message: 'Error inesperado', error: err.message });
  }
});

// Obtener usuario
app.get('/api/usuarios/:id', async (req, res) => {
  const { id } = req.params;
  try {
    const { data, error } = await supabase.from('usuarios').select('*').eq('id', id).single();
    if (error || !data) return res.status(404).json({ message: 'Usuario no encontrado', error: error?.message });
    res.json(data);
  } catch (err) {
    res.status(500).json({ message: 'Error inesperado', error: err.message });
  }
});

// Actualizar usuario (PUT)
app.put('/api/usuarios/:id', async (req, res) => {
  const { id } = req.params;
  try {
    const { data, error } = await supabase.from('usuarios').update(req.body).eq('id', id).select();
    if (error) return res.status(500).json({ message: 'Error al actualizar usuario', error: error.message });
    res.json({ message: 'Usuario actualizado', data });
  } catch (err) {
    res.status(500).json({ message: 'Error inesperado', error: err.message });
  }
});

// Eliminar usuario (DELETE)
app.delete('/api/usuarios/:id', async (req, res) => {
  const { id } = req.params;
  try {
    const { error } = await supabase.from('usuarios').delete().eq('id', id);
    if (error) return res.status(500).json({ message: 'Error al eliminar usuario', error: error.message });
    res.json({ message: 'Usuario eliminado' });
  } catch (err) {
    res.status(500).json({ message: 'Error inesperado', error: err.message });
  }
});

// Inhabilitar (PATCH) - versión con logging y respuesta detallada (temporal)
app.patch('/api/usuarios/:id/disable', async (req, res) => {
  const { id } = req.params;
  try {
    // 1) comprobar existencia del usuario
    const { data: existing, error: errCheck } = await supabase
      .from('usuarios')
      .select('id')
      .eq('id', id)
      .single();

    if (errCheck) {
      console.error('Error comprobando existencia usuario:', errCheck);
      return res.status(500).json({ message: 'Error comprobando usuario', error: errCheck.message || errCheck });
    }
    if (!existing) {
      return res.status(404).json({ message: 'Usuario no encontrado' });
    }

    // 2) intentar actualizar deleted_at
    const { data, error } = await supabase
      .from('usuarios')
      .update({ deleted_at: new Date().toISOString() })
      .eq('id', id)
      .select();

    if (error) {
      // mostramos el error devuelto por Supabase en la respuesta para que lo veas en la UI
      console.error('Supabase error al inhabilitar usuario:', error);
      return res.status(500).json({ message: 'No se pudo inhabilitar el usuario', error: error.message || error });
    }

    return res.json({ ok: true, data });
  } catch (err) {
    console.error('Excepción en /api/usuarios/:id/disable:', err);
    return res.status(500).json({ message: 'Error inesperado', error: err.message || String(err) });
  }
});

// Reactivar (PATCH)
app.patch('/api/usuarios/:id/enable', async (req, res) => {
  const { id } = req.params;
  try {
    const { data, error } = await supabase
      .from('usuarios')
      .update({ deleted_at: null })
      .eq('id', id)
      .select();
    if (error) return res.status(500).json({ message: 'No se pudo reactivar el usuario', error: error.message });
    res.json({ ok: true, data });
  } catch (err) {
    res.status(500).json({ message: 'Error inesperado', error: err.message });
  }
});

// Puerto
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`API corriendo en puerto ${PORT}`);
});