// server.js (o index.js)
const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');
const bcrypt = require('bcrypt');
require('dotenv').config();

const app = express();

// Detectar entorno
const isDev = process.env.NODE_ENV === 'development';

// Orígenes permitidos según entorno
const allowedOrigins = isDev
  ? ['http://localhost:3000']
  : ['https://stock-sync-react.vercel.app'];

// CORS: permitir PATCH y responder preflight
app.use(cors({
  origin: allowedOrigins,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.options('*', cors());

app.use(express.json());

// Conexión a Supabase (usa la key que tengas configurada)
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);

// Ruta raíz
app.get('/', (req, res) => {
  res.send('Bienvenido a la API de Stock Sync');
});

// Ruta de prueba
app.get('/api/ping', (req, res) => {
  res.json({ message: 'API funcionando correctamente' });
});

// Registro de usuario
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

    const { data, error } = await supabase.from('usuarios').insert({
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

    if (error) {
      console.error('Error Supabase:', error);
      return res.status(500).json({ message: 'Error al registrar', error: error.message });
    }

    res.json({ message: 'Usuario registrado con éxito' });
  } catch (err) {
    console.error('Error inesperado:', err);
    res.status(500).json({ message: 'Error inesperado en el servidor', error: err.message });
  }
});

// Login de usuario
app.post('/api/login', async (req, res) => {
  const { user, pass } = req.body;

  if (!user || !pass) {
    return res.status(400).json({ message: 'Faltan credenciales' });
  }

  try {
    const { data, error } = await supabase
      .from('usuarios')
      .select('*')
      .or(`email.eq.${user},username.eq.${user}`)
      .single();

    if (error || !data) {
      return res.status(401).json({ message: 'Usuario no encontrado' });
    }

    const match = await bcrypt.compare(pass, data.pass);
    if (!match) {
      return res.status(401).json({ message: 'Contraseña incorrecta' });
    }

    res.json({ message: 'Login exitoso', user: data });
  } catch (err) {
    console.error('Error inesperado en login:', err);
    res.status(500).json({ message: 'Error inesperado en el servidor', error: err.message });
  }
});

// Obtener todos los usuarios
app.get('/api/usuarios', async (req, res) => {
  try {
    const { data, error } = await supabase.from('usuarios').select('*');
    if (error) {
      console.error('Error al obtener usuarios:', error);
      return res.status(500).json({ message: 'Error al obtener usuarios', error: error.message });
    }
    res.json(data);
  } catch (err) {
    console.error('Error inesperado /api/usuarios:', err);
    res.status(500).json({ message: 'Error inesperado', error: err.message });
  }
});

// Obtener usuario por ID
app.get('/api/usuarios/:id', async (req, res) => {
  const { id } = req.params;
  try {
    const { data, error } = await supabase
      .from('usuarios')
      .select('*')
      .eq('id', id)
      .single();

    if (error || !data) {
      return res.status(404).json({ message: 'Usuario no encontrado', error: error?.message });
    }
    res.json(data);
  } catch (err) {
    console.error('Error inesperado /api/usuarios/:id:', err);
    res.status(500).json({ message: 'Error inesperado', error: err.message });
  }
});

// Actualizar usuario por ID (PUT)
app.put('/api/usuarios/:id', async (req, res) => {
  const { id } = req.params;
  const updates = req.body;

  try {
    const { data, error } = await supabase
      .from('usuarios')
      .update(updates)
      .eq('id', id)
      .select();

    if (error) {
      return res.status(500).json({ message: 'Error al actualizar usuario', error: error.message });
    }
    res.json({ message: 'Usuario actualizado', data });
  } catch (err) {
    console.error('Error inesperado PUT /api/usuarios/:id:', err);
    res.status(500).json({ message: 'Error inesperado', error: err.message });
  }
});

// Eliminar usuario por ID
app.delete('/api/usuarios/:id', async (req, res) => {
  const { id } = req.params;
  try {
    const { error } = await supabase
      .from('usuarios')
      .delete()
      .eq('id', id);

    if (error) {
      return res.status(500).json({ message: 'Error al eliminar usuario', error: error.message });
    }

    res.json({ message: 'Usuario eliminado' });
  } catch (err) {
    console.error('Error inesperado DELETE /api/usuarios/:id:', err);
    res.status(500).json({ message: 'Error inesperado', error: err.message });
  }
});

// Inhabilitar usuario (soft delete): PATCH /disable
app.patch('/api/usuarios/:id/disable', async (req, res) => {
  const { id } = req.params;
  try {
    const payload = { deleted_at: new Date().toISOString() };
    const { data, error } = await supabase
      .from('usuarios')
      .update(payload)
      .eq('id', id)
      .select();

    if (error) {
      console.error('Error al inhabilitar:', error);
      return res.status(500).json({ message: 'No se pudo inhabilitar el usuario', error: error.message });
    }

    res.json({ ok: true, data });
  } catch (err) {
    console.error('Error inesperado PATCH /disable:', err);
    res.status(500).json({ message: 'Error inesperado', error: err.message });
  }
});

// Reactivar usuario (soft delete): PATCH /enable
app.patch('/api/usuarios/:id/enable', async (req, res) => {
  const { id } = req.params;
  try {
    const payload = { deleted_at: null };
    const { data, error } = await supabase
      .from('usuarios')
      .update(payload)
      .eq('id', id)
      .select();

    if (error) {
      console.error('Error al reactivar:', error);
      return res.status(500).json({ message: 'No se pudo reactivar el usuario', error: error.message });
    }

    res.json({ ok: true, data });
  } catch (err) {
    console.error('Error inesperado PATCH /enable:', err);
    res.status(500).json({ message: 'Error inesperado', error: err.message });
  }
});

// Puerto dinámico para Render
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`API corriendo en puerto ${PORT}`);
});