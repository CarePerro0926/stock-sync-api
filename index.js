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

// CORS dinámico
app.use(cors({
  origin: allowedOrigins,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type']
}));
app.use(express.json());

// Conexión a Supabase
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

  if (role === 'admin' && !email.endsWith('@stocksync.com')) {
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
  const { data, error } = await supabase.from('usuarios').select('*');

  if (error) {
    console.error('Error al obtener usuarios:', error);
    return res.status(500).json({ message: 'Error al obtener usuarios', error: error.message });
  }

  res.json(data);
});

// Obtener usuario por ID
app.get('/api/usuarios/:id', async (req, res) => {
  const { id } = req.params;

  const { data, error } = await supabase
    .from('usuarios')
    .select('*')
    .eq('id', id)
    .single();

  if (error || !data) {
    return res.status(404).json({ message: 'Usuario no encontrado', error: error?.message });
  }

  res.json(data);
});

// Actualizar usuario por ID
app.put('/api/usuarios/:id', async (req, res) => {
  const { id } = req.params;
  const updates = req.body;

  const { data, error } = await supabase
    .from('usuarios')
    .update(updates)
    .eq('id', id)
    .select();

  if (error) {
    return res.status(500).json({ message: 'Error al actualizar usuario', error: error.message });
  }

  res.json({ message: 'Usuario actualizado', data });
});

// Eliminar usuario por ID
app.delete('/api/usuarios/:id', async (req, res) => {
  const { id } = req.params;

  const { error } = await supabase
    .from('usuarios')
    .delete()
    .eq('id', id);

  if (error) {
    return res.status(500).json({ message: 'Error al eliminar usuario', error: error.message });
  }

  res.json({ message: 'Usuario eliminado' });
});

// Puerto dinámico para Render
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`API corriendo en puerto ${PORT}`);
});