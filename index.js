// index.js
const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

// Verificación de variables de entorno
if (!process.env.SUPABASE_URL || !process.env.SUPABASE_KEY) {
  console.error('❌ Faltan variables de entorno: SUPABASE_URL o SUPABASE_KEY');
  process.exit(1);
}

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

// Ruta de diagnóstico de entorno
app.get('/api/env-check', (req, res) => {
  res.json({
    SUPABASE_URL: process.env.SUPABASE_URL ? '✅ definida' : '❌ faltante',
    SUPABASE_KEY: process.env.SUPABASE_KEY ? '✅ definida' : '❌ faltante'
  });
});

// Ruta para registrar usuario
app.post('/api/registro', async (req, res) => {
  const { nombres, apellidos, cedula, fecha, telefono, email, user, pass, role } = req.body;

  console.log('📥 Datos recibidos:', req.body);

  // Validación de campos obligatorios
  if (!nombres || !apellidos || !cedula || !fecha || !telefono || !email || !user || !pass || !role) {
    return res.status(400).json({ message: 'Faltan campos obligatorios' });
  }

  try {
    const { data, error } = await supabase.from('usuarios').insert({
      nombres,
      apellidos,
      cedula,
      fecha_nacimiento: fecha,
      telefono,
      email,
      username: user,
      pass,
      role
    });

    if (error) {
      console.error('❌ Error Supabase:', error);
      return res.status(500).json({ message: 'Error al registrar', error: error.message });
    }

    console.log('✅ Usuario registrado:', data);
    res.json({ message: 'Usuario registrado con éxito' });
  } catch (err) {
    console.error('❌ Error inesperado:', err);
    res.status(500).json({ message: 'Error inesperado en el servidor', error: err.message });
  }
});

// Ruta para obtener todos los usuarios
app.get('/api/usuarios', async (req, res) => {
  try {
    const { data, error } = await supabase.from('usuarios').select('*');

    if (error) {
      console.error('❌ Error al obtener usuarios:', error);
      return res.status(500).json({ message: 'Error al obtener usuarios', error: error.message });
    }

    res.json(data);
  } catch (err) {
    console.error('❌ Error inesperado al obtener usuarios:', err);
    res.status(500).json({ message: 'Error inesperado en el servidor', error: err.message });
  }
});

// Puerto dinámico para Render
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`🚀 API corriendo en puerto ${PORT}`);
});