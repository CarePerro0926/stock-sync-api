// index.js
const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

// Conexión a Supabase
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);

// Ruta de prueba
app.get('/api/ping', (req, res) => {
  res.json({ message: 'API funcionando correctamente' });
});

// Ruta para registrar usuario
app.post('/api/registro', async (req, res) => {
  const { nombres, apellidos, cedula, fecha, email, user, pass, role } = req.body;

  if (!nombres || !apellidos || !cedula || !fecha || !email || !user || !pass || !role) {
    return res.status(400).json({ message: 'Faltan campos obligatorios' });
  }

  const { data, error } = await supabase.from('usuarios').insert({
    nombres,
    apellidos,
    cedula,
    fecha_nacimiento: fecha,
    email,
    username: user,
    pass,
    role
  });

  if (error) {
    return res.status(500).json({ message: 'Error al registrar', error: error.message });
  }

  res.json({ message: 'Usuario registrado con éxito' });
});

app.listen(3001, () => {
  console.log('API corriendo en http://localhost:3001');
});