const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2');

// Configuración de la base de datos
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '12345',
  database: 'geotube_db',
});

const JWT_SECRET = 'tu_clave_secreta_jwt_muy_segura_aqui_12345';

// Middleware para verificar token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Token de acceso requerido' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Token inválido' });
    }
    req.user = user;
    next();
  });
};

// Registro de usuario
router.post('/register', async (req, res) => {
  try {
    const { nombre, email, password } = req.body;

    if (!nombre || !email || !password) {
      return res.status(400).json({ error: 'Todos los campos son requeridos' });
    }

    // Verificar si el usuario ya existe
    const [existingUsers] = await db.promise().execute(
      'SELECT id FROM usuarios WHERE email = ?',
      [email]
    );

    if (existingUsers.length > 0) {
      return res.status(400).json({ error: 'El usuario ya existe' });
    }

    // Hash de la contraseña
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Insertar nuevo usuario
    const [result] = await db.promise().execute(
      'INSERT INTO usuarios (nombre, email, password) VALUES (?, ?, ?)',
      [nombre, email, hashedPassword]
    );

    // Generar token
    const token = jwt.sign(
      { id: result.insertId, email: email },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.status(201).json({
      message: 'Usuario registrado exitosamente',
      token,
      user: {
        id: result.insertId,
        nombre,
        email
      }
    });

  } catch (error) {
    console.error('Error en registro:', error);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// Login de usuario
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email y contraseña son requeridos' });
    }

    // Buscar usuario
    const [users] = await db.promise().execute(
      'SELECT * FROM usuarios WHERE email = ?',
      [email]
    );

    if (users.length === 0) {
      return res.status(400).json({ error: 'Credenciales inválidas' });
    }

    const user = users[0];

    // Verificar contraseña
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(400).json({ error: 'Credenciales inválidas' });
    }

    // Generar token
    const token = jwt.sign(
      { id: user.id, email: user.email },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({
      message: 'Login exitoso',
      token,
      user: {
        id: user.id,
        nombre: user.nombre,
        email: user.email,
        foto: user.foto,
        google_id: user.google_id
      }
    });

  } catch (error) {
    console.error('Error en login:', error);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// Verificar token
router.get('/verify', authenticateToken, (req, res) => {
  res.json({ 
    valid: true, 
    user: req.user 
  });
});

// Obtener perfil de usuario
router.get('/profile', authenticateToken, async (req, res) => {
  try {
    const [users] = await db.promise().execute(
      'SELECT id, nombre, email, foto, google_id, creado_en FROM usuarios WHERE id = ?',
      [req.user.id]
    );

    if (users.length === 0) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }

    // Obtener estadísticas del usuario
    const [stats] = await db.promise().execute(
      `SELECT COUNT(*) as total_videos, 
              COUNT(DISTINCT video_id) as videos_unicos,
              MAX(fecha) as ultimo_acceso
       FROM accesos 
       WHERE usuario_id = ?`,
      [req.user.id]
    );

    res.json({
      user: users[0],
      statistics: stats[0]
    });

  } catch (error) {
    console.error('Error obteniendo perfil:', error);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// Registrar acceso a video
router.post('/register-video-access', authenticateToken, async (req, res) => {
  const { youtube_video_id, titulo, location_name, latitude, longitude, duracion_reproduccion = 0 } = req.body;

  try {
    // Buscar o crear el video en la base de datos
    let [videos] = await db.promise().execute(
      'SELECT id FROM videos WHERE youtube_video_id = ?', 
      [youtube_video_id]
    );

    let videoId;
    if (videos.length === 0) {
      // Insertar nuevo video
      const [result] = await db.promise().execute(
        'INSERT INTO videos (youtube_video_id, location_name, latitude, longitude, titulo) VALUES (?, ?, ?, ?, ?)',
        [youtube_video_id, location_name, latitude, longitude, titulo || 'Video de YouTube']
      );
      videoId = result.insertId;
    } else {
      videoId = videos[0].id;
    }

    // Registrar el acceso
    await db.promise().execute(
      'INSERT INTO accesos (usuario_id, video_id, es_valido, ip_origen, user_agent, duracion_reproduccion) VALUES (?, ?, 1, ?, ?, ?)',
      [req.user.id, videoId, req.ip, req.get('User-Agent') || 'Unknown', duracion_reproduccion]
    );

    // Actualizar contador de vistas del video
    await db.promise().execute(
      'UPDATE videos SET vistas_totales = vistas_totales + 1 WHERE id = ?',
      [videoId]
    );

    res.json({ success: true, message: 'Acceso registrado correctamente' });
  } catch (error) {
    console.error('Error registrando acceso:', error);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// Obtener historial de videos vistos por usuario
router.get('/user-history/:userId', authenticateToken, async (req, res) => {
  const { userId } = req.params;

  try {
    // Verificar que el usuario solo pueda ver su propio historial
    if (parseInt(userId) !== req.user.id) {
      return res.status(403).json({ error: 'No autorizado' });
    }

    const [history] = await db.promise().execute(`
      SELECT 
        v.youtube_video_id,
        v.titulo,
        v.location_name,
        v.latitude,
        v.longitude,
        a.fecha,
        a.duracion_reproduccion,
        v.vistas_totales
      FROM accesos a
      JOIN videos v ON a.video_id = v.id
      WHERE a.usuario_id = ?
      ORDER BY a.fecha DESC
      LIMIT 50
    `, [userId]);

    res.json(history);
  } catch (error) {
    console.error('Error obteniendo historial:', error);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// Limpiar historial de usuario
router.delete('/clear-history/:userId', authenticateToken, async (req, res) => {
  const { userId } = req.params;

  try {
    // Verificar que el usuario solo pueda limpiar su propio historial
    if (parseInt(userId) !== req.user.id) {
      return res.status(403).json({ error: 'No autorizado' });
    }

    await db.promise().execute(
      'DELETE FROM accesos WHERE usuario_id = ?',
      [userId]
    );

    res.json({ success: true, message: 'Historial limpiado correctamente' });
  } catch (error) {
    console.error('Error limpiando historial:', error);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// Cambiar contraseña
router.put('/change-password', authenticateToken, async (req, res) => {
  const { currentPassword, newPassword } = req.body;

  try {
    // Obtener usuario actual
    const [users] = await db.promise().execute(
      'SELECT password FROM usuarios WHERE id = ?',
      [req.user.id]
    );

    if (users.length === 0) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }

    const user = users[0];

    // Verificar contraseña actual
    const validPassword = await bcrypt.compare(currentPassword, user.password);
    if (!validPassword) {
      return res.status(400).json({ error: 'Contraseña actual incorrecta' });
    }

    // Hash de la nueva contraseña
    const saltRounds = 10;
    const hashedNewPassword = await bcrypt.hash(newPassword, saltRounds);

    // Actualizar contraseña
    await db.promise().execute(
      'UPDATE usuarios SET password = ? WHERE id = ?',
      [hashedNewPassword, req.user.id]
    );

    res.json({ success: true, message: 'Contraseña actualizada correctamente' });
  } catch (error) {
    console.error('Error cambiando contraseña:', error);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// Actualizar foto de perfil
router.put('/update-photo', authenticateToken, async (req, res) => {
  const { foto } = req.body;

  try {
    await db.promise().execute(
      'UPDATE usuarios SET foto = ? WHERE id = ?',
      [foto, req.user.id]
    );

    // Obtener usuario actualizado
    const [users] = await db.promise().execute(
      'SELECT id, nombre, email, foto, google_id FROM usuarios WHERE id = ?',
      [req.user.id]
    );

    res.json({ 
      success: true, 
      message: 'Foto actualizada correctamente',
      user: users[0]
    });
  } catch (error) {
    console.error('Error actualizando foto:', error);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

module.exports = router;