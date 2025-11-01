// routes/videoPlayerRoutes.js
const express = require('express');
const router = express.Router();
const mysql = require('mysql2');

// Configuración de la base de datos (usar la misma conexión)
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '12345',
  database: 'geotube_db',
});

// Middleware para registrar acceso a videos
const registrarAccesoVideo = async (req, res, next) => {
  const { videoId } = req.params;
  const usuario_id = req.user?.id || null; // Si implementas autenticación
  const ip_origen = req.ip || req.connection.remoteAddress;
  const user_agent = req.get('User-Agent');
  
  // Verificar si la ubicación es válida (dentro de México)
  // Puedes obtener esto del frontend o verificar en el backend
  const es_valido = 1; // Por defecto asumimos válido
  
  try {
    await db.promise().execute(
      'CALL registrar_acceso(?, ?, NULL, NULL, ?, ?, ?)',
      [usuario_id, videoId, es_valido, ip_origen, user_agent]
    );
  } catch (error) {
    console.error('Error registrando acceso:', error);
  }
  next();
};

// Endpoint para obtener información detallada del video
router.get('/video/:videoId', registrarAccesoVideo, async (req, res) => {
  try {
    const { videoId } = req.params;

    // Obtener información del video
    const [videoRows] = await db.promise().execute(
      `SELECT v.*, 
              COUNT(a.id) as total_views,
              COUNT(DISTINCT a.usuario_id) as unique_viewers
       FROM videos v 
       LEFT JOIN accesos a ON v.id = a.video_id 
       WHERE v.youtube_video_id = ? 
       GROUP BY v.id`,
      [videoId]
    );

    if (videoRows.length === 0) {
      return res.status(404).json({ error: 'Video no encontrado' });
    }

    const video = videoRows[0];

    // Obtener videos relacionados (misma ubicación)
    const [relatedRows] = await db.promise().execute(
      `SELECT v.*, 
              COUNT(a.id) as view_count
       FROM videos v 
       LEFT JOIN accesos a ON v.id = a.video_id 
       WHERE v.location_name = ? AND v.youtube_video_id != ?
       GROUP BY v.id 
       ORDER BY view_count DESC 
       LIMIT 10`,
      [video.location_name, videoId]
    );

    // Obtener estadísticas de accesos
    const [statsRows] = await db.promise().execute(
      `SELECT 
         COUNT(*) as total_plays,
         SUM(es_valido) as valid_plays,
         DATE(fecha) as play_date
       FROM accesos 
       WHERE video_id = ? AND fecha >= DATE_SUB(NOW(), INTERVAL 7 DAY)
       GROUP BY DATE(fecha)
       ORDER BY play_date DESC`,
      [video.id]
    );

    res.json({
      video: {
        id: video.youtube_video_id,
        title: video.location_name,
        location: video.location_name,
        coordinates: {
          lat: video.latitude,
          lng: video.longitude
        },
        uploadDate: video.creado_en,
        views: video.total_views,
        uniqueViewers: video.unique_viewers
      },
      relatedVideos: relatedRows,
      statistics: statsRows
    });

  } catch (error) {
    console.error('Error obteniendo video:', error);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// Endpoint para obtener comentarios (si decides implementarlos)
router.get('/video/:videoId/comments', async (req, res) => {
  // Implementar lógica de comentarios si la necesitas
  res.json({ comments: [] }); // Placeholder
});

module.exports = router;