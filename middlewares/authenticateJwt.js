// middlewares/authenticateJwt.js
import jwt from 'jsonwebtoken';

const JWT_SECRET = process.env.JWT_SECRET;

export default function authenticateJwt(req, res, next) {
  try {
    if (!JWT_SECRET) {
      console.error('JWT_SECRET no definido en el entorno');
      return res.status(500).json({ error: 'Server configuration error' });
    }

    // Soportar Authorization header o cookie "token"
    const authHeader = req.headers.authorization || req.headers.Authorization;
    const tokenFromHeader = authHeader && authHeader.startsWith('Bearer ') ? authHeader.split(' ')[1] : null;
    const tokenFromCookie = req.cookies && req.cookies.token ? req.cookies.token : null;
    const token = tokenFromHeader || tokenFromCookie;

    if (!token) {
      return res.status(401).json({ error: 'No token provided' });
    }

    let payload;
    try {
      payload = jwt.verify(token, JWT_SECRET);
    } catch (err) {
      // Manejar expiración por separado para mensajes más claros
      if (err.name === 'TokenExpiredError') {
        return res.status(401).json({ error: 'Token expired' });
      }
      console.error('authenticateJwt verify error:', err.message || err);
      return res.status(401).json({ error: 'Invalid token' });
    }

    const role =
      payload.role ||
      payload.user_role ||
      (payload['https://hasura.io/jwt/claims'] && payload['https://hasura.io/jwt/claims']['x-hasura-role']) ||
      (payload['https://supabase.io/jwt/claims'] && payload['https://supabase.io/jwt/claims'].role) ||
      null;

    req.user = {
      id: payload.sub || payload.user_id || payload.uid || null,
      email: payload.email || null,
      role: role || 'anonymous',
      tokenPayload: payload,
      raw: payload
    };

    // Log breve (no imprimir payload completo en producción)
    console.log('authenticateJwt ok user:', { id: req.user.id, role: req.user.role });

    return next();
  } catch (err) {
    console.error('authenticateJwt unexpected error:', err);
    return res.status(401).json({ error: 'Authentication failed' });
  }
}
