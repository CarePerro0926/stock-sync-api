// middlewares/authenticateJwt.js
import jwt from 'jsonwebtoken';

const JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_API_TOKEN = process.env.VITE_ADMIN_API_TOKEN; // opcional, solo para debug seguro

export default function authenticateJwt(req, res, next) {
  try {
    if (!JWT_SECRET) {
      console.error('JWT_SECRET no definido en el entorno');
      return res.status(500).json({ error: 'Server configuration error' });
    }

    // DEBUG TEMPORAL - imprimir información mínima para depuración
    console.log('--- AUTH CHECK START ---');
    console.log('Request method:', req.method, 'Request path:', req.path);
    console.log('Headers Authorization:', req.headers.authorization || '<no authorization header>');
    console.log('All raw headers keys:', Object.keys(req.headers).join(', '));

    // Soportar Authorization header o cookie "token"
    const authHeader = req.headers.authorization || req.headers.Authorization;
    const tokenFromHeader = authHeader && authHeader.startsWith('Bearer ') ? authHeader.split(' ')[1] : null;
    const tokenFromCookie = req.cookies && req.cookies.token ? req.cookies.token : null;
    const token = tokenFromHeader || tokenFromCookie;

    if (!token) {
      console.log('--- AUTH CHECK END ---');
      return res.status(401).json({ error: 'No token provided' });
    }

    // Si el token coincide exactamente con la admin key, permitir acceso administrativo temporalmente
    if (ADMIN_API_TOKEN && token === ADMIN_API_TOKEN) {
      req.user = { id: 'admin-key', email: null, role: 'administrador', tokenPayload: null, raw: null, via: 'admin-key' };
      console.log('authenticateJwt ok user:', { id: req.user.id, role: req.user.role, via: req.user.via });
      console.log('--- AUTH CHECK END ---');
      return next();
    }

    // Intentar decodificar el token para ver si es JWT y mostrar payload mínimo
    try {
      const parts = token.split('.');
      if (parts.length === 3) {
        const payloadJson = Buffer.from(parts[1], 'base64').toString('utf8');
        console.log('Decoded JWT payload (raw):', payloadJson);
      } else {
        console.log('Token present but not JWT format (no 3 parts)');
      }
    } catch (err) {
      console.log('Error decoding token payload:', err.message);
    }

    let payload;
    try {
      payload = jwt.verify(token, JWT_SECRET);
    } catch (err) {
      if (err.name === 'TokenExpiredError') {
        console.log('authenticateJwt -> Token expired');
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

    // Permitir rol 'auditor' para la ruta /api/audit-logs (solo lectura)
    // Esto evita el 403 cuando el token tiene role: 'auditor'
    if (req.path && req.path.startsWith('/api/audit-logs')) {
      const allowed = ['administrador', 'auditor'];
      if (!allowed.includes(req.user.role)) {
        console.log('authenticateJwt -> Forbidden: insufficient role for audit-logs', req.user.role);
        return res.status(403).json({ success: false, message: 'Forbidden: insufficient role' });
      }
    }

    // Log breve (no imprimir payload completo en producción)
    console.log('authenticateJwt ok user:', { id: req.user.id, role: req.user.role });
    console.log('--- AUTH CHECK END ---');

    return next();
  } catch (err) {
    console.error('authenticateJwt unexpected error:', err);
    return res.status(401).json({ error: 'Authentication failed' });
  }
}
