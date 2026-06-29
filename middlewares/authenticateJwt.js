// middlewares/authenticateJwt.js
import jwt from 'jsonwebtoken';
const JWT_SECRET = process.env.JWT_SECRET;

export default function authenticateJwt(req, res, next) {
  try {
    const auth = req.headers.authorization || req.headers.Authorization;
    if (!auth || !auth.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'No token provided' });
    }
    const token = auth.split(' ')[1];
    const payload = jwt.verify(token, JWT_SECRET);

    const role =
      payload.role ||
      payload.user_role ||
      (payload['https://hasura.io/jwt/claims'] && payload['https://hasura.io/jwt/claims']['x-hasura-role']) ||
      (payload['https://supabase.io/jwt/claims'] && payload['https://supabase.io/jwt/claims'].role);

    req.user = {
      id: payload.sub || payload.user_id || payload.uid || null,
      email: payload.email || null,
      role: role || 'anonymous',
      raw: payload
    };

    console.log('authenticateJwt req.user:', JSON.stringify(req.user));
    return next();
  } catch (err) {
    console.error('authenticateJwt error:', err.message || err);
    return res.status(401).json({ error: 'Invalid token' });
  }
}
