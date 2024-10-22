import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';

interface JwtPayload {
  username: string;
}

export const authenticateToken = (req: Request, res: Response, next: NextFunction) => {
  // TODO: verify the token exists and add the user data to the request object
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).send('Unauthorized');
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET_KEY as string) as JwtPayload;
    req.user = decoded;
    return next();
  } catch (err) {
    return res.status(403).send('Forbidden');
  }
};