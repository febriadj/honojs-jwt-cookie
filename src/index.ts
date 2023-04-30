import { Hono } from 'hono';
import { v4 as uuidv4 } from 'uuid';
import bcrypt from 'bcryptjs';
import setError from './helpers/setError';

export type IEnv = {
  D1: D1Database;
};

const app = new Hono<{ Bindings: IEnv }>();

app.get('/', (c) => c.text('Hello Hono!'));

app.post('/register', async (c) => {
  try {
    const { email, fullname, password } = await c.req.json();

    const userExists = await c.env.D1.prepare(
      'SELECT * FROM users WHERE email = ?'
    )
      .bind(email)
      .first();

    if (userExists) {
      throw new Error('Email already in use');
    }

    const hash = await bcrypt.hash(password, await bcrypt.genSalt(10));
    const stmt = await c.env.D1.prepare(
      'INSERT INTO users (id, email, fullname, password) VALUES(?, ?, ?, ?)'
    )
      .bind(uuidv4(), email, fullname, hash)
      .run();

    return c.json({ success: true, meta: stmt.meta });
  } catch (err) {
    const error = setError((obj) => {
      if (err instanceof Error) {
        obj['message'] = err.message;
        obj['code'] = 409;
      }
    });

    c.status(error.code);

    return c.json(error);
  }
});

export default app;
