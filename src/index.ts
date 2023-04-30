import { Hono } from 'hono';
import { sign } from 'hono/utils/jwt/jwt';
import { v4 as uuidv4 } from 'uuid';
import bcrypt from 'bcryptjs';
import setError from './helpers/setError';

export type IEnv = {
  D1: D1Database;
  JWT_SECRET: string;
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

app.post('/login', async (c) => {
  try {
    const { email, password } = await c.req.json();

    const stmt: { id: string; email: string; password: string } =
      await c.env.D1.prepare(
        'SELECT id, email, password FROM users WHERE email = ?'
      )
        .bind(email)
        .first();

    if (!stmt || !(await bcrypt.compare(password, stmt.password))) {
      throw new Error(!stmt ? 'User does not exist' : 'Invalid password');
    }

    // Generate JWT token
    const token = await sign({ id: stmt.id }, c.env.JWT_SECRET);

    // Store JWT token in cookies
    c.cookie('accessToken', token, { httpOnly: true });

    return c.json({ success: true });
  } catch (err) {
    const error = setError((obj) => {
      if (err instanceof Error) {
        obj['message'] = err.message;
        obj['code'] = 401;
      }
    });

    c.status(error.code);
    return c.json(error);
  }
});

export default app;
