import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { sign } from 'hono/utils/jwt/jwt';
import { jwt } from 'hono/jwt';
import { v4 as uuidv4 } from 'uuid';
import bcrypt from 'bcryptjs';
import setError from './helpers/setError';

export type IEnv = {
  D1: D1Database;
  CLIENT_ORIGIN: string;
  JWT_SECRET: string;
};

const app = new Hono<{ Bindings: IEnv }>();

app.use('*', async (c, next) => {
  const setCors = await cors({
    origin: ['http://localhost:5173', c.env.CLIENT_ORIGIN],
    credentials: true,
  });
  return setCors(c, next);
});

app.use('/users/*', async (c, next) => {
  const setJwt = await jwt({
    cookie: 'accessToken',
    secret: c.env.JWT_SECRET,
  });
  return setJwt(c, next);
});

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

    c.header('Access-Control-Allow-Credentials', 'true');
    c.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE');
    c.header('Access-Control-Allow-Headers', '*');
    c.header(
      'Access-Control-Allow-Origin',
      `http://localhost:5173, ${c.env.CLIENT_ORIGIN}`
    );

    // Generate JWT token
    const accessToken = await sign({ id: stmt.id }, c.env.JWT_SECRET);

    c.cookie('accessToken', accessToken, {
      expires: new Date(new Date().setDate(new Date().getDate() + 7)),
      httpOnly: true,
      sameSite: 'None',
      secure: true,
    });

    return c.json({ success: true, data: { userId: stmt.id } });
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

app.get('/users/:id', async (c) => {
  try {
    const id = c.req.param('id');

    const stmt = await c.env.D1.prepare('SELECT * FROM users WHERE id = ?')
      .bind(id)
      .first();

    return c.json({ success: true, data: stmt });
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
