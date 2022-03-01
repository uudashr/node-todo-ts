import express, { NextFunction, Request, Response, RequestHandler } from 'express';
import cookieParser from 'cookie-parser';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import crypto from'crypto';

const app = express();

const PORT = 3500;
const SECRET = 'secret';
// const COOKIE_USER_FINGERPRINT = "__Secure-Fgp" // for https
const COOKIE_USER_FINGERPRINT = "Fgp" // for http

let accounts = [
  { email: 'uudashr@gmail.com', name: 'Nuruddin Ashr', password: 'secret' },
];

let taskSequenceId = 3;
let tasks = [
  { id: 1, name: 'Follow up SRE Support', completed: true, ownerId: 'uudashr@gmail.com' },
  { id: 2, name: 'Read IAM Service Spec', ownerId: 'uudashr@gmail.com' },
  { id: 3, name: 'Research chat protocols', ownerId: 'uudashr@gmail.com' },
];

app.use(express.json());
app.use(express.text());
app.use(cors({
  origin: true,
  credentials: true
}));
app.use(cookieParser());
app.use(delay(500));

interface RequestWithAuth extends Request {
  authenticatedId?: string
}

interface AuthenticatedRequest extends Request {
  authenticatedId: string
}

function delay(ms): RequestHandler {
  return (req: Request, res: Response, next: NextFunction) => {
    setTimeout(() => next(), ms);
  };
}

app.get('/', (req: Request, res: Response) => {
  res.send('Hello World!');
});

app.get('/dev/accounts', (req: Request, res: Response) => {
  res.json(accounts);
});

function errorPayload(code, message) {
  return { 
    error: { code, message } 
  };
}

app.post('/register', (req: Request, res: Response) => {
  const { email, name, password } = req.body;
  const acc = accounts.find(acc => acc.email === email);
  if (acc) {
    return res.status(409).json(errorPayload('email_used',  'Email already used'));
  }

  accounts = [...accounts, { email, name, password }];
  return res.status(201).send('created');
});

function buildTokenPayload(type) {
  if (type === 'web') {
    const userFingerprint = crypto.randomBytes(50).toString('hex');
    return { userFingerprint };
  }

  return {};
}

app.post('/authenticate', (req: Request, res: Response) => {
  const { email, password, type } = req.body;

  const acc = accounts.find(acc => acc.email === email && acc.password === password);
  if (!acc) {
    return res.status(401).json(errorPayload('invalid_credentials', 'Invalid username or password'));
  }

  const payload = buildTokenPayload(type);
  const token = jwt.sign(payload, SECRET, {
    subject: acc.email,
    expiresIn: '60m'
  });

  if (payload.userFingerprint) {
    // res.cookie(COOKIE_USER_FINGERPRINT, payload.userFingerprint, { sameSite: 'strict', httpOnly: true, secure: true });
    res.cookie(COOKIE_USER_FINGERPRINT, payload.userFingerprint, { sameSite: 'strict', httpOnly: true });
  }

  return res.status(201).json({ token });
});

function authChecks(req: RequestWithAuth, res: Response, next: NextFunction) {
  const authHeader = req.header('Authorization')
  if (!authHeader?.startsWith('Bearer ')) {
    return res.status(401).send('unauthorized');
  }

  const accessToken = authHeader.substring('Bearer '.length)
  try {
    const payload = jwt.verify(accessToken, SECRET);

    if (payload.userFingerprint && (payload.userFingerprint !== req.cookies[COOKIE_USER_FINGERPRINT])) {
      return res.status(401).send('unauthorized');
    }

    req.authenticatedId = payload.sub;

    next();
  } catch (e) {
    return res.status(401).send(e.message);
  }
}

app.get('/userinfo', authChecks, (req: AuthenticatedRequest, res: Response) => {
  const acc = accounts.find(acc => acc.email === req.authenticatedId)
  if (!acc) {
    return res.status(404).send('not found');
  }

  const { email, name } = acc;
  res.json({ email, name });
});

app.get('/tasks', authChecks, (req: AuthenticatedRequest, res: Response) => {
  const queryCompleted = req.query.completed;
  const filteredTasks = tasks.filter(task => {
    return task.ownerId === req.authenticatedId
  }).filter(task => {
    if (queryCompleted === 'true') {
      return task.completed;
    }

    if (queryCompleted === 'false') {
      const completed = task.completed || false
      return !completed;
    }

    return true;
  }).map(({ id, name, completed }) => ({ id, name, completed }));

  res.json(filteredTasks);
});

app.post('/tasks', authChecks, (req: AuthenticatedRequest, res: Response) => {
  const { name } = req.body;
  const id = ++taskSequenceId;
  tasks = [...tasks, { id, name, ownerId: req.authenticatedId }];
  res.status(201).send('created');
});

app.get('/tasks/:id', authChecks, (req: AuthenticatedRequest, res: Response) => {
  const paramId = req.params.id;
  const found = tasks.find(task => (
    task.id === Number(paramId) &&
    task.ownerId === req.authenticatedId
  ));

  if (!found) {
    return res.status(404).send('not found');
  }

  const { id, name, completed } = found;
  return res.json({ id, name, completed });
});

app.put('/tasks/:id', authChecks, (req: AuthenticatedRequest, res: Response) => {
  const paramId = req.params.id;
  const found = tasks.find(task => (
    task.id === Number(paramId) &&
    task.ownerId === req.authenticatedId
  ));

  if (!found) {
    return res.status(404).send('not found');
  }

  const { name, completed } = req.body;
  tasks = tasks.map(task => {
    if (task.id == found.id) {
      return { ...task, name, completed }
    }

    return task
  })

  return res.status(204).send('no content');
});

app.delete('/tasks/:id', authChecks, (req: AuthenticatedRequest, res: Response) => {
  const paramId = req.params.id;
  const found = tasks.find(task => (
    task.id === Number(paramId) && 
    task.ownerId === req.authenticatedId
  ));

  if (!found) {
    return res.status(404).send('not found');
  }

  tasks = tasks.filter(task => task.id !== found.id);
  return res.status(204).send('no content');
});

app.put('/tasks/:id/name', authChecks, (req: AuthenticatedRequest, res: Response) => {
  const paramId = req.params.id;
  const nameValue = req.body;
  if (!nameValue) {
    return res.status(400).json(errorPayload('empty_name', 'Name is empty'));
  }

  const found = tasks.find(task => (
    task.id === Number(paramId) && task.ownerId === req.authenticatedId
  ));
  if (!found) {
    return res.status(404).send('not found');
  }

  tasks = tasks.map(task => {
    if (task.id === found.id) {
      return  { ...task, name: nameValue };
    }

    return task;
  })
  return res.status(204).send('no content');
});

app.put('/tasks/:id/completed', authChecks, (req: AuthenticatedRequest, res: Response) => {
  const paramId = req.params.id;
  const found = tasks.find(task => (
    task.id === Number(paramId) && task.ownerId === req.authenticatedId
  ));
  if (!found) {
    return res.status(404).send('not found');
  }


  tasks = tasks.map(task => {
    if (task.id === found.id) {
      return  { ...task, completed: true };
    }

    return task;
  })
  return res.status(204).send('no content');
});

app.delete('/tasks/:id/completed', authChecks, (req: AuthenticatedRequest, res: Response) => {
  const paramId = req.params.id;
  const found = tasks.find(task => (
    task.id === Number(paramId) && task.ownerId === req.authenticatedId
  ));
  if (!found) {
    return res.status(404).send('not found');
  }

  tasks = tasks.map(task => {
    if (task.id === found.id) {
      const { completed, ...taskRest } = task;
      return taskRest;
    }

    return task;
  })
  return res.status(204).send('no content');
});

app.listen(PORT, () => {
  console.log(`Node Todo listening on port ${PORT}`);
});