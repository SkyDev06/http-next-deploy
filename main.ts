import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import path from 'path';
import fs from 'fs';

const app = express();
const PORT = 3000;
// sendResponse
function sendResponse(req: Request, res: Response, data: any) {
  const userAgent = req.headers['user-agent'] || '';

  const isIOS = /iphone|ipad|ios/i.test(userAgent);

  if (isIOS) {
    // iOS butuh JSON proper
    res.setHeader('Content-Type', 'application/json');
    return res.json(data);
  } else {
    // Windows / Android pakai raw string
    return res.send(JSON.stringify(data));
  }
}

app.set('trust proxy', 1);
app.disable('x-powered-by');

// ================= MIDDLEWARE =================
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors());

const limiter = rateLimit({
  windowMs: 60_000,
  max: 50,
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(limiter);

// ================= STATIC =================
app.use(express.static(path.join(process.cwd(), 'public')));

// ================= LOGGER =================
app.use((req: Request, res: Response, next: NextFunction) => {
  const clientIp =
    (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() ||
    req.socket.remoteAddress ||
    'unknown';

  console.log(`[REQ] ${req.method} ${req.path} → ${clientIp}`);
  next();
});

// ================= ROOT =================
app.get('/', (_req: Request, res: Response) => {
  res.send('Login Server Running');
});

// ================= DASHBOARD =================
app.all('/player/login/dashboard', async (req: Request, res: Response) => {
  const body = req.body;
  let clientData = '';

  if (body && typeof body === 'object' && Object.keys(body).length > 0) {
    clientData = Object.keys(body)[0];
  }

  const encodedClientData = Buffer.from(clientData).toString('base64');

  const templatePath = path.join(process.cwd(), 'template', 'dashboard.html');
  const templateContent = fs.readFileSync(templatePath, 'utf-8');

  const htmlContent = templateContent.replace('{{ data }}', encodedClientData);

  res.setHeader('Content-Type', 'text/html');
  res.send(htmlContent);
});

// ================= LOGIN VALIDATE =================
app.all('/player/growid/login/validate', async (req: Request, res: Response) => {
  try {
    let _token, growId, password, email;

if (typeof req.body === 'object' && Object.keys(req.body).length === 1) {
  const raw = Object.keys(req.body)[0];
  const params = new URLSearchParams(raw);

  _token = params.get('_token');
  growId = params.get('growId');
  password = params.get('password');
  email = params.get('email');
} else {
  _token = req.body._token;
  growId = req.body.growId;
  password = req.body.password;
  email = req.body.email;
}

    // ================= REGISTER BUTTON (EMPTY) =================
    // kalau kosong → tetap kirim token kosong biar C++ handle register
    if (!growId && !password) {
      const raw = `_token=${_token || ''}&growId=&password=`;
      const token = Buffer.from(raw).toString('base64');

      return sendResponse(req, res, {
  status: 'success',
  message: 'Account Validated.',
  token,
  url: '',
  accountType: 'growtopia',
});
    }

    // ================= VALIDASI LOGIN =================
    if (!growId || !password) {
      return res.json({
        status: 'error',
        message: 'growId and password required',
      });
    }

    // ================= NORMAL LOGIN =================
    let raw = `_token=${_token}&growId=${growId}&password=${password}`;
    if (email) raw += `&email=${email}`;

    const token = Buffer.from(raw).toString('base64');

sendResponse(req, res, {
  status: 'success',
  message: 'Account Validated.',
  token,
  url: '',
  accountType: 'growtopia',
});
  } catch (error) {
    console.log(`[ERROR]: ${error}`);
    res.status(500).json({
      status: 'error',
      message: 'Internal Server Error',
    });
  }
});

// ================= CHECKTOKEN REDIRECT =================
app.all('/player/growid/checktoken', async (_req: Request, res: Response) => {
  return res.redirect(307, '/player/growid/validate/checktoken');
});

// ================= CHECKTOKEN VALIDATE =================
app.all('/player/growid/validate/checktoken', async (req: Request, res: Response) => {
  try {
    let refreshToken: string | undefined;

    if (typeof req.body === 'object' && req.body !== null) {
      const formData = req.body as Record<string, string>;

      if ('refreshToken' in formData) {
        refreshToken = formData.refreshToken;
      } else if (Object.keys(formData).length === 1) {
        const rawPayload = Object.keys(formData)[0];
        const params = new URLSearchParams(rawPayload);
        refreshToken = params.get('refreshToken') || undefined;
      }
    }

    if (!refreshToken) {
      return res.json({
        status: 'error',
        message: 'Missing refreshToken',
      });
    }

    // decode & encode ulang (no modification)
    const decoded = Buffer.from(refreshToken, 'base64').toString('utf-8');
    const token = Buffer.from(decoded).toString('base64');

sendResponse(req, res, {
  status: 'success',
  message: 'Account Validated.',
  token,
  url: '',
  accountType: 'growtopia',
  accountAge: 2,
});
  } catch (error) {
    console.log(`[ERROR]: ${error}`);
    res.json({
      status: 'error',
      message: 'Internal Server Error',
    });
  }
});

// ================= START =================
app.listen(PORT, () => {
  console.log(`[SERVER] Running on http://localhost:${PORT}`);
});

export default app;
