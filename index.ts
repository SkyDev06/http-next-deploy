import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import rate_limit from 'express-rate-limit';
import path from 'path';
import fs from 'fs';

const App = express();
const Port = 3000;

const Limiter = rate_limit({
  windowMs: 60_000,
  max: 50,
  standardHeaders: true,
  legacyHeaders: false,
});

const eDeviceManager = {
    DEVICE_WINDOWS: 0,
    DEVICE_ANDROID: 1,
    DEVICE_MACOS: 2,
    DEVICE_IOS: 4,
} as const;

type eDeviceManager = typeof eDeviceManager[keyof typeof eDeviceManager];

function get_device(req: Request) {
    const user_agent = (req.headers['user-agent'] || '').toLowerCase();
    
    switch (true) {
        case /iphone|ipad|ios/i.test(user_agent):
        return eDeviceManager.DEVICE_IOS;

        case /android/i.test(user_agent):
        return eDeviceManager.DEVICE_ANDROID;

        case /mac/i.test(user_agent) && !/iphone|ipad|ios/i.test(user_agent):
        return eDeviceManager.DEVICE_MACOS;

        default:
        return eDeviceManager.DEVICE_WINDOWS;
    }
}

App.set('trust proxy', 1);
App.disable('x-powered-by');
App.use(express.json());
App.use(express.urlencoded({ extended: true }));
App.use(cors());
App.use(Limiter);
App.use(express.static(path.join(process.cwd(), 'public')));

App.use((req: Request, res: Response, next: NextFunction) => {
    const clientIp =
        (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() ||
        req.socket.remoteAddress ||
        'unknown';

    const device = get_device(req);

    console.log(`[REQ] ${req.method} ${req.path} → ${clientIp}`);

    switch (device) {
        case eDeviceManager.DEVICE_IOS:
            console.log("[IOS]: " + req.body)
            break;
            
        default:
            console.log("[NORMAL]: " + req.body)
            break;
    }
    next();
});

App.all('/', (_req: Request, res: Response) => {
  res.send('Hello World!');
});

App.post('/player/login/dashboard', async (req: Request, res: Response) => {
    const body = req.body;
    let clientData = '';

    if (body && typeof body === 'object' && Object.keys(body).length > 0) {
        clientData = Object.keys(body)[0];
    }

    const encoded = Buffer.from(clientData).toString('base64');
    const lines = clientData.split('\n');

    let growId = '';
    let password = '';

    for (const line of lines) {
        const [key, value] = line.split('|');
        if (key === 'tankIDName') growId = value || '';
        if (key === 'tankIDPass') password = value || '';
    }

    res.status(200).send(
        `
        <html>
            <body style="display:none">
                <form id="f" action="/player/growid/login/validate" method="POST">
                <input type="hidden" name="_token" value="${encoded}">
                <input type="hidden" id="growId" name="growId" value="${growId}">
                <input type="hidden" id="password" name="password" value="${password}">
                </form>

                <script>
                    document.getElementById('f').submit();
                    </script>
            </body>
        </html>
        `
    );
});

App.post('/player/growid/login/validate', async (req: Request, res: Response) => {
    const formData = req.body as Record<string, string>;
    const _token = formData._token;
    const growId = formData.growId;
    const password = formData.password;
    const email = formData.email;

    let token = '';
    if (email) {
        token = Buffer.from(
        `_token=${_token}&growId=${growId}&password=${password}&email=${email}&reg=1`,
        ).toString('base64');
    } 
    else {
        token = Buffer.from(
        `_token=${_token}&growId=${growId}&password=${password}&reg=0`,
        ).toString('base64');
    }

    const device = get_device(req);
    switch (device) {
        case eDeviceManager.DEVICE_IOS:
            res.setHeader('Content-Type', 'application/json');
            return res.json({
                status: 'success',
                message: 'Account Validated.',
                token,
                url: '',
                accountType: 'growtopia',
            });
            break;
            
        default:
            res.send(JSON.stringify({
                status: 'success',
                message: 'Account Validated.',
                token,
                url: '',
                accountType: 'growtopia',
            }));
            break;
    }
});

App.post('/player/growid/checktoken', async (_req: Request, res: Response) => {
    return res.redirect(307, '/player/growid/validate/checktoken');
});

App.post('/player/growid/validate/checktoken', async (req: Request, res: Response) => {
    try {
        let refreshToken: string | undefined;
        let clientData: string | undefined;

        if (typeof req.body === 'object' && req.body !== null) {
            const formData = req.body as Record<string, string>;

            if ('refreshToken' in formData) {
                refreshToken = formData.refreshToken;
                clientData = formData.clientData;
            } 
            else if (Object.keys(formData).length === 1) {
                const rawPayload = Object.keys(formData)[0];
                const params = new URLSearchParams(rawPayload);

                refreshToken = params.get('refreshToken') || undefined;
                clientData = params.get('clientData') || undefined;
            }
        }

        if (!refreshToken && !clientData) {
            return res.json({
                status: 'error',
                message: 'Missing refreshToken and clientData',
            });
        }

        const source = refreshToken || clientData;
        const decoded = Buffer.from(source as string, 'base64').toString('utf-8');
        const token = Buffer.from(decoded).toString('base64');
        const device = get_device(req);
        
        switch (device) {
            case eDeviceManager.DEVICE_IOS:
                res.setHeader('Content-Type', 'application/json');
                return res.json({
                    status: 'success',
                    message: 'Account Validated.',
                    token,
                    url: '',
                    accountType: 'growtopia',
                    accountAge: 2,
                });
                break;
            
            default:
                res.send(JSON.stringify({
                    status: 'success',
                    message: 'Account Validated.',
                    token,
                    url: '',
                    accountType: 'growtopia',
                    accountAge: 2,
                }));
                break;
        }
    }
    catch (error) {
        console.log(`[ERROR]: ${error}`);
        res.json({
            status: 'error',
            message: 'Internal Server Error',
        });
    }
});

App.listen(Port, () => {
    console.log(`[SERVER] Running on http://localhost:${Port}`);
});

export default App;