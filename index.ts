import express, { Request, Response, NextFunction } from 'express';

const App = express();
const Port = 3000;

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
App.use(express.text({ type: "*/*" }));

App.use((req: Request, res: Response, next: NextFunction) => {
    const clientIp =
        (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() ||
        req.socket.remoteAddress ||
        'unknown';

    const device = get_device(req);

    console.log(`\n[REQ] ${req.method} ${req.path} → ${clientIp}`);

    // 🔥 DEBUG FULL REQUEST (KHUSUS iOS)
    if (device === eDeviceManager.DEVICE_IOS) {
        console.log("=== IOS DEBUG START ===");
        console.log("HEADERS:", req.headers);
        console.log("BODY TYPE:", typeof req.body);
        console.log("BODY:", req.body);
        console.log("QUERY:", req.query);
        console.log("=== IOS DEBUG END ===");
    }

    let clientData = '';

    // handle string (iOS raw)
    if (typeof req.body === 'string') {
        clientData = req.body;
    }

    // handle object
    else if (req.body && typeof req.body === 'object') {
        const keys = Object.keys(req.body);

        if (keys.length === 1 && keys[0].includes('|')) {
            clientData = keys[0];
        } else if (req.body.refreshToken) {
            clientData = req.body.refreshToken;
        } else if (req.body.clientData) {
            clientData = req.body.clientData;
        } else {
            clientData = JSON.stringify(req.body);
        }
    }

    if (!clientData) {
        clientData = '[EMPTY BODY]';
    }

    console.log(
        `[${device === eDeviceManager.DEVICE_IOS ? "IOS" : "NORMAL"}]: ${clientData}`
    );

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

    let token = '';
    token = Buffer.from(
        `_token=${_token}&growId=${growId}&password=${password}`,
    ).toString('base64');

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

App.all('/player/growid/checktoken', async (_req: Request, res: Response) => {
    return res.redirect(307, '/player/growid/validate/checktoken');
});

App.all('/player/growid/validate/checktoken', async (req: Request, res: Response) => {
    try {
        let refreshToken: string | undefined;

        // 🔥 HANDLE STRING (iOS raw)
        if (typeof req.body === 'string') {
            const params = new URLSearchParams(req.body);
            refreshToken = params.get('refreshToken') || undefined;
        }

        // 🔥 HANDLE OBJECT
        else if (typeof req.body === 'object' && req.body !== null) {
            const formData = req.body as Record<string, string>;

            if ('refreshToken' in formData) {
                refreshToken = formData.refreshToken;
            } 
            else if (Object.keys(formData).length === 1) {
                const rawPayload = Object.keys(formData)[0];
                const params = new URLSearchParams(rawPayload);
                refreshToken = params.get('refreshToken') || undefined;
            }
        }

        // 🔥 HANDLE QUERY (fallback iOS)
        if (!refreshToken && req.query.refreshToken) {
            refreshToken = String(req.query.refreshToken);
        }

        if (!refreshToken) {
            return res.json({
                status: 'error',
                message: 'Missing refreshToken',
            });
        }

        const decoded = Buffer.from(refreshToken, 'base64').toString('utf-8');
        const token = Buffer.from(decoded).toString('base64');

        const device = get_device(req);

        const response = {
            status: 'success',
            message: 'Account Validated.',
            token,
            url: '',
            accountType: 'growtopia',
            accountAge: 2,
        };

        if (device === eDeviceManager.DEVICE_IOS) {
            res.setHeader('Content-Type', 'application/json');
            return res.json(response);
        }

        return res.send(JSON.stringify(response));
    }
    catch (error) {
        console.log(`[ERROR]: ${error}`);
        return res.json({
            status: 'error',
            message: 'Internal Server Error',
        });
    }
});

App.listen(Port, () => {
    console.log(`[SERVER] Running on http://localhost:${Port}`);
});

export default App;