<h1 align="center">Growtopia Login Backend</h1>

<p align="center">
  A Growtopia Login System Dashboard.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/GTVersion-v5.42-green" alt="GTVersion: v5.42">
</p>

## Hosting Usage

Tutorial:

[![Tutorial Videos](http://img.youtube.com/vi/8OXt1tHmeAM/0.jpg)](http://www.youtube.com/watch?v=8OXt1tHmeAM)

## Server Configuration

### Middleware Setup

- **Trust Proxy**: Set to trust 1 proxy in front of the app (`app.set('trust proxy', 1)`)
- **Body Parsing**: Supports both JSON and URL-encoded bodies (`express.json()`, `express.urlencoded({ extended: true })`)
- **CORS**: Enabled for all origins (`cors()`)
- **Rate Limiting**: 50 requests per minute per IP (`windowMs: 60_000, max: 50`)
- **Static Files**: Serves files from `/public` folder (`express.static`)
- **Request Logging**: Logs all requests with client IP, method, path, and status code

## API Endpoints

- `GET /` - Returns a greeting message
- `ALL /player/login/dashboard` - Serves the login dashboard HTML page with client data
- `POST /player/growid/login/validate` - Validates GrowID login credentials and handles registration
- `POST /player/growid/checktoken` - Redirects (307) to `/player/growid/validate/checktoken`
- `POST /player/growid/validate/checktoken` - Validates token and returns updated token

## How It Works

### 1. Dashboard Request

When a user accesses `/player/login/dashboard`, the server:
- Receives client data in the request body (optional) as object keys
- Extracts the first key which contains pipe-delimited data
- Converts the raw data to base64 format without JSON wrapping
- Serves the dashboard HTML with the encoded data injected into the `_token` field via the `{{ data }}` template placeholder

### 2. Client Data Format

When the Growtopia client connects to `/player/login/dashboard`, it sends data in the request body as an object where the keys contain the actual data:

```javascript
{
  "tankIDName|\ntankIDPass|\nrequestedName|\nf|1\nprotocol|225...": ""
}
```

The server extracts the first key, which contains pipe-delimited (`|`) key-value pairs separated by newlines (`\n`). This raw data is then base64 encoded and injected into the HTML template as the `_token` field.

### 3. Login Validation

After the user submits the login form from `/player/login/dashboard`, a POST request is sent to `/player/growid/login/validate` containing:

**For Login:**
```txt
_token=<base64_encoded_client_data>
growId=<username>
password=<user_password>
```

**For Registration:**
```txt
_token=<base64_encoded_client_data>
growId=<username>
email=<user_email>
password=<user_password>
password_confirmation=<confirmed_password>
```

Then responds with:

```json
{
  "status": "success",
  "message": "Account Validated.",
  "token": "<base64_encoded_credentials>",
  "url": "",
  "accountType": "growtopia"
}
```

The token contains:
- `_token` - Base64-encoded client data
- `growId` - Username
- `password` - User password
- `email` - User email (only for registration)
- `reg` - Registration flag (`0` for login, `1` for registration)

**Note:** This implementation always validates successfully as it doesn't connect to a database. You should implement proper credential validation against your server database.

### 4. Token Verification

When login as saved Growtopia client sends data to the server in this format:

```txt
protocol|225
ltoken|X3Rva2VuPWV5SjBZVzVyU1VST1lX...
platformID|0,1,1
adc|1
```

The `ltoken` is a base64-encoded string that decodes to:

```txt
_token=eyJ0YW5rSUROYW1lIjoiYWtpbyIs...&growId=UserName&password=UserPass&reg=0
```

#### Token Structure

- `_token` - Base64-encoded client information (RID, MAC address, game version, protocol, etc.)
- `growId` - Username
- `password` - User password
- `reg` - Registration status (`0` = login, `1` = register)

### 5. Token Refresh

Endpoint `/player/growid/checktoken` redirects (307) the client to `/player/growid/validate/checktoken` to preserve the request body data.

The client sends a POST request to `/player/growid/validate/checktoken` with:

```txt
refreshToken=<base64_encoded_refresh_token>
clientData=<base64_encoded_client_data>
```

#### Content Type Support

The server supports multiple content types for different clients:
- **JSON** (`application/json`) - Desktop client
- **Form URL-encoded** - HTML form submissions
- **Plain text** - Mobile clients (parsed with URLSearchParams)

Then responds with:

```json
{
  "status": "success",
  "message": "Token is valid.",
  "token": "<base64_encoded_credentials>",
  "url": "",
  "accountType": "growtopia"
}
```

**Note:** This implementation always validates successfully as it doesn't connect to a database. You should implement proper credential validation against your server database.

### 6. Dashboard Features

The login dashboard (`/template/dashboard.html`) includes:

#### Forms
- **Login Form**: Growtopia Name (letters/numbers only), Password (letters, numbers, `@`, `.`, `_`, `!`, `-`)
- **Registration Form**: Growtopia Name, Email, Password, Confirm Password
- **Toggle**: Users can switch between login and registration forms

#### Input Validation
- **Username**: Only alphanumeric characters allowed (`[A-Za-z0-9]+`)
- **Password**: Alphanumeric plus special characters `@`, `.`, `_`, `!`, `-` (`[A-Za-z0-9@._!\-]+`)
- **Real-time filtering**: JavaScript prevents invalid character input
- **Password matching**: Registration validates that password and confirmation match

#### Security Features
- **Anti-devtools**: Blocks F12, Ctrl+Shift+I, Ctrl+Shift+C, Ctrl+Shift+J, Ctrl+U
- **Double-click prevention**: Disables links after first click
- **Form submission lock**: Prevents double submission
- **Mobile responsive**: Scales down on screens < 667px width

## Installation

```bash
bun install
```

## Development

Run the development server locally:

```bash
bun run dev
```

## Deployment

Deploy the application to Vercel:

1. **Fork the repository** - Click the "Fork" button on the top right of this repository page
2. **Login to Vercel** - Go to [Vercel](https://vercel.com) and login or register using your GitHub account (recommended)
3. **Create new project**:
   - Click the "New" button on the top right of your team project page
   - Select "Project"
   - Import your Git repository by selecting the forked repository
   - Click "Import"
4. **Configure and deploy**:
   - Check the Framework Preset setting
   - If the framework preset is not set to "Elysia", select "Elysia" from the dropdown
   - Click "Deploy"
   - Wait for the deployment to complete


## Contact

- Telegram: [@ethermite](https://t.me/ethermite)
- Discord: [Nakai Community](https://discord.gg/UFr8C9gCq9)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
