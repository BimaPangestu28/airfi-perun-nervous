# AirFi - WiFi Access via CKB Micropayments

AirFi provides secure, time-limited WiFi access via CKB (Nervos Network) micropayments using Perun state channels for off-chain payments.

## Features

- **Generated Guest Wallets**: Automatic keypair generation for each session
- **On-chain Funding**: Send CKB from any wallet to fund your session
- **Perun State Channels**: Off-chain micropayments for pay-per-minute billing
- **Real-time Dashboard**: Live session monitoring with auto-refresh
- **SQLite Persistence**: Session and wallet history survives restarts
- **Host Dashboard**: Web-based dashboard with password auth

## Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   Guest Portal  │────▶│  Backend Server │────▶│   CKB Testnet   │
│   (HTML/JS)     │     │    (Golang)     │     │  (via Perun)    │
└─────────────────┘     └─────────────────┘     └─────────────────┘
        │                       │
        │                       ▼
        │               ┌─────────────────┐
        │               │  SQLite DB      │
        │               │  (airfi.db)     │
        │               └─────────────────┘
        │
        ▼
┌─────────────────┐
│   Any CKB       │
│   Wallet        │
└─────────────────┘
```

## Quick Start

### 1. Build

```bash
go mod tidy
go build -o backend ./cmd/backend
go build -o hostcli ./cmd/hostcli
```

### 2. Run Backend

```bash
./backend
```

Backend starts on `http://localhost:8080` with:
- SQLite database at `./airfi.db`
- JWT keys at `./keys/`

### 3. Run Host CLI Dashboard

```bash
./hostcli dashboard
```

Shows real-time session monitoring with auto-refresh every 2 seconds.

### 4. Access Web Portal

| URL | Description |
|-----|-------------|
| `http://localhost:8080/` | Guest landing page |
| `http://localhost:8080/connect` | Buy WiFi page (generates wallet) |
| `http://localhost:8080/dashboard` | Host dashboard (password: `airfi2025`) |

## Payment Flow

### Guest Flow

1. Guest opens `/connect` page
2. Backend generates a temporary CKB wallet
3. Guest sees QR code with wallet address
4. Guest sends CKB from any wallet (JoyID, Neuron, etc.)
5. Backend detects funding, creates session
6. Perun channel opens automatically
7. WiFi activates, 1 CKB = 1 minute

```
┌─────────────┐         ┌─────────────┐         ┌─────────────┐
│   Guest     │         │   Backend   │         │   CKB Node  │
└─────────────┘         └─────────────┘         └─────────────┘
      │                       │                       │
      │   GET /connect        │                       │
      │──────────────────────▶│                       │
      │   (generate wallet)   │                       │
      │◀──────────────────────│                       │
      │                       │                       │
      │   Send CKB to address │                       │
      │───────────────────────────────────────────────▶
      │                       │                       │
      │   Poll wallet status  │   Check balance       │
      │──────────────────────▶│──────────────────────▶│
      │                       │   (funded)            │
      │   session created     │◀──────────────────────│
      │◀──────────────────────│                       │
      │                       │                       │
      │   Redirect to /session/xxx                    │
      │                                               │
```

## Pricing

| Amount | Duration |
|--------|----------|
| 150 CKB | ~2.5 hours |
| 200 CKB | ~3+ hours |
| 300 CKB | ~5 hours |
| Custom | 1 CKB = 1 minute |

Minimum: 150 CKB (includes channel funding + transaction fees)

## API Endpoints

### Guest Wallet

| Endpoint | Method | Description |
|----------|--------|-------------|
| `POST /api/v1/wallet/guest` | POST | Generate new guest wallet |
| `GET /api/v1/wallet/guest/:id` | GET | Check wallet status & balance |

### Session Management

| Endpoint | Method | Description |
|----------|--------|-------------|
| `GET /api/v1/sessions` | GET | List all sessions |
| `GET /api/v1/sessions/:id` | GET | Get session info |
| `GET /api/v1/sessions/:id/token` | GET | Get JWT access token |
| `POST /api/v1/sessions/:id/end` | POST | End session, settle channel |

### Perun Channels

| Endpoint | Method | Description |
|----------|--------|-------------|
| `POST /api/v1/channels/open` | POST | Open payment channel |
| `POST /api/v1/sessions/:id/extend` | POST | Micropayment extension |

### System

| Endpoint | Method | Description |
|----------|--------|-------------|
| `GET /health` | GET | Health check |
| `GET /api/v1/wallet` | GET | Host wallet status |

## Host CLI Commands

```bash
# Interactive dashboard with real-time updates
./hostcli dashboard

# Display QR code
./hostcli qr

# List sessions
./hostcli sessions

# Watch sessions (auto-refresh)
./hostcli sessions watch

# System status
./hostcli status

# Wallet info
./hostcli wallet

# Settle channel
./hostcli settle <session-id>

# Custom API URL
./hostcli --api http://192.168.1.100:8080 dashboard
```

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `8080` | Server port |
| `HOST_PRIVATE_KEY` | (demo key) | Host wallet private key |
| `DASHBOARD_PASSWORD` | `airfi2025` | Dashboard login password |

### Example

```bash
export PORT=8080
export DASHBOARD_PASSWORD=mysecretpassword
./backend
```

## Project Structure

```
airfi-perun-nervous/
├── cmd/
│   ├── backend/        # Backend server
│   └── hostcli/        # Host CLI tool
├── internal/
│   ├── auth/           # JWT authentication
│   ├── db/             # SQLite database
│   ├── guest/          # Guest wallet generation
│   └── perun/          # Perun channel integration
├── web/guest/
│   ├── static/         # CSS, JS assets
│   └── templates/      # HTML templates
├── config/             # Configuration files
├── keys/               # JWT keys (auto-generated)
└── airfi.db            # SQLite database (auto-created)
```

## Database Schema

### Sessions Table

```sql
CREATE TABLE sessions (
    id TEXT PRIMARY KEY,
    wallet_id TEXT,
    channel_id TEXT,
    guest_address TEXT,
    host_address TEXT,
    funding_ckb INTEGER DEFAULT 0,
    balance_ckb INTEGER DEFAULT 0,
    spent_ckb INTEGER DEFAULT 0,
    created_at DATETIME,
    expires_at DATETIME,
    status TEXT DEFAULT 'pending_funding',
    settled_at DATETIME
);
```

### Guest Wallets Table

```sql
CREATE TABLE guest_wallets (
    id TEXT PRIMARY KEY,
    address TEXT UNIQUE,
    private_key_hex TEXT,
    funding_ckb INTEGER DEFAULT 0,
    balance_ckb INTEGER DEFAULT 0,
    created_at DATETIME,
    funded_at DATETIME,
    session_id TEXT,
    status TEXT DEFAULT 'created'
);
```

## Technology Stack

- **Backend**: Go 1.21+, Gin, SQLite
- **Blockchain**: Nervos CKB Testnet
- **State Channels**: Perun Network
- **Frontend**: HTML, CSS, JavaScript

### Dependencies

```
github.com/nervosnetwork/ckb-sdk-go/v2  # CKB SDK
github.com/gin-gonic/gin                 # HTTP framework
github.com/mattn/go-sqlite3              # SQLite driver
github.com/golang-jwt/jwt/v5             # JWT
github.com/mdp/qrterminal/v3             # QR code terminal
go.uber.org/zap                          # Logging
perun.network/go-perun                   # State channels
github.com/decred/dcrd/dcrec/secp256k1   # Keypair generation
```

## Testing

### Manual Test Flow

```bash
# Terminal 1: Start backend
./backend

# Terminal 2: Run CLI dashboard
./hostcli dashboard

# Browser: Open guest portal
open http://localhost:8080/connect

# Copy the generated wallet address
# Send CKB from testnet faucet or any wallet
# Watch the session appear in CLI when funded
```

### API Tests

```bash
# Health check
curl http://localhost:8080/health

# Wallet status
curl http://localhost:8080/api/v1/wallet

# List sessions
curl http://localhost:8080/api/v1/sessions

# Generate guest wallet
curl -X POST http://localhost:8080/api/v1/wallet/guest

# Check wallet status
curl http://localhost:8080/api/v1/wallet/guest/<wallet_id>
```

## CKB Testnet Resources

- **Explorer**: https://pudge.explorer.nervos.org
- **Faucet**: https://faucet.nervos.org
- **Documentation**: https://docs.nervos.org

## Session Status Flow

```
created → funded → channel_open → active → settled
                                     ↓
                                  expired
```

## License

MIT License

## Links

- [Nervos CKB](https://nervos.org)
- [Perun Network](https://perun.network)
- [Catalyst Labs](https://catalystlabs.id)
