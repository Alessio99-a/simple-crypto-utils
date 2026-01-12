# 🚀 Setup Guide

Complete setup guide for developing and using the Secure Crypto Library.

## 📋 Prerequisites

- **Node.js** ≥16.0.0 (check: `node --version`)
- **npm** ≥7.0.0 (check: `npm --version`)
- **TypeScript** ≥5.0.0 (installed via devDependencies)

## 🔧 Installation

### For Library Users

```bash
# Install the library
npm install secure-crypto-library

# Or with yarn
yarn add secure-crypto-library
```

### For Contributors/Developers

```bash
# Clone the repository
git clone https://github.com/yourusername/secure-crypto-library.git
cd secure-crypto-library

# Install dependencies
npm install

# Build the library
npm run build

# Run tests
npm test
```

## 📁 Project Structure

```
secure-crypto-library/
├── src/
│   ├── encrypt.ts              # Main encryption logic
│   ├── decrypt.ts              # Main decryption logic
│   ├── utils.ts                # Key generation utilities
│   ├── index.ts                # Public API exports
│   ├── examples.ts             # Usage examples
│   └── __tests__/
│       └── security.test.ts    # Security tests
├── dist/                       # Compiled JavaScript (generated)
├── docs/
│   ├── README.md               # Main documentation
│   ├── SECURITY.md             # Security policy
│   ├── MODE_COMPARISON.md      # Mode comparison guide
│   ├── QUICK_REFERENCE.md      # Cheat sheet
│   └── SETUP.md                # This file
├── package.json
├── tsconfig.json
├── .gitignore
├── .npmignore
└── LICENSE
```

## 🔨 Development Scripts

```bash
# Build TypeScript to JavaScript
npm run build

# Run all tests
npm test

# Run tests in watch mode (auto-rerun on changes)
npm run test:watch

# Run security-specific tests
npm run test:security

# Generate coverage report
npm run test:coverage

# Lint code
npm run lint

# Format code
npm run format

# Prepare for publishing
npm run prepublishOnly
```

## 🧪 Testing Setup

### Running Tests

```bash
# All tests
npm test

# Watch mode
npm run test:watch

# With coverage
npm run test:coverage

# Specific test file
npm test -- security.test.ts
```

### Coverage Reports

Coverage reports are generated in `coverage/` directory:

```bash
npm run test:coverage
open coverage/lcov-report/index.html
```

**Target Coverage:**

- Branches: 70%
- Functions: 80%
- Lines: 80%
- Statements: 80%

## 🔐 Generating Keys

### Setup Script

Create a `setup-keys.js` file:

```javascript
const {
  generateRSAKeyPair,
  generateX25519KeyPair,
  generateAuthenticatedKeySet,
} = require("secure-crypto-library");
const fs = require("fs");

// Create keys directory
if (!fs.existsSync("./keys")) {
  fs.mkdirSync("./keys", { mode: 0o700 });
}

// Generate RSA keys
const rsa = generateRSAKeyPair();
fs.writeFileSync("./keys/rsa-public.key", rsa.publicKey);
fs.writeFileSync("./keys/rsa-private.key", rsa.privateKey, { mode: 0o600 });

// Generate X25519 keys
const x25519 = generateX25519KeyPair();
fs.writeFileSync("./keys/x25519-public.key", x25519.publicKey);
fs.writeFileSync("./keys/x25519-private.key", x25519.privateKey, {
  mode: 0o600,
});

// Generate authenticated key set
const auth = generateAuthenticatedKeySet();
fs.writeFileSync("./keys/auth-enc-public.key", auth.encryption.publicKey);
fs.writeFileSync("./keys/auth-enc-private.key", auth.encryption.privateKey, {
  mode: 0o600,
});
fs.writeFileSync("./keys/auth-sign-public.key", auth.signing.publicKey);
fs.writeFileSync("./keys/auth-sign-private.key", auth.signing.privateKey, {
  mode: 0o600,
});

console.log("✅ Keys generated successfully in ./keys/");
```

Run with:

```bash
node setup-keys.js
```

### Add to .gitignore

```bash
echo "keys/" >> .gitignore
echo "*.key" >> .gitignore
```

## 🌐 Environment Setup

### Development Environment

Create `.env` file (don't commit this):

```bash
# Example private keys (use your generated ones)
PRIVATE_KEY_RSA=your_rsa_private_key_base64
PRIVATE_KEY_X25519=your_x25519_private_key_base64
PRIVATE_KEY_ED25519=your_ed25519_private_key_base64

# Master password for testing
TEST_PASSWORD=TestPassword123!ForDevelopmentOnly

# Node environment
NODE_ENV=development
```

### Loading Environment Variables

```typescript
import { config } from "dotenv";
config();

const privateKey = process.env.PRIVATE_KEY_X25519;
if (!privateKey) {
  throw new Error("PRIVATE_KEY_X25519 not set in environment");
}
```

## 📦 Publishing to NPM

### Pre-publish Checklist

- [ ] All tests passing (`npm test`)
- [ ] Code formatted (`npm run format`)
- [ ] No linting errors (`npm run lint`)
- [ ] Coverage meets thresholds
- [ ] Documentation updated
- [ ] Version bumped in package.json
- [ ] CHANGELOG.md updated

### Publishing Steps

```bash
# 1. Login to npm
npm login

# 2. Run prepublish checks (automatic)
npm run prepublishOnly

# 3. Publish (dry run first)
npm publish --dry-run

# 4. Publish for real
npm publish

# 5. Tag the release
git tag v1.0.0
git push origin v1.0.0
```

## 🔄 CI/CD Setup

### GitHub Actions Workflow

Create `.github/workflows/ci.yml`:

```yaml
name: CI

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  test:
    runs-on: ubuntu-latest

    strategy:
      matrix:
        node-version: [16.x, 18.x, 20.x]

    steps:
      - uses: actions/checkout@v3

      - name: Use Node.js ${{ matrix.node-version }}
        uses: actions/setup-node@v3
        with:
          node-version: ${{ matrix.node-version }}

      - name: Install dependencies
        run: npm ci

      - name: Build
        run: npm run build

      - name: Lint
        run: npm run lint

      - name: Test
        run: npm test

      - name: Coverage
        run: npm run test:coverage

      - name: Upload coverage
        uses: codecov/codecov-action@v3
        with:
          files: ./coverage/lcov.info

  security:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v3

      - name: Run security audit
        run: npm audit

      - name: Run security tests
        run: npm run test:security
```

## 🐳 Docker Setup (Optional)

Create `Dockerfile`:

```dockerfile
FROM node:18-alpine

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci --only=production

# Copy built files
COPY dist/ ./dist/

# Set user
USER node

CMD ["node", "dist/index.js"]
```

Build and run:

```bash
docker build -t secure-crypto-library .
docker run -it secure-crypto-library
```

## 🧰 IDE Setup

### VS Code

Create `.vscode/settings.json`:

```json
{
  "typescript.tsdk": "node_modules/typescript/lib",
  "editor.formatOnSave": true,
  "editor.defaultFormatter": "esbenp.prettier-vscode",
  "editor.codeActionsOnSave": {
    "source.fixAll.eslint": true
  },
  "files.exclude": {
    "dist": true,
    "coverage": true,
    "node_modules": true
  }
}
```

Recommended extensions (`.vscode/extensions.json`):

```json
{
  "recommendations": [
    "dbaeumer.vscode-eslint",
    "esbenp.prettier-vscode",
    "ms-vscode.vscode-typescript-next"
  ]
}
```

## 🔍 Debugging Setup

### VS Code Launch Configuration

Create `.vscode/launch.json`:

```json
{
  "version": "0.2.0",
  "configurations": [
    {
      "type": "node",
      "request": "launch",
      "name": "Debug Tests",
      "program": "${workspaceFolder}/node_modules/.bin/jest",
      "args": ["--runInBand", "--no-cache"],
      "console": "integratedTerminal",
      "internalConsoleOptions": "neverOpen"
    },
    {
      "type": "node",
      "request": "launch",
      "name": "Debug Example",
      "program": "${workspaceFolder}/src/examples.ts",
      "preLaunchTask": "tsc: build - tsconfig.json",
      "outFiles": ["${workspaceFolder}/dist/**/*.js"]
    }
  ]
}
```

## 📊 Monitoring & Logging

### Setup Logging

```typescript
// src/logger.ts
export enum LogLevel {
  DEBUG = 0,
  INFO = 1,
  WARN = 2,
  ERROR = 3,
}

class Logger {
  private level: LogLevel = LogLevel.INFO;

  setLevel(level: LogLevel) {
    this.level = level;
  }

  debug(message: string, ...args: any[]) {
    if (this.level <= LogLevel.DEBUG) {
      console.debug(`[DEBUG] ${message}`, ...args);
    }
  }

  info(message: string, ...args: any[]) {
    if (this.level <= LogLevel.INFO) {
      console.info(`[INFO] ${message}`, ...args);
    }
  }

  warn(message: string, ...args: any[]) {
    if (this.level <= LogLevel.WARN) {
      console.warn(`[WARN] ${message}`, ...args);
    }
  }

  error(message: string, ...args: any[]) {
    if (this.level <= LogLevel.ERROR) {
      console.error(`[ERROR] ${message}`, ...args);
    }
  }
}

export const logger = new Logger();
```

Use in code:

```typescript
import { logger } from "./logger";

logger.info("Encrypting file with secure-channel mode");
logger.debug("Ephemeral key generated:", ephemeralKey);
```

## 🔐 Security Checklist

Before deploying:

- [ ] Private keys stored securely (not in code)
- [ ] Environment variables configured
- [ ] Strict mode enabled for production
- [ ] Logging configured (no sensitive data in logs)
- [ ] Rate limiting implemented
- [ ] Input validation in place
- [ ] Dependencies audited (`npm audit`)
- [ ] Security tests passing
- [ ] HTTPS/TLS enforced
- [ ] Access controls configured

## 🆘 Troubleshooting

### Common Issues

**Issue:** `Cannot find module 'secure-crypto-library'`

```bash
# Solution: Rebuild
npm run build
```

**Issue:** `Tests fail with "module not found"`

```bash
# Solution: Clean and reinstall
rm -rf node_modules dist
npm install
npm run build
```

**Issue:** `Permission denied when writing keys`

```bash
# Solution: Check directory permissions
chmod 700 ./keys
chmod 600 ./keys/*.key
```

**Issue:** Type errors in IDE

```bash
# Solution: Restart TypeScript server
# In VS Code: Cmd+Shift+P → "TypeScript: Restart TS Server"
```

## 📞 Support

- **Documentation:** See `docs/` directory
- **Examples:** See `src/examples.ts`
- **Issues:** GitHub Issues
- **Security:** security@yourproject.com

## 🎓 Next Steps

1. ✅ Read README.md for overview
2. ✅ Review QUICK_REFERENCE.md for API
3. ✅ Check examples.ts for usage patterns
4. ✅ Read SECURITY.md for best practices
5. ✅ Study MODE_COMPARISON.md to choose the right mode
6. ✅ Run tests to verify setup
7. ✅ Build something awesome!

---

**Happy Coding! 🎉**
