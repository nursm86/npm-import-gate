// Minimal demo service. Its only job is to be a realistic project for the gate to scan in CI.
import express from 'express';
import helmet from 'helmet';

const app = express();
app.use(helmet());
app.get('/health', (_request, response) => response.json({ status: 'ok' }));

const PORT = Number(process.env.PORT ?? 3000);
app.listen(PORT);
