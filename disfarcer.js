class FrontendChecker {
    constructor(config = {}) {
      if (!config.paginaSafe) {
        throw new Error('FrontendChecker: A URL da paginaSafe é obrigatória.');
      }
      this.config = {
        paginaSafe: config.paginaSafe,
        modoDebug: config.modoDebug || false,
        ...config
      };

      this.resultados = {
        touch: false,
        devTools: false,
        webRTC: 'verificando...',
        timestamp: Date.now()
      };
    }

    verificarTouch() {
      const temTouch = (
        'ontouchstart' in window ||
        navigator.maxTouchPoints > 0 ||
        navigator.msMaxTouchPoints > 0
      );

      const screenWidth = window.screen.width;
      const isDesktopSize = screenWidth > 1024;
      const suspeito = temTouch && isDesktopSize;

      this.resultados.touch = temTouch;
      this.log(temTouch ? '✅ Dispositivo touch detectado' : '📱 Dispositivo desktop');
      if (suspeito) this.log('⚠️ Touch suspeito em tela grande');

      return temTouch;
    }

    verificarDevTools() {
      let devToolsAberto = false;

      const threshold = 160;
      const widthThreshold = window.outerWidth - window.innerWidth > threshold;
      const heightThreshold = window.outerHeight - window.innerHeight > threshold;

      const debugCheck = /./;
      debugCheck.toString = function() {
        devToolsAberto = true;
        return 'DevTools detectado';
      };
      console.log('%c', debugCheck);

      const start = performance.now();
      debugger;
      const end = performance.now();
      const timingCheck = (end - start) > 100;

      devToolsAberto = devToolsAberto || widthThreshold || heightThreshold || timingCheck;

      this.resultados.devTools = !devToolsAberto;
      this.log(devToolsAberto ? '❌ DevTools detectado ABERTO' : '✅ DevTools fechado');

      return !devToolsAberto;
    }

 
    verificarWebRTC() {
      return new Promise((resolve) => {
        try {
          const pc = new RTCPeerConnection({iceServers: []});
          pc.createDataChannel('');
          pc.createOffer().then(offer => pc.setLocalDescription(offer));

          pc.onicecandidate = (ice) => {
            if (!ice || !ice.candidate || !ice.candidate.candidate) {
              if (!pc.onicecandidate.done) {
                pc.onicecandidate.done = true;
                this.log('✅ WebRTC verificado (sem IP vazado).');
                this.resultados.webRTC = 'seguro';
                resolve(true);
              }
              return;
            }
            const ipRegex = /([0-9]{1,3}(\.[0-9]{1,3}){3})/;
            const ipMatch = ipRegex.exec(ice.candidate.candidate);
            if (ipMatch) {
              this.log('❌ IP WebRTC vazado:', ipMatch[1]);
              this.resultados.webRTC = `vazado: ${ipMatch[1]}`;
              if (!pc.onicecandidate.done) {
                 pc.onicecandidate.done = true;
                 resolve(false); // Encontrou um IP, considera falha
              }
            }
          };
          // Timeout para caso a verificação nunca se complete
          setTimeout(() => {
             if (!pc.onicecandidate.done) {
                pc.onicecandidate.done = true;
                this.log('⚠️ WebRTC timeout.');
                this.resultados.webRTC = 'timeout';
                resolve(true); // Em caso de dúvida, permite
             }
          }, 2000);
        } catch (e) {
          this.log('⚠️ WebRTC não disponível.');
          this.resultados.webRTC = 'indisponível';
          resolve(true); // Se não tem WebRTC, não tem como vazar IP por ele
        }
      });
    }

    async executarVerificacao() {
      this.log('🔍 Iniciando verificação de frontend...');

      const checks = {
        touch: this.verificarTouch(),
        devTools: this.verificarDevTools(),
        webRTC: await this.verificarWebRTC(),
      };

      const aprovado = Object.values(checks).every(check => check === true);

      this.log('📊 Resultado final do frontend:', aprovado ? '✅ APROVADO' : '❌ BLOQUEADO');
      this.log('Detalhes:', this.resultados);

      return aprovado;
    }

    // ============================================
    // REDIRECIONAMENTO
    // ============================================
    async redirecionar() {
      const aprovado = await this.executarVerificacao();

      if (aprovado) {
        this.log('✅ Frontend OK. Deixando a página carregar normalmente.');
        // Não faz nada, deixa a página carregar normalmente
      } else {
        this.log('❌ Frontend falhou. Redirecionando para página segura...');
        window.location.href = this.config.paginaSafe;
      }
    }

    log(...args) {
      if (this.config.modoDebug) {
        console.log('[FRONTEND]', ...args);
      }
    }
}

if (typeof module !== 'undefined' && module.exports) {
    module.exports = FrontendChecker;
}
