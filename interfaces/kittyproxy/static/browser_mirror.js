/**
 * Browser Mirroring Script
 * Captures DOM changes and screenshots for live mirroring
 * 
 * Note: This uses html2canvas which captures the DOM directly, so no screen capture
 * permissions (getDisplayMedia/getUserMedia) are required. The user doesn't need to
 * grant any browser permissions to share their screen.
 */

class BrowserMirror {
    constructor(websocketUrl, sessionId, userId) {
        this.ws = null;
        this.websocketUrl = websocketUrl;
        this.sessionId = sessionId;
        this.userId = userId;
        this.isMirroring = false;
        this.observer = null;
        this.lastScreenshot = null;
        this.lastScreenshotHash = null;
        this.lastScreenshotDimensions = null;
        this.screenshotInterval = null;
        this.domSnapshot = null;
        this.lastDomHash = null;
        
        // Configuration
        this.config = {
            screenshotInterval: 1000, // 1 seconde
            domCheckInterval: 500,    // 500ms
            maxScreenshotSize: 5000000, // 5MB (augmenté pour qualité maximale)
            quality: 0.95,  // Qualité JPEG maximale (95%)
            scale: 1.0      // Scale à 100% pour qualité maximale
        };
    }
    
    async start() {
        if (this.isMirroring) return;
        
        try {
            // Si le WebSocket est déjà fourni (collaboration WebSocket), l'utiliser directement
            if (this.ws && this.ws.readyState === WebSocket.OPEN) {
                // Le message mirror_start a déjà été envoyé par startBrowserMirroring
                // Capturer le DOM initial
                await this.captureInitialDOM();
                
                // Démarrer la surveillance
                this.startDOMObserver();
                this.startScreenshotCapture();
                
                this.isMirroring = true;
                console.log('[BrowserMirror] Mirroring started using existing WebSocket');
            } else {
                // Sinon, connecter au WebSocket
                await this.connect();
                
                // Capturer le DOM initial
                await this.captureInitialDOM();
                
                // Démarrer la surveillance
                this.startDOMObserver();
                this.startScreenshotCapture();
                
                this.isMirroring = true;
                console.log('[BrowserMirror] Mirroring started');
            }
        } catch (error) {
            console.error('[BrowserMirror] Error starting mirror:', error);
            throw error;
        }
    }
    
    stop() {
        if (!this.isMirroring) return;
        
        this.isMirroring = false;
        
        if (this.observer) {
            this.observer.disconnect();
            this.observer = null;
        }
        
        if (this.screenshotInterval) {
            clearInterval(this.screenshotInterval);
            this.screenshotInterval = null;
        }
        
        if (this.ws) {
            this.ws.close();
            this.ws = null;
        }
        
        console.log('[BrowserMirror] Mirroring stopped');
    }
    
    async connect() {
        return new Promise((resolve, reject) => {
            // Construire l'URL WebSocket correctement
            // Utiliser le serveur SaaS pour le mirroring
            let wsUrl;
            if (this.websocketUrl.startsWith('ws://') || this.websocketUrl.startsWith('wss://')) {
                // URL WebSocket déjà complète, utiliser directement
                wsUrl = `${this.websocketUrl}/ws/v1/sessions/${this.sessionId}/mirror`;
            } else if (this.websocketUrl.startsWith('http://') || this.websocketUrl.startsWith('https://')) {
                // URL HTTP/HTTPS, convertir en WebSocket
                const wsProtocol = this.websocketUrl.startsWith('https') ? 'wss:' : 'ws:';
                const host = this.websocketUrl.replace(/^https?:\/\//, '');
                wsUrl = `${wsProtocol}//${host}/ws/v1/sessions/${this.sessionId}/mirror`;
            } else {
                // Juste un hostname, utiliser ws:// par défaut
                wsUrl = `ws://${this.websocketUrl}/ws/v1/sessions/${this.sessionId}/mirror`;
            }
            
            console.log('[BrowserMirror] Connecting to:', wsUrl);
            this.ws = new WebSocket(wsUrl);
            
            this.ws.onopen = () => {
                // Envoyer les informations de connexion
                this.ws.send(JSON.stringify({
                    type: 'mirror_start',
                    user_id: this.userId
                }));
                resolve();
            };
            
            this.ws.onerror = (error) => {
                console.error('[BrowserMirror] WebSocket error:', error);
                reject(error);
            };
            
            this.ws.onclose = () => {
                console.log('[BrowserMirror] WebSocket closed');
                if (this.isMirroring) {
                    // Tentative de reconnexion
                    setTimeout(() => this.connect(), 3000);
                }
            };
            
            this.ws.onmessage = (event) => {
                try {
                    const data = JSON.parse(event.data);
                    this.handleMessage(data);
                } catch (error) {
                    console.error('[BrowserMirror] Error parsing message:', error);
                }
            };
        });
    }
    
    handleMessage(data) {
        switch (data.type) {
            case 'mirror_config':
                if (data.config) {
                    this.config = { ...this.config, ...data.config };
                }
                break;
            case 'request_screenshot':
                this.captureScreenshot();
                break;
            case 'request_dom':
                this.captureDOM();
                break;
        }
    }
    
    async captureInitialDOM() {
        const dom = this.getDOMSnapshot();
        this.domSnapshot = dom;
        this.lastDomHash = this.hashString(JSON.stringify(dom));
        
        this.send({
            type: 'dom_snapshot',
            dom: dom,
            url: window.location.href,
            timestamp: Date.now()
        });
    }
    
    getDOMSnapshot() {
        // Capturer le HTML complet
        const html = document.documentElement.outerHTML;
        
        // Capturer les dimensions
        const dimensions = {
            width: window.innerWidth,
            height: window.innerHeight,
            scrollX: window.scrollX,
            scrollY: window.scrollY
        };
        
        // Capturer les styles critiques
        const styles = this.captureCriticalStyles();
        
        return {
            html: html.substring(0, 1000000), // Limiter à 1MB
            dimensions,
            styles,
            url: window.location.href,
            title: document.title
        };
    }
    
    captureCriticalStyles() {
        const styles = {};
        const styleSheets = Array.from(document.styleSheets);
        
        styleSheets.slice(0, 10).forEach((sheet, index) => {
            try {
                if (sheet.cssRules) {
                    const rules = Array.from(sheet.cssRules).slice(0, 100);
                    styles[`sheet_${index}`] = rules.map(rule => rule.cssText).join('\n');
                }
            } catch (e) {
                // Cross-origin stylesheet, skip
            }
        });
        
        return styles;
    }
    
    startDOMObserver() {
        // Observer les changements DOM
        this.observer = new MutationObserver((mutations) => {
            if (!this.isMirroring) return;
            
            // Détecter les changements significatifs
            const hasSignificantChange = mutations.some(mutation => {
                return mutation.type === 'childList' || 
                       mutation.type === 'attributes' ||
                       (mutation.type === 'characterData' && mutation.target.textContent.length > 10);
            });
            
            if (hasSignificantChange) {
                // Debounce: capturer après un court délai
                clearTimeout(this.domCaptureTimeout);
                this.domCaptureTimeout = setTimeout(() => {
                    this.captureDOMChanges();
                }, 200);
            }
        });
        
        this.observer.observe(document.body, {
            childList: true,
            subtree: true,
            attributes: true,
            attributeOldValue: true,
            characterData: true
        });
    }
    
    captureDOMChanges() {
        const currentDom = this.getDOMSnapshot();
        const currentHash = this.hashString(JSON.stringify(currentDom));
        
        if (currentHash !== this.lastDomHash) {
            // Calculer le diff
            const diff = this.calculateDiff(this.domSnapshot, currentDom);
            
            this.send({
                type: 'dom_diff',
                diff: diff,
                url: window.location.href,
                timestamp: Date.now()
            });
            
            this.domSnapshot = currentDom;
            this.lastDomHash = currentHash;
        }
    }
    
    calculateDiff(oldDom, newDom) {
        // Simplification: envoyer seulement les changements majeurs
        // Pour une vraie implémentation, utiliser une librairie de diff
        return {
            url_changed: oldDom.url !== newDom.url,
            title_changed: oldDom.title !== newDom.title,
            dimensions_changed: JSON.stringify(oldDom.dimensions) !== JSON.stringify(newDom.dimensions)
        };
    }
    
    startScreenshotCapture() {
        // Capturer des screenshots périodiquement
        this.screenshotInterval = setInterval(() => {
            if (this.isMirroring) {
                this.captureScreenshot();
            }
        }, this.config.screenshotInterval);
    }
    
    async captureScreenshot() {
        // Gestionnaire d'erreur global pour les images (sera supprimé après la capture)
        const imageErrorHandler = (e) => {
            // Empêcher la propagation de l'erreur
            e.stopPropagation();
            e.preventDefault();
            
            const img = e.target;
            if (img && img.tagName === 'IMG') {
                try {
                    // Remplacer par une image transparente
                    const canvas = document.createElement('canvas');
                    canvas.width = img.naturalWidth || img.width || 1;
                    canvas.height = img.naturalHeight || img.height || 1;
                    img.src = canvas.toDataURL();
                    img.onerror = null; // Supprimer le gestionnaire pour éviter les boucles
                } catch (err) {
                    // Si ça échoue, masquer l'image
                    img.style.display = 'none';
                    img.onerror = null;
                }
            }
        };
        
        // Ajouter le gestionnaire d'erreur global temporairement
        document.addEventListener('error', imageErrorHandler, true);
        
        try {
            // Utiliser html2canvas si disponible, sinon utiliser une méthode alternative
            if (typeof html2canvas !== 'undefined') {
                const currentDimensions = {
                    width: window.innerWidth,
                    height: window.innerHeight
                };
                
                // Vérifier si les dimensions ont changé
                const dimensionsChanged = !this.lastScreenshotDimensions ||
                    this.lastScreenshotDimensions.width !== currentDimensions.width ||
                    this.lastScreenshotDimensions.height !== currentDimensions.height;
                
                // Calculer le scale effectif en tenant compte du devicePixelRatio pour une qualité maximale
                const devicePixelRatio = window.devicePixelRatio || 1;
                const effectiveScale = (this.config.scale || 1.0) * devicePixelRatio;
                
                // Fonction pour gérer les erreurs d'images dans le clone
                const handleImageErrors = (clonedDoc) => {
                    // Gérer les erreurs d'images dans le clone
                    const images = clonedDoc.querySelectorAll('img');
                    images.forEach(img => {
                        // Vérifier si l'image est déjà en erreur
                        if (img.naturalWidth === 0 && img.naturalHeight === 0 && img.src) {
                            // Image déjà en erreur, la remplacer
                            try {
                                const canvas = document.createElement('canvas');
                                canvas.width = img.width || 1;
                                canvas.height = img.height || 1;
                                img.src = canvas.toDataURL();
                            } catch (err) {
                                img.style.display = 'none';
                            }
                        }
                        
                        // Ajouter un gestionnaire d'erreur pour remplacer les images en erreur
                        const errorHandler = function(e) {
                            e.stopPropagation();
                            e.preventDefault();
                            try {
                                const canvas = document.createElement('canvas');
                                canvas.width = this.width || 1;
                                canvas.height = this.height || 1;
                                this.src = canvas.toDataURL();
                                this.onerror = null;
                            } catch (err) {
                                this.style.display = 'none';
                                this.onerror = null;
                            }
                        };
                        
                        img.addEventListener('error', errorHandler, { once: true, capture: true });
                        
                        // Si l'image n'est pas complète, précharger avec gestion d'erreur
                        if (img.src && !img.complete && img.src.startsWith('data:') === false) {
                            const tempImg = new Image();
                            tempImg.crossOrigin = 'anonymous';
                            tempImg.onerror = () => {
                                // Si l'image échoue, la remplacer par une image transparente
                                try {
                                    const canvas = document.createElement('canvas');
                                    canvas.width = img.width || 1;
                                    canvas.height = img.height || 1;
                                    img.src = canvas.toDataURL();
                                } catch (err) {
                                    img.style.display = 'none';
                                }
                            };
                            tempImg.onload = () => {
                                // Image chargée avec succès, rien à faire
                            };
                            try {
                                tempImg.src = img.src;
                            } catch (err) {
                                // Si on ne peut pas charger, remplacer
                                try {
                                    const canvas = document.createElement('canvas');
                                    canvas.width = img.width || 1;
                                    canvas.height = img.height || 1;
                                    img.src = canvas.toDataURL();
                                } catch (err2) {
                                    img.style.display = 'none';
                                }
                            }
                        }
                    });
                };
                
                const canvas = await html2canvas(document.body, {
                    scale: effectiveScale,  // Scale avec devicePixelRatio pour qualité maximale
                    useCORS: true,
                    logging: false,
                    backgroundColor: '#ffffff',
                    allowTaint: false,  // Changer à false pour éviter les problèmes CORS
                    removeContainer: false,
                    imageTimeout: 10000,  // Réduire le timeout
                    width: currentDimensions.width,
                    height: currentDimensions.height,
                    // Options pour améliorer la qualité
                    foreignObjectRendering: false,  // Désactiver pour éviter les problèmes avec SVG
                    pixelRatio: devicePixelRatio,  // Utiliser le ratio de pixels de l'écran
                    letterRendering: true,  // Meilleur rendu du texte
                    onclone: handleImageErrors,
                    ignoreElements: (element) => {
                        // Ignorer les éléments avec des erreurs d'image
                        if (element.tagName === 'IMG' && element.naturalWidth === 0 && element.naturalHeight === 0) {
                            return true;
                        }
                        return false;
                    }
                });
                
                // Calculer un hash de l'image pour détecter les changements
                const imageHash = await this.calculateImageHash(canvas);
                
                // Ne pas envoyer si l'image est identique (même hash et mêmes dimensions)
                if (!dimensionsChanged && imageHash === this.lastScreenshotHash) {
                    return; // Image identique, ne pas envoyer
                }
                
                const dataUrl = canvas.toDataURL('image/jpeg', this.config.quality);
                
                // Vérifier la taille
                if (dataUrl.length > this.config.maxScreenshotSize) {
                    // Réduire progressivement la qualité et le scale (mais garder une bonne qualité)
                    const reducedQuality = Math.max(0.7, this.config.quality - 0.1);
                    const reducedScale = Math.max(0.7, (this.config.scale || 1.0) - 0.1);
                    const reducedCanvas = await html2canvas(document.body, {
                        scale: reducedScale,
                        useCORS: true,
                        logging: false,
                        backgroundColor: '#ffffff',
                        allowTaint: false,  // Changer à false pour éviter les problèmes CORS
                        removeContainer: false,
                        imageTimeout: 10000,  // Réduire le timeout
                        width: currentDimensions.width,
                        height: currentDimensions.height,
                        foreignObjectRendering: false,  // Désactiver pour éviter les problèmes avec SVG
                        pixelRatio: window.devicePixelRatio || 1,
                        onclone: handleImageErrors,
                        ignoreElements: (element) => {
                            // Ignorer les éléments avec des erreurs d'image
                            if (element.tagName === 'IMG' && element.naturalWidth === 0 && element.naturalHeight === 0) {
                                return true;
                            }
                            return false;
                        }
                    });
                    
                    // Recalculer le hash pour l'image réduite
                    const reducedHash = await this.calculateImageHash(reducedCanvas);
                    if (!dimensionsChanged && reducedHash === this.lastScreenshotHash) {
                        return; // Image identique même après réduction
                    }
                    
                    const reducedDataUrl = reducedCanvas.toDataURL('image/jpeg', reducedQuality);
                    this.sendScreenshot(reducedDataUrl, reducedHash, currentDimensions);
                } else {
                    this.sendScreenshot(dataUrl, imageHash, currentDimensions);
                }
            } else {
                // Fallback: capturer seulement le DOM
                console.warn('[BrowserMirror] html2canvas not available, using DOM only');
            }
        } catch (error) {
            // Ignorer les erreurs d'images individuelles qui ne bloquent pas la capture
            if (error && error.target && error.target.tagName === 'IMG') {
                // Erreur sur une image spécifique, ne pas bloquer la capture
                console.warn('[BrowserMirror] Image load error (non-blocking):', error.target.src);
                return;
            }
            // Ne pas logger les erreurs d'images car elles sont gérées par le gestionnaire global
            if (error && error.type === 'error' && error.target && error.target.tagName === 'IMG') {
                return; // Erreur d'image gérée, ne pas logger
            }
            console.error('[BrowserMirror] Error capturing screenshot:', error);
        } finally {
            // Toujours supprimer le gestionnaire d'erreur global
            document.removeEventListener('error', imageErrorHandler, true);
        }
    }
    
    // Calculer un hash simple de l'image pour détecter les changements
    async calculateImageHash(canvas) {
        try {
            // Obtenir les données de l'image à une résolution réduite pour le hash
            const ctx = canvas.getContext('2d');
            const imageData = ctx.getImageData(0, 0, Math.min(canvas.width, 100), Math.min(canvas.height, 100));
            const data = imageData.data;
            
            // Calculer un hash simple basé sur les pixels
            let hash = 0;
            const step = Math.max(1, Math.floor(data.length / 1000)); // Échantillonner pour performance
            for (let i = 0; i < data.length; i += step * 4) {
                // Prendre seulement la valeur rouge pour simplifier
                hash = ((hash << 5) - hash) + data[i];
                hash = hash & hash; // Convertir en 32bit integer
            }
            
            return hash.toString();
        } catch (error) {
            // En cas d'erreur, utiliser un hash basé sur la taille
            return `${canvas.width}x${canvas.height}-${canvas.width * canvas.height}`;
        }
    }
    
    sendScreenshot(dataUrl, imageHash, dimensions) {
        // Stocker les informations de la dernière image envoyée
        this.lastScreenshot = dataUrl;
        this.lastScreenshotHash = imageHash;
        this.lastScreenshotDimensions = dimensions || {
            width: window.innerWidth,
            height: window.innerHeight
        };
        
        this.send({
            type: 'screenshot',
            image: dataUrl,
            url: window.location.href,
            dimensions: this.lastScreenshotDimensions,
            timestamp: Date.now()
        });
    }
    
    hashString(str) {
        let hash = 0;
        for (let i = 0; i < str.length; i++) {
            const char = str.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash; // Convert to 32bit integer
        }
        return hash.toString();
    }
    
    send(data) {
        if (this.ws && this.ws.readyState === WebSocket.OPEN) {
            try {
                this.ws.send(JSON.stringify(data));
            } catch (error) {
                console.error('[BrowserMirror] Error sending data:', error);
            }
        } else {
            console.warn('[BrowserMirror] WebSocket not ready, state:', this.ws ? this.ws.readyState : 'null');
        }
    }
}

// Export pour utilisation globale
if (typeof window !== 'undefined') {
    window.BrowserMirror = BrowserMirror;
}

