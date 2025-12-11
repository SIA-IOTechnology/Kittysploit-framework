"""
Kittysploit Badge Plugin

Inject Kittysploit badge in HTML pages to indicate proxy interception.
"""

from .base import InterceptionPlugin


class KittysploitBadgePlugin(InterceptionPlugin):
    """Plugin to inject Kittysploit badge in HTML pages"""
    
    def __init__(self):
        super().__init__(
            "Kittysploit Badge",
            "Inject Kittysploit badge in HTML pages to indicate proxy interception"
        )
        self.enabled = True  # Enabled by default
    
    def process_response(self, flow):
        if not self.enabled or not flow.response:
            return
        
        # Only inject in HTML responses
        content_type = flow.response.headers.get('Content-Type', '').lower()
        if 'text/html' not in content_type:
            return
        
        try:
            # Decode response content
            content = flow.response.content.decode('utf-8', errors='ignore')
            
            # Badge HTML/CSS/JS to inject
            badge_html = """
<div id="kittyproxy-badge" style="
    position: fixed;
    top: 0;
    right: 0;
    z-index: 999999;
    background: rgba(0, 0, 0, 0.85);
    backdrop-filter: blur(10px);
    -webkit-backdrop-filter: blur(10px);
    color: #ffffff;
    padding: 10px 18px;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Fira Code', 'Consolas', monospace;
    font-size: 11px;
    font-weight: 500;
    letter-spacing: 0.5px;
    border-bottom-left-radius: 12px;
    box-shadow: 0 4px 16px rgba(0,0,0,0.3), 0 0 0 1px rgba(255,255,255,0.1);
    display: flex;
    align-items: center;
    gap: 10px;
    user-select: none;
    pointer-events: none;
">
    <span style="
        width: 8px;
        height: 8px;
        background: #4caf50;
        border-radius: 50%;
        box-shadow: 0 0 8px rgba(76, 175, 80, 0.6);
        animation: pulse 2s ease-in-out infinite;
    "></span>
    <span style="font-weight: 600; color: #ffffff;">Kittysploit</span>
    <span style="opacity: 0.6; font-size: 10px; font-weight: 400;">Proxy Active</span>
</div>
<style>
@keyframes pulse {
    0%, 100% {
        opacity: 1;
        transform: scale(1);
    }
    50% {
        opacity: 0.7;
        transform: scale(0.95);
    }
}
#kittyproxy-badge {
    transition: opacity 0.3s ease;
}
</style>
"""
            
            # Inject before </body> or at the end if no body tag
            if '</body>' in content.lower():
                content = content.replace('</body>', badge_html + '</body>')
            elif '</html>' in content.lower():
                content = content.replace('</html>', badge_html + '</html>')
            else:
                # If no body/html tag, append at the end
                content += badge_html
            
            # Update response content
            flow.response.content = content.encode('utf-8')
            flow.response.headers['Content-Length'] = str(len(flow.response.content))
            
        except Exception as e:
            # Silently fail if injection fails
            pass

