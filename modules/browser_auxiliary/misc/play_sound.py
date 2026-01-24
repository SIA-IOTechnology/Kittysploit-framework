from kittysploit import *

class Module(BrowserAuxiliary):
    __info__ = {
        "name": "Play Sound",
        "description": "Play a sound on the browser victim (requires user interaction on modern browsers)",
        "author": "KittySploit Team",
        "browser": Browser.ALL,
        "platform": Platform.ALL,
        "session_type": SessionType.BROWSER,
        "user_interaction": True,
    }

    url_audio = OptString("https://www.soundhelix.com/examples/mp3/SoundHelix-Song-1.mp3", "URL of the audio file to play", True)

    def run(self):
        """Play a sound on the target browser session"""
        # Modern browsers block autoplay without user interaction
        # We'll wait for the next user interaction (click, keypress, etc.) to play the audio
        code_js = f"""
        (function() {{
            try {{
                // Create audio element
                const audio = new Audio('{self.url_audio}');
                audio.volume = 1.0;
                audio.preload = 'auto';
                
                let audioPlayed = false;
                
                // Function to play audio
                function playAudio() {{
                    if (audioPlayed) return;
                    audioPlayed = true;
                    
                    const playPromise = audio.play();
                    if (playPromise !== undefined) {{
                        playPromise.then(() => {{
                            console.log('Audio playing');
                        }}).catch(error => {{
                            console.error('Failed to play audio:', error);
                        }});
                    }}
                }}
                
                // Try to play immediately (might work if user already interacted)
                const playPromise = audio.play();
                if (playPromise !== undefined) {{
                    playPromise.then(() => {{
                        audioPlayed = true;
                        console.log('Audio playing');
                    }}).catch(() => {{
                        // Autoplay blocked - wait for user interaction
                        console.log('Autoplay blocked. Waiting for user interaction...');
                        
                        // Listen for any user interaction event
                        const events = ['click', 'keydown', 'keypress', 'mousedown', 'touchstart', 'pointerdown'];
                        const playOnInteraction = (event) => {{
                            playAudio();
                            // Remove listeners after first interaction
                            events.forEach(evt => {{
                                document.removeEventListener(evt, playOnInteraction, true);
                                window.removeEventListener(evt, playOnInteraction, true);
                            }});
                        }};
                        
                        // Add listeners to document and window
                        events.forEach(evt => {{
                            document.addEventListener(evt, playOnInteraction, true);
                            window.addEventListener(evt, playOnInteraction, true);
                        }});
                    }});
                }}
            }} catch (error) {{
                console.error('Error creating audio:', error);
            }}
        }})();
        """
        
        self.send_js(code_js)
        return True