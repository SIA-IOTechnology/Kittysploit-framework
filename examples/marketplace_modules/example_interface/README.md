# Example Web UI

Example web interface for the KittySploit marketplace.

## Description

This module demonstrates how to create a user interface compatible with the KittySploit marketplace system. It shows how to:

- Create an entry point for an interface
- Manage paths dynamically
- Access extension resources
- Configure a web interface

## Installation

```bash
kittysploit> market install example-web-ui
```

After installation, a launcher is automatically created at the project root:
```
launch_example_web_ui.py
```

## Usage

### Launch the interface

```bash
python launch_example_web_ui.py
```

Or from anywhere in the project:

```bash
./launch_example_web_ui.py  # Unix/Linux/Mac
python launch_example_web_ui.py  # Windows
```

### Configuration

The interface loads its configuration from `config.json` in the extension folder:
```
extensions/example-web-ui/latest/config.json
```

You can modify this file to customize:
- Server host and port
- Interface theme
- Debug options

## Structure

```
example_interface/
├── extension.toml          # Manifest
├── config.json            # Configuration
├── README.md             # Documentation
└── src/
    └── main.py           # Entry point
```

## How it Works

### 1. Installation

During installation from the marketplace:

1. The extension is downloaded to `extensions/example-web-ui/latest/`
2. A launcher is created at root: `launch_example_web_ui.py`

### 2. Launch

The launcher:

1. Automatically finds the extension folder
2. Configures `sys.path` to include extension folders
3. Executes `src/main.py` with global variables:
   - `__extension_id__`: Extension ID
   - `__extension_base__`: Path to extension folder

### 3. Path Resolution

In your code (`src/main.py`), you can access the extension folder:

```python
def get_extension_info():
    return {
        'id': globals().get('__extension_id__', 'unknown'),
        'base': globals().get('__extension_base__', Path.cwd()),
    }

ext_info = get_extension_info()
ext_base = Path(ext_info['base'])

# Load a config file
config_file = ext_base / "config.json"
```

## Developing a Real Web Interface

To create a functional web interface with Flask:

### 1. Add Flask to manifest

```toml
[permissions]
allowed_imports = ["flask", "flask_cors", "werkzeug", "jinja2"]
```

### 2. Create structure

```
src/
├── main.py              # Entry point
├── ui/
│   ├── __init__.py
│   ├── server.py       # Flask application
│   ├── routes.py       # HTTP routes
│   └── templates/      # HTML templates
│       └── index.html
└── static/             # CSS, JS, images
    ├── css/
    ├── js/
    └── img/
```

### 3. Example Flask server

**src/ui/server.py:**
```python
from flask import Flask, render_template
from pathlib import Path

def create_app(config):
    app = Flask(__name__)
    app.config.update(config)
    
    @app.route('/')
    def index():
        return render_template('index.html')
    
    return app
```

**src/main.py:**
```python
from ui.server import create_app

def main():
    ext_base = setup_paths()
    config = load_config(ext_base)
    
    app = create_app(config)
    app.run(host=config['host'], port=config['port'])
```

## Uninstallation

```bash
kittysploit> market uninstall example-web-ui
```

This removes:
- The `extensions/example-web-ui/` folder
- The `launch_example_web_ui.py` launcher

## System Advantages

1. **Isolation**: Extension stays in its folder
2. **Portability**: Launcher automatically finds the extension
3. **Simplicity**: No need to manually modify sys.path
4. **Clean uninstallation**: Everything is grouped in `extensions/`

## License

MIT License
