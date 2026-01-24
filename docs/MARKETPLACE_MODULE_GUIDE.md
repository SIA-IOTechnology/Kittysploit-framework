# Marketplace Module Creation Guide

This guide explains how to create different types of modules for the KittySploit marketplace.

## Supported Module Types

1. **MODULE**: Classic modules (exploits, auxiliary, post, etc.)
2. **PLUGIN**: Plugins extending framework functionality
3. **UI/INTERFACE**: User interfaces with launcher at root
4. **MIDDLEWARE**: Dynamically loaded middlewares

## Module Structure

### 1. Manifest (extension.toml)

Each extension must contain an `extension.toml` file at its root:

```toml
# Identity
id = "my-awesome-exploit"
name = "My Awesome Exploit"
version = "1.0.0"
description = "Exploit description"
author = "your@email.com"

# Extension type
extension_type = "module"  # or "plugin", "UI", "middleware"

# Entry point
entry_point = "src/exploit.py"

# Installation path (for modules and plugins only)
install_path = "modules/exploits/my_awesome_exploit.py"
# OR for a package:
# install_path = "modules/exploits/my_awesome_exploit/"

# Compatibility
[compatibility]
kittysploit_min = "1.0.0"
kittysploit_max = "2.0.0"

# Permissions
[permissions]
network_access = true
database_access = false
sandbox_level = "standard"  # permissive, standard, strict, paranoid
allowed_imports = ["requests", "socket", "http.client"]
blocked_imports = []
hooks = []
events = []
middlewares = []

# Marketplace metadata
[metadata]
price = 0.0  # 0.0 = free
currency = "EUR"
license = "MIT"
```

## Examples by Type

### MODULE Type (exploit, auxiliary, etc.)

**Directory structure:**
```
my-exploit/
├── extension.toml
└── src/
    └── exploit.py
```

**extension.toml:**
```toml
id = "my-exploit"
name = "My Exploit"
version = "1.0.0"
extension_type = "module"
entry_point = "src/exploit.py"
install_path = "modules/exploits/my_exploit.py"

[permissions]
network_access = true
```

**src/exploit.py:**
```python
from core.framework.base_module import BaseModule

class Module(BaseModule):
    """My awesome exploit"""
    
    def __init__(self, framework):
        super().__init__(framework)
        self.info = {
            'Name': 'My Exploit',
            'Description': 'My awesome exploit',
            'Author': ['Your Name'],
            'License': 'MIT'
        }
        
        self.options.add_string('RHOST', 'Target host', required=True)
        self.options.add_port('RPORT', 'Target port', default=80)
    
    def run(self):
        rhost = self.options['RHOST']
        rport = self.options['RPORT']
        
        self.print_info(f"Exploiting {rhost}:{rport}")
        # Your code here
        
        return True
```

### PLUGIN Type

**Directory structure:**
```
my-plugin/
├── extension.toml
└── src/
    └── plugin.py
```

**extension.toml:**
```toml
id = "my-plugin"
name = "My Plugin"
version = "1.0.0"
extension_type = "plugin"
entry_point = "src/plugin.py"
install_path = "plugins/my_plugin.py"

[permissions]
database_access = true
```

**src/plugin.py:**
```python
class Module:
    """KittySploit Plugin"""
    
    def __init__(self, framework):
        self.framework = framework
    
    def initialize(self):
        """Called when loading the plugin"""
        print("Plugin initialized!")
    
    def cleanup(self):
        """Called when unloading"""
        pass
```

### UI/INTERFACE Type

**Directory structure:**
```
my-gui/
├── extension.toml
├── src/
│   ├── main.py
│   ├── ui/
│   │   └── mainwindow.py
│   └── lib/
│       └── helpers.py
└── assets/
    └── logo.png
```

**extension.toml:**
```toml
id = "my-gui"
name = "My GUI Interface"
version = "1.0.0"
extension_type = "UI"
entry_point = "src/main.py"
# NO install_path for interfaces

[permissions]
network_access = true
database_access = true
```

**src/main.py:**
```python
#!/usr/bin/env python3
"""
GUI interface entry point
"""
import os
from pathlib import Path

def main():
    # __extension_base__ is provided by the launcher
    ext_base = Path(globals().get('__extension_base__', Path.cwd()))
    
    print(f"Interface launched from: {ext_base}")
    
    # Your imports and code here
    from ui.mainwindow import MainWindow
    
    app = MainWindow()
    app.run()

if __name__ == "__main__":
    main()
```

## Installation

### After Installation

Once installed from the marketplace, the module is downloaded to:
```
extensions/
└── <extension-id>/
    └── latest/  (or specific version)
        ├── extension.toml
        ├── src/
        └── ...
```

### For MODULES and PLUGINS

A stub file is automatically created in the target folder (defined by `install_path`).

**Generated stub example (`modules/exploits/my_exploit.py`):**
```python
# Auto-generated stub module (marketplace extension)
# Extension: my-exploit
# Entry: src/exploit.py

from pathlib import Path
import importlib.util
import sys

__extension_id__ = 'my-exploit'
__extension_version_dir__ = 'latest'
__extension_entry_rel_path__ = 'src/exploit.py'

def _find_extension_base():
    here = Path(__file__).resolve()
    for parent in (here.parent, *here.parents):
        candidate = parent / "extensions" / __extension_id__ / __extension_version_dir__
        if candidate.exists():
            return candidate
    return Path.cwd() / "extensions" / __extension_id__ / __extension_version_dir__

# Dynamically loads the module from extensions/
_impl, _impl_path = _load_impl()
Module = getattr(_impl, 'Module')
```

**Usage:**
```bash
kittysploit> use exploits/my_exploit
kittysploit (exploits/my_exploit)> show options
kittysploit (exploits/my_exploit)> run
```

### For INTERFACES

A launcher is created at the project root:

```
launch_my_gui.py
```

**Launch:**
```bash
python launch_my_gui.py
```

The launcher automatically finds the extension folder in `extensions/<id>/latest/` and configures `sys.path` correctly.

## Best Practices

### 1. Code Structure

- Place your code in a `src/` subdirectory
- Use relative paths in your code
- Don't hardcode absolute paths

### 2. Dependencies

- List Python imports in `allowed_imports`
- Don't include proprietary binary dependencies
- Prefer standard or common libraries

### 3. Permissions

- Request only necessary permissions
- `network_access = false` if you don't use network
- Use `sandbox_level = "standard"` by default

### 4. Compatibility

- Test with different KittySploit versions
- Define `kittysploit_min` and `kittysploit_max`
- Document system dependencies

### 5. Documentation

- Add a README.md in your extension
- Document module options
- Include usage examples

## Uninstallation

During uninstallation:
1. The `extensions/<id>/` directory is removed
2. Stubs are automatically removed
3. Interface launchers are removed

```bash
kittysploit> market uninstall my-exploit
```

## Troubleshooting

### Module doesn't appear in `show modules`

- Check that `install_path` is correct in `extension.toml`
- Check that the stub was created in the correct folder
- Restart KittySploit to reload modules

### "Module not found" Error

- Check that `entry_point` points to the correct file
- Check that the `Module` class is properly defined
- Check logs in `extensions/<id>/latest/`

### Interface doesn't start

- Check that the launcher `launch_<id>.py` exists at root
- Check that `entry_point` is correct
- Launch with `python -v launch_<id>.py` to see details

## Security

- All extensions are validated by the KittySploit team
- Signatures are verified during installation
- Extensions run with permissions defined in the manifest
- Use sandbox to limit risks
