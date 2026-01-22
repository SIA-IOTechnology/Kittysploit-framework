# Marketplace Module Examples

This folder contains example modules for the KittySploit marketplace.

## Contents

### 1. example_exploit/

Example **MODULE** type (HTTP exploit).

Demonstrates:
- Basic module structure
- Using `install_path` to create a stub
- Options and configuration
- Framework interaction

**Type**: `module`  
**Install path**: `modules/exploits/example_http.py`

### 2. example_interface/

Example **UI/INTERFACE** type (web interface).

Demonstrates:
- User interface structure
- Automatic launcher at root
- Dynamic path resolution
- External configuration

**Type**: `UI`  
**Launcher**: `launch_example_web_ui.py` (created at root)

## Usage

### Testing Locally

To test these examples without going through the marketplace:

#### 1. MODULE (example_exploit)

```bash
# Create extension folder manually
mkdir -p extensions/example-http-exploit/latest
cp -r examples/marketplace_modules/example_exploit/* extensions/example-http-exploit/latest/

# Create the stub manually (or let the system create it)
# The stub will be in: modules/exploits/example_http.py

# In KittySploit
kittysploit> use exploits/example_http
kittysploit (exploits/example_http)> show options
kittysploit (exploits/example_http)> run
```

#### 2. INTERFACE (example_interface)

```bash
# Create extension folder
mkdir -p extensions/example-web-ui/latest
cp -r examples/marketplace_modules/example_interface/* extensions/example-web-ui/latest/

# Create launcher manually
# (see generated content in documentation)

# Launch
python launch_example_web_ui.py
```

### Via Marketplace

If these modules were published on the marketplace:

```bash
# Installation
kittysploit> market install example-http-exploit
kittysploit> market install example-web-ui

# Usage
kittysploit> use exploits/example_http
python launch_example_web_ui.py
```

## Creating Your Own Module

### Steps

1. **Copy an example**
   ```bash
   cp -r examples/marketplace_modules/example_exploit my_module
   cd my_module
   ```

2. **Modify extension.toml**
   ```toml
   id = "my-module"
   name = "My Module"
   # ... other fields
   ```

3. **Develop your code**
   - Modify `src/` with your logic
   - Add dependencies in `allowed_imports`
   - Define necessary permissions

4. **Test locally**
   - Create folder in `extensions/`
   - Create manual stub
   - Test in KittySploit

5. **Submit to marketplace**
   - Contact KittySploit team
   - Provide your module and manifest
   - Team will validate and publish

## Supported Module Types

| Type | Description | Install Path | Launcher |
|------|-------------|--------------|----------|
| `module` | Exploit, auxiliary, post, etc. | ✅ Required | ❌ No |
| `plugin` | Framework plugin | ✅ Required | ❌ No |
| `UI` | User interface | ❌ No | ✅ Yes |
| `middleware` | Dynamic middleware | ❌ No | ❌ No |

## Recommended Structure

### For a MODULE or PLUGIN

```
my_module/
├── extension.toml          # Manifest (REQUIRED)
├── README.md              # Documentation
├── LICENSE                # License
└── src/
    ├── exploit.py         # Entry point (Module class)
    ├── helpers.py         # Auxiliary code
    └── config.json        # Optional configuration
```

### For an INTERFACE

```
my_interface/
├── extension.toml          # Manifest (REQUIRED)
├── README.md              # Documentation
├── LICENSE                # License
├── config.json            # Configuration
└── src/
    ├── main.py            # Entry point
    ├── ui/                # Interface code
    │   ├── server.py
    │   └── templates/
    ├── lib/               # Libraries
    └── static/            # Static assets
        ├── css/
        ├── js/
        └── img/
```

## Manifest Files

### Required Fields

```toml
id = "unique-id"              # Unique ID (validated by team)
name = "Display Name"         # Display name
version = "1.0.0"            # Semver
extension_type = "module"     # Type (module, plugin, UI, middleware)
```

### Fields for MODULE/PLUGIN

```toml
entry_point = "src/exploit.py"                    # File containing Module
install_path = "modules/exploits/my_module.py"   # Where to create stub
```

### Fields for INTERFACE

```toml
entry_point = "src/main.py"   # Entry point
# NO install_path!
```

### Permissions

```toml
[permissions]
network_access = true          # Network access
database_access = false        # Database access
sandbox_level = "standard"     # Security level
allowed_imports = ["requests"] # Allowed imports
```

## Complete Documentation

For more information:

- **Complete guide**: `docs/MARKETPLACE_MODULE_GUIDE.md`
- **Installation system**: `MARKETPLACE_INSTALLATION_SYSTEM.md`
- **Framework API**: `docs/API.md`

## Support

For any questions:
- Documentation: `docs/`
- Issues: GitHub Issues
- Contact: team@kittysploit.com

## License

Examples are provided under MIT License.
Your module can have its own license (specify in manifest).
