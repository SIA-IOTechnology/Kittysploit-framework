#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys

# Add the project root to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from interfaces.kittyproxy.module_suggester import ModuleSuggester

suggester = ModuleSuggester()

# Collect all suggested modules
all_modules = set()

# From TECHNOLOGY_MODULE_MAPPING
for modules in suggester.TECHNOLOGY_MODULE_MAPPING.values():
    all_modules.update(modules)

# From VULNERABILITY_MODULE_MAPPING
for modules in suggester.VULNERABILITY_MODULE_MAPPING.values():
    all_modules.update(modules)

# From CONFIG_MODULE_MAPPING
for modules in suggester.CONFIG_MODULE_MAPPING.values():
    all_modules.update(modules)

# Check which modules exist
missing_modules = []
existing_modules = []

for module_path in sorted(all_modules):
    # Convert module path to file path
    file_path = os.path.join("modules", module_path + ".py")
    
    if os.path.exists(file_path):
        existing_modules.append(module_path)
    else:
        missing_modules.append(module_path)

print("=" * 80)
print("MODULES SUGGESTÉS PAR KITTYPROXY")
print("=" * 80)
print(f"\nTotal de modules suggérés: {len(all_modules)}")
print(f"Modules existants: {len(existing_modules)}")
print(f"Modules manquants: {len(missing_modules)}")
print("\n" + "=" * 80)
print("MODULES MANQUANTS:")
print("=" * 80)

if missing_modules:
    for module in missing_modules:
        print(f"  - {module}")
else:
    print("  Aucun module manquant!")

print("\n" + "=" * 80)
print("MODULES EXISTANTS:")
print("=" * 80)

if existing_modules:
    for module in existing_modules:
        print(f"  [OK] {module}")
