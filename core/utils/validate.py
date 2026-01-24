def validate_hash_type(hash_type: str) -> bool:
    """Validate hash type"""
    SUPPORTED_HASH_TYPES = ['md5', 'sha1', 'sha256', 'bcrypt']
    if hash_type and hash_type.lower() not in SUPPORTED_HASH_TYPES:
        return False
    return True

def validate_module_type(module_type: str) -> bool:
    """Validate module type"""
    SUPPORTED_MODULE_TYPES = ['exploits', 
                                'auxiliary', 
                                'scanner', 
                                'post', 
                                'payloads',
                                'encoders',
                                'listeners',
                                'backdoors',
                                'workflow',
                                'browser_exploits', 
                                'browser_auxiliary', 
                                'environments', 
                                'scanner', 
                                'shortcut']
    if module_type and module_type.lower() not in SUPPORTED_MODULE_TYPES:
        return False
    return True