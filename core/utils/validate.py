from core.utils.module_static_metadata import SUPPORTED_MODULE_TYPES, normalize_module_type


def validate_hash_type(hash_type: str) -> bool:
    SUPPORTED_HASH_TYPES = ['md5', 'sha1', 'sha256', 'bcrypt']
    if hash_type and hash_type.lower() not in SUPPORTED_HASH_TYPES:
        return False
    return True


def validate_module_type(module_type: str) -> bool:
    if not module_type:
        return True
    return normalize_module_type(module_type) in SUPPORTED_MODULE_TYPES
