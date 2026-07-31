# -*- coding: utf-8 -*-
"""NFS / MOUNT scanners (NSE nfs-showmount)."""

from lib.scanner.nfs.detectors import probe_nfs_showmount

__all__ = ["probe_nfs_showmount"]
