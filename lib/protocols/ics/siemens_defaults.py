#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Known Siemens OT defaults — passwords, HMI credentials, TIA project paths."""

from __future__ import annotations

DEFAULT_S7_PASSWORDS: tuple[str, ...] = (
    "",
    "123456",
    "111111",
    "000000",
    "password",
    "siemens",
    "admin",
    "Admin123",
    "Siemens123",
    "TIA123",
    "plc",
    "PLC",
)

HMI_DEFAULT_CREDENTIALS: tuple[tuple[str, str], ...] = (
    ("administrator", ""),
    ("administrator", "administrator"),
    ("admin", "admin"),
    ("admin", ""),
    ("user", "user"),
    ("operator", "operator"),
    ("guest", "guest"),
    ("Administrator", ""),
    ("Administrator", "100"),
    ("HMI", "HMI"),
    ("KTP", "KTP"),
    ("simatic", "simatic"),
    ("SIMATIC", "SIMATIC"),
)

HMI_LOGIN_PATHS: tuple[str, ...] = (
    "/",
    "/portal/login",
    "/Portal/Portal.mwsl",
    "/WinCC/Login.aspx",
    "/login",
    "/api/login",
    "/Pages/Login.aspx",
    "/Portal/Portal.mwsl?PriNav=Start",
)

TIA_PROJECT_PATHS: tuple[str, ...] = (
    "/project.ap17",
    "/project.ap18",
    "/project.ap19",
    "/project.ap20",
    "/project.zap17",
    "/project.zap18",
    "/TIA/project.ap17",
    "/TIA/project.ap18",
    "/backup/project.ap17",
    "/backup/project.ap18",
    "/downloads/project.ap17",
    "/downloads/project.ap18",
    "/files/project.ap17",
    "/files/project.ap18",
    "/Project1.ap17",
    "/Project1.ap18",
    "/Plant.ap17",
    "/Plant.ap18",
    "/config/project.ap17",
    "/config/project.ap18",
)

TIA_PROJECT_EXTENSIONS: tuple[str, ...] = (
    ".ap15",
    ".ap16",
    ".ap17",
    ".ap18",
    ".ap19",
    ".ap20",
    ".zap15",
    ".zap16",
    ".zap17",
    ".zap18",
)

S7_BLOCK_TYPE_CODES: dict[str, int] = {
    "OB": 0x38,
    "DB": 0x41,
    "SDB": 0x42,
    "FC": 0x43,
    "SFC": 0x44,
    "FB": 0x45,
    "SFB": 0x46,
}

S7_PROGRAM_TRANSFER_JOBS: tuple[int, ...] = (0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F)
