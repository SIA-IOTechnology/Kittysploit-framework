#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from core.framework.option.option_choice import OptChoice
from core.utils.exceptions import OptionValidationError


class OptEnum(OptChoice):
    """Choice option with choices listed first (Metasploit-style OptEnum)."""

    def __init__(self, choices, description="", required=False, default=None, advanced=False):
        if not choices:
            raise OptionValidationError("OptEnum requires at least one choice")
        choice_list = list(choices)
        if default is None:
            default = choice_list[0]
        super().__init__(
            default=default,
            description=description,
            required=required,
            choices=choice_list,
            advanced=advanced,
        )
