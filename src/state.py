# -*- coding: utf-8 -*-
from enum import Enum

class State(Enum):
    """
    An enumeration to represent the state of a vulnerability.
    """
    FIXED = "fixed"
    NOTFIXED = "not-fixed"
    WONTFIX = "wont-fix"
    UNKNOWN = "unknown"

    def __str__(self):
        return self.value
    
    def from_string(state_str: str) -> 'State':
        """
        Converts a string to a State enum.

        :param state_str: str: The state string.
        :return: State: The corresponding State enum.
        """
        state_map = {
            "fixed": State.FIXED,
            "not-fixed": State.NOTFIXED,
            "wont-fix": State.WONTFIX,
            "unknown": State.UNKNOWN,
        }
        return state_map.get(state_str.lower().strip(), State.UNKNOWN)