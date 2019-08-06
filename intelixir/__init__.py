# -*- coding: utf-8 -*-
# ██╗███╗   ██╗████████╗███████╗██╗     ██╗██╗  ██╗██╗██████╗ 
# ██║████╗  ██║╚══██╔══╝██╔════╝██║     ██║╚██╗██╔╝██║██╔══██╗
# ██║██╔██╗ ██║   ██║   █████╗  ██║     ██║ ╚███╔╝ ██║██████╔╝
# ██║██║╚██╗██║   ██║   ██╔══╝  ██║     ██║ ██╔██╗ ██║██╔══██╗
# ██║██║ ╚████║   ██║   ███████╗███████╗██║██╔╝ ██╗██║██║  ██║
# ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚══════╝╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═╝                                                          

"""
SophosLabs Intelix Library
~~~~~~~~~~~~~~~~~~~~~
Intelixir is a demonstration of SophosLabs Intelix, written in Python.
usage:
   >>> import intelixir
   >>> file_hash = 'D8A928B2043DB77E340B523547BF16CB4AA483F0645FE0A290ED1F20AAB76257'
   >>> s = intelixir.lookup.sha256(file_hash)
   >>> s.detectionName
   'Mal/Generic-S'
:copyright: (c) 2019 by @secbug.
:license: Apache 2.0, see LICENSE for more details.
"""

import requests
import json
import hashlib
from urllib.parse import urlparse, quote
from .__version__ import __title__, __description__, __url__, __version__, __author__, __license__

from .api import SophosLabs
