import sys
from unittest.mock import MagicMock

# mock dependencies which we don't care about covering in our tests
ch = MagicMock()
sys.modules['charmhelpers'] = ch
sys.modules['charmhelpers.core'] = ch.core
sys.modules['charmhelpers.core.unitdata'] = ch.core.unitdata
sys.modules['charms.layer.status'] = MagicMock()
