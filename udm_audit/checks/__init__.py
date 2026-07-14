from .version import VersionCheck
from .ssh_hardening import SSHHardeningCheck
from .vpn_security import VPNSecurityCheck
from .container_security import ContainerSecurityCheck
from .network_exposure import NetworkExposureCheck, UpdateStatusCheck, LoggingConfigCheck
from .integrity import IntegrityCheck
from .firewall import FirewallCheck

ALL_CHECKS = [
    VersionCheck,
    SSHHardeningCheck,
    VPNSecurityCheck,
    ContainerSecurityCheck,
    NetworkExposureCheck,
    UpdateStatusCheck,
    LoggingConfigCheck,
    IntegrityCheck,
    FirewallCheck,
]

CHECK_MAP = {cls.check_id: cls for cls in ALL_CHECKS}

__all__ = ["ALL_CHECKS", "CHECK_MAP"] + [cls.__name__ for cls in ALL_CHECKS]
