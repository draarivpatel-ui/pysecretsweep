"""Exception types for pysecretsweep."""


class SecretSweepError(Exception):
    """Base class for expected pysecretsweep input and usage failures."""


class UsageError(SecretSweepError):
    """Invalid user input, configuration, detector selection, or baseline."""


class DetectorError(SecretSweepError):
    """A detector failed while scanning input."""
