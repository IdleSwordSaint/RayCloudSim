from typing import Optional

from core.infrastructure import Link, Node


class ZTALink(Link):
    """
    ZTA-aware Link that models additional security overheads.

    Adds optional attributes for encryption overhead and authentication latency
    that can be accounted for when estimating transmission times.
    """

    def __init__(
        self,
        src: Node,
        dst: Node,
        max_bandwidth: float,
        base_latency: Optional[float] = 0,
        encryption_overhead: float = 0.0,
        auth_latency: float = 0.0,
    ):
        super().__init__(src, dst, max_bandwidth, base_latency)
        self.encryption_overhead = encryption_overhead  # as fraction of payload size (0-1)
        self.auth_latency = auth_latency  # fixed latency component (seconds)

    def effective_payload_bits(self, bits: float, requires_encryption: bool) -> float:
        """Return the effective number of bits after encryption expansion (if any)."""
        if requires_encryption and self.encryption_overhead > 0:
            return bits * (1.0 + self.encryption_overhead)
        return bits

    def extra_security_latency(self, requires_auth: bool) -> float:
        """Return extra fixed latency if authentication is required."""
        return self.auth_latency if requires_auth and self.auth_latency > 0 else 0.0

