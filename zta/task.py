from typing import Optional

from core.task import Task


class ZTATask(Task):
    """
    Task with Zero Trust attributes.

    Adds criticality and data sensitivity; and whether encryption/auth are required.
    """

    def __init__(
        self,
        task_id: int,
        task_size: int,
        cycles_per_bit: int,
        trans_bit_rate: int,
        src_name: str,
        ddl: Optional[int] = -1,
        task_name: Optional[str] = "",
        criticality: str = "low",  # 'low' | 'high'
        sensitivity: float = 0.0,   # 0..1
        requires_encryption: bool = True,
        requires_auth: bool = True,
    ):
        super().__init__(
            task_id=task_id,
            task_size=task_size,
            cycles_per_bit=cycles_per_bit,
            trans_bit_rate=trans_bit_rate,
            src_name=src_name,
            ddl=ddl,
            task_name=task_name,
        )
        self.criticality = criticality
        self.sensitivity = sensitivity
        self.requires_encryption = requires_encryption
        self.requires_auth = requires_auth

