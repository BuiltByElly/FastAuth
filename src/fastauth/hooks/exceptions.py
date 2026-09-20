from fastapi import HTTPException


class HookAbort(HTTPException):
    """
    Raised when a hook is intentionally aborted.
    """

    def __init__(self, status_code: int = 400, detail: str = "Rejected"):
        super().__init__(status_code=status_code, detail=detail)
