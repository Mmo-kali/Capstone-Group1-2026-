"""Helper utilities for business logic."""

from dataclasses import dataclass


@dataclass
class ProcessedResult:
    """Represents processed output for display."""

    username: str
    masked_password: str
    domain: str
    dc_ip: str
    dc_fqdn: str
    message: str


def process_user_input(
    username: str,
    password: str,
    domain: str,
    dc_ip: str,
    dc_fqdn: str,
) -> ProcessedResult:
    """Process user input from the form.

    Args:
        username: Provided username.
        password: Provided password.
        domain: Provided domain.
        dc_ip: Provided domain controller IP.
        dc_fqdn: Provided domain controller FQDN.

    Returns:
        ProcessedResult: Processed data for output display.
    """
    # Placeholder for additional processing logic
    masked_password = "*" * len(password)
    message = f"Welcome, {username}. Your domain is set to {domain}."

    return ProcessedResult(
        username=username,
        masked_password=masked_password,
        domain=domain,
        dc_ip=dc_ip,
        dc_fqdn=dc_fqdn,
        message=message,
    )
