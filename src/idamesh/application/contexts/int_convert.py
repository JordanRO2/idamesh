"""The int_convert use-case."""

from __future__ import annotations

from idamesh.application.dto.int_convert import IntConvertCommand, IntConvertResult
from idamesh.domain.services.number import NumberService


class IntConvertUseCase:
    """Reinterpret an integer token across representations at a bit width.

    A thin adapter over the pure
    :class:`~idamesh.domain.services.number.NumberService`: it forwards the
    ``value`` token and ``bits`` width and wraps the resulting
    :class:`~idamesh.domain.entities.number_conversion.NumberConversion`.
    """

    def __init__(self, number: NumberService) -> None:
        self._number = number

    def execute(self, command: IntConvertCommand) -> IntConvertResult:
        """Convert ``command.value`` at ``command.bits`` and wrap the result.

        An unparseable token or an out-of-range bit width surfaces as an error
        the interface layer renders as an ``isError`` result.
        """
        conversion = self._number.convert(command.value, command.bits)
        return IntConvertResult(conversion=conversion)
