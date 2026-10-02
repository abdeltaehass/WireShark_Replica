class DisplayFilterError(Exception):
    """A display filter can't be compiled, and where it goes wrong.

    ``start`` and ``end`` are the characters of the filter the message is
    about, counted from 0, with ``end`` one past the last of them. A filter
    that stops too soon points one past its own end.
    """

    def __init__(self, message: str, text: str, start: int, end: int | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.text = text
        self.start = start
        self.end = max(start + 1, start + 1 if end is None else end)

    def pointer(self) -> str:
        """The filter, with a marker on the line below under the part that is wrong::

        ip.src == hello
                  ^~~~~
        """
        # A tab or a line break would put the marker under the wrong column.
        shown = "".join(" " if character.isspace() else character for character in self.text)
        marker = " " * self.start + "^" + "~" * (self.end - self.start - 1)
        return f"{shown}\n{marker}"
