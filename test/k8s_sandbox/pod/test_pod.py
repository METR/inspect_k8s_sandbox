import pytest

from k8s_sandbox._pod.execute import _MarkedStream

MARKER = "<completed-sentinel-value-0123456789abcdef0123456789abcdef-"


@pytest.mark.parametrize(
    ("frame", "output", "returncode"),
    [
        pytest.param(b"before{m}42>after", "before", 42, id="output-after-dropped"),
        pytest.param(b"a\nb{m}42>\nc\nd", "a\nb", 42, id="new-lines"),
        pytest.param(b"stdout", "stdout", None, id="not-present"),
        pytest.param(b"", "", None, id="empty"),
        pytest.param(b"{m}42>after", "", 42, id="nothing-preceding"),
        pytest.param(b"before{m}42>", "before", 42, id="nothing-following"),
        pytest.param(b"{m}0>", "", 0, id="0"),
        pytest.param(b"{m}255>", "", 255, id="255"),
    ],
)
def test_marked_stream(frame: bytes, output: str, returncode: int | None) -> None:
    stream = _MarkedStream(MARKER)

    stream.append(frame.replace(b"{m}", MARKER.encode()))
    stream.flush()

    assert (str(stream.buffer), stream.returncode) == (output, returncode)
