from . import xref
import pytest

at_broad = False

@pytest.mark.skipif(not at_broad, reason="need ssh host")
def test_pull(tmpdir):
    dest = str(tmpdir.join("dest"))

    p = xref.Pull()
    p.pull("ssh://gold.broadinstitute.org/xchip/datasci/pmontgom/testfile", dest)
    assert open(dest).read() == "sample\n"