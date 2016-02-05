from . import pull_url

def test_pull(tmpdir):
    dest = str(tmpdir.join("dest"))

    p = pull_url.Pull()
    p.pull("ssh://gold.broadinstitute.org/xchip/datasci/pmontgom/testfile", dest)
    assert open(dest).read() == "sample\n"