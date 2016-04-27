import time
import textwrap

from conseq import exec_client

def test_basic_sge_job_exec(tmpdir):
    job_dir = str(tmpdir)
    with open(job_dir+"/script1", "wt") as fd:
        fd.write(textwrap.dedent("""
        print("run")
        """))
        fd.close()

    c = exec_client.SgeExecClient("datasci-dev", "use UGER")

    e = c.exec_script("name", "ID", job_dir, ["python script1"], {"name": "banana"}, True, "", "desc")
    while True:
        output, failure = e.get_completion()
        assert failure is None
        if output is not None:
            break
        time.sleep(5)

    assert output == {"name": "banana"}

def test_sge_job_reattach(tmpdir):
    job_dir = str(tmpdir)
    with open(job_dir+"/script1", "wt") as fd:
        fd.write(textwrap.dedent("""
        print("ran")
        """))
        fd.close()

    c = exec_client.SgeExecClient("datasci-dev", "use UGER")

    e = c.exec_script("name", "ID", job_dir, ["python script1"], {"name": "test_sge_job_reattach"}, True, "", "desc")
    extern_id = e.get_external_id()

    c2 = exec_client.SgeExecClient("datasci-dev", "use UGER")
    e2 = c2.reattach(extern_id)

    while True:
        output, failure = e2.get_completion()
        assert failure is None
        if output is not None:
            break
        time.sleep(5)

    assert output == {"name": "test_sge_job_reattach"}



def test_sge_job_write_file(tmpdir):
    job_dir = str(tmpdir)
    with open(job_dir+"/script1", "wt") as fd:
        fd.write(textwrap.dedent("""
        fd = open("output.txt", "wt")
        fd.write("hello")
        fd.close()
        """))
        fd.close()

    c = exec_client.SgeExecClient("datasci-dev", "use UGER")

    e = c.exec_script("name", "ID", job_dir, ["python script1"], {"file": {"$filename": "output.txt"}}, True, "", "desc")
    while True:
        output, failure = e.get_completion()
        assert failure is None
        if output is not None:
            break
        time.sleep(5)

    assert "file" in output
    assert type(output["file"]) == dict and not ("$filename" in output["file"])

