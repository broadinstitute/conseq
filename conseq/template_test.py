import jinja2
from . import depexec

def test_recursive_config_values():
    jinja2_env = jinja2.Environment(undefined=jinja2.StrictUndefined)
    assert depexec.render_template(jinja2_env, "x", {}) == "x"
    assert depexec.render_template(jinja2_env, "x{{config.y}}", {"y":"z"}) == "xz"
    assert depexec.render_template(jinja2_env, "x{{config.y}}", {"y":"{{config.yy}}", "yy":"zz"}) == "xzz"
