import json

import jinja2
import six


class LazyConfig:
    def __init__(self, render_template, config_dict):
        self._config_dict = config_dict
        self._render_template = render_template

    def get(self, name, default=None):
        if name in self:
            return self[name]
        else:
            return default

    def __contains__(self, name):
        return name in self._config_dict

    def __getitem__(self, name):
        v = self._config_dict[name]
        if isinstance(v, str):
            return self._render_template(v)
        else:
            return v

    def __getattr__(self, item):
        return self.__getitem__(item)

    def __repr__(self):
        return "<LazyConfig {}>".format(repr(self._config_dict))


class MissingTemplateVar(Exception):
    def __init__(self, message, variables, template):
        super(MissingTemplateVar, self).__init__()
        self.variables = variables
        self.template = template
        self.message = message

    def get_error(self):
        var_defs = []
        for k, v in self.variables.items():
            if isinstance(v, dict):
                var_defs.append("  {}:".format(repr(k)))
                for k2, v2 in v.items():
                    var_defs.append("    {}: {}".format(repr(k2), repr(v2)))
            else:
                var_defs.append("  {}: {}".format(repr(k), repr(v)))

        var_block = "".join(x + "\n" for x in var_defs)
        return (
            "Template error: {}, applying vars:\n{}\n to template:\n{}".format(self.message, var_block, self.template))


def render_template(jinja2_env, template_text, config, **kwargs):
    assert isinstance(template_text, six.string_types), "Expected string for template but got {}".format(
        repr(template_text))
    kwargs = dict(kwargs)

    def render_template_callback(text):
        try:
            rendered = jinja2_env.from_string(text).render(**kwargs)
            return rendered
        except jinja2.exceptions.UndefinedError as ex:
            raise MissingTemplateVar(ex.message, kwargs, text)

    kwargs["config"] = LazyConfig(render_template_callback, config)

    return render_template_callback(template_text)


def _quote_str(x):
    if isinstance(x, jinja2.StrictUndefined):
        return x
    else:
        return json.dumps(x)


def create_jinja2_env():
    jinja2_env = jinja2.Environment(undefined=jinja2.StrictUndefined)

    jinja2_env.filters['quoted'] = _quote_str
    return jinja2_env

def create_template_jinja2_env():
    return jinja2.Environment(
    loader=jinja2.PackageLoader('conseq', 'templates'),
    autoescape=jinja2.select_autoescape(['html', 'xml'])
)
