import json
import jinja2
import six
from typing import Dict, Any
from typing import Union, Tuple
from conseq.types import PropsType
from jinja2 import Environment
from conseq.parser import QueryVariable


class LazyValue:
    def __init__(self, callback):
        self.callback = callback


class AugmentedConfig:
    def __init__(self, config, extra_values):
        self.extra_values = extra_values
        self.config = config

    def get(self, name, default=None):
        if name in self.extra_values:
            return self.extra_values[name]
        return self.config.get(name, default)

    def __contains__(self, name):
        if name in self.extra_values:
            return True
        return name in self.config

    def __getitem__(self, name):
        if name in self.extra_values:
            return self.extra_values[name]
        return self.config[name]

    def __getattr__(self, item):
        return self.__getitem__(item)

    def __repr__(self):
        return f"<AugmentedConfig {repr(self.config)}, {repr(self.extra_values)}>"


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
        if isinstance(v, LazyValue):
            v = v.callback()
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
        return "Template error: {}, applying vars:\n{}\n to template:\n{}".format(
            self.message, var_block, self.template
        )


def render_template(jinja2_env, template_text: str, config: Dict[str, Any], **kwargs):
    assert isinstance(
        template_text, six.string_types
    ), "Expected string for template but got {}".format(repr(template_text))
    kwargs = dict(kwargs)

    def render_template_callback(text):
        try:
            rendered = jinja2_env.from_string(text).render(**kwargs)
            return rendered
        except jinja2.exceptions.UndefinedError as ex:
            raise MissingTemplateVar(ex.message, kwargs, text)

    def _get_script_dir():
        if "SCRIPT_DIR" in kwargs:
            return kwargs["SCRIPT_DIR"]
        if not ("task" in kwargs and "SCRIPT_DIR" in kwargs["task"]):
            raise Exception("Can only use SCRIPT_DIR variable inside of rules")
        return kwargs["task"]["SCRIPT_DIR"]

    kwargs["config"] = LazyConfig(
        render_template_callback,
        AugmentedConfig(config, {"SCRIPT_DIR": LazyValue(_get_script_dir)}),
    )

    return render_template_callback(template_text)


def _quote_str(x):
    if isinstance(x, jinja2.StrictUndefined):
        return x
    else:
        return json.dumps(x)


def create_jinja2_env():
    jinja2_env = jinja2.Environment(undefined=jinja2.StrictUndefined)

    jinja2_env.filters["quoted"] = _quote_str
    return jinja2_env


def create_template_jinja2_env():
    return jinja2.Environment(
        loader=jinja2.PackageLoader("conseq", "templates"),
        autoescape=jinja2.select_autoescape(["html", "xml"]),
    )


def expand_dict_item(
    jinja2_env: Environment,
    k: str,
    v: Union[str, Dict[str, str]],
    config: PropsType,
    **kwargs,
) -> Tuple[str, Union[str, Dict[str, str]]]:
    # assert isinstance(config, dict)

    k = render_template(jinja2_env, k, config, **kwargs)
    # QueryVariables get introduced via expand input spec
    if not isinstance(v, QueryVariable):
        if isinstance(v, dict):
            v = expand_dict(jinja2_env, v, config, **kwargs)
        else:
            v = render_template(jinja2_env, v, config, **kwargs)
    return k, v


def expand_dict(
    jinja2_env: Environment, d: PropsType, config: Any, **kwargs,
) -> PropsType:
    assert isinstance(d, dict)
    # assert isinstance(config, dict)

    new_output = {}
    for k, v in d.items():
        #        print("expanding k", k)
        k, v = expand_dict_item(jinja2_env, k, v, config, **kwargs)
        new_output[k] = v

    return new_output
