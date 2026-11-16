class ArtifactTypeMismatch(Exception):
    pass


class MissingOutputDeclaration(Exception):
    """A rule declares neither `outputs` nor `output_types`, so we can't tell what it produces"""
