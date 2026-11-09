"""Verify embedded Git identities against Cargo metadata."""


def resolved_provenance(fixtures, metadata):
    result = {}
    for field, name in [("local_interpreter", "bitcoin-scriptexec"), ("compiler", "bitcoin-script")]:
        claimed = fixtures[field]
        packages = [package for package in metadata["packages"] if package["name"] == name]
        if len(packages) != 1:
            raise RuntimeError(f"Expected exactly one resolved {name} package")
        package = packages[0]
        for key in ("name", "version", "source"):
            if claimed.get(key) != package.get(key):
                raise RuntimeError(f"Compiled {name} {key} differs from Cargo's resolved graph")
        commit = claimed["commit"]
        source = package.get("source")
        if (not isinstance(commit, str) or len(commit) != 40
                or any(character not in "0123456789abcdef" for character in commit)
                or not isinstance(source, str) or not source.startswith("git+")
                or source.rpartition("#")[2] != commit):
            raise RuntimeError(f"Expected an immutable resolved git commit for {name}")
        result[field] = {key: package[key] for key in ("name", "version", "source")}
    return result
