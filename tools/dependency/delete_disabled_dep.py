import os
from importlib.util import spec_from_loader, module_from_spec
from importlib.machinery import SourceFileLoader



# Shared Starlark/Python files must have a .bzl suffix for Starlark import, so
# we are forced to do this workaround.
def load_module(name, path):
    spec = spec_from_loader(name, SourceFileLoader(name, path))
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def put_in_quotes(string):
  return "\""+string+"\""

ENVOY_VERSION = "1_29_4"

api_path = "/workspace/5g_proto/devtools/envoy-builder/sc_envoy/api"
path = "/workspace/5g_proto/devtools/envoy-builder/sc_envoy/bazel/repository_locations.bzl"

repository_locations_utils = load_module(
    'repository_locations_utils', os.path.join(api_path, 'bazel/repository_locations_utils.bzl'))
spec_loader = repository_locations_utils.load_repository_locations_spec

# Load repositories
path_module_for_rep_loc = load_module('repository_locations', path)
rep_loc_spec = spec_loader(path_module_for_rep_loc.REPOSITORY_LOCATIONS_SPEC)

# Load build extentions
path = "/workspace/5g_proto/devtools/envoy-builder/sc_envoy/source/extensions/extensions_build_config.bzl"
path_module = load_module('extensions_build_config', path)
extentions_build = path_module.EXTENSIONS

# Load contrib extentions
path = "/workspace/5g_proto/devtools/envoy-builder/sc_envoy/contrib/contrib_build_config.bzl"
path_module = load_module('contrib_build_config', path)
extentions_contrib = path_module.CONTRIB_EXTENSIONS

repos_in_use = {}
print(f"Original Size: {len(rep_loc_spec)}")
for rep in rep_loc_spec.items():
    if "use_category" in rep[1] and ("test_only" in rep[1]["use_category"] or ["build"] == rep[1]["use_category"]):
      continue
    if "extensions" in rep[1]:
      if len(rep[1]["extensions"]) == 0:
        repos_in_use[rep[0]] = rep[1]
      is_in_use = False
      for ext in rep[1]["extensions"]:
        is_active = ext in extentions_build or ext in extentions_contrib
        is_in_use = is_in_use or is_active
      if is_in_use:
        repos_in_use[rep[0]] = rep[1]
    else:
      repos_in_use[rep[0]] = rep[1]
print(f"End Size: {len(repos_in_use)}")
with open("repository_locations_envoy_"+ENVOY_VERSION+".bzl", 'w') as file:
  file.write("PROTOBUF_VERSION = " + put_in_quotes(path_module_for_rep_loc.PROTOBUF_VERSION))
  file.write("\n\n")
  file.write("REPOSITORY_LOCATIONS_SPEC = dict(\n")
  for r in repos_in_use.items():
    file.write("    " + r[0] + " = dict(\n")
    for t in r[1].items():
      if type(t[1]) is str:
        file.write("        " + t[0] + " = " + put_in_quotes(t[1]) + ",\n")
      else:
        file.write("        " + t[0] + " = [")
        for e in t[1]:
          if e == t[1][-1]:
            file.write(put_in_quotes(e))
          else:
            file.write(put_in_quotes(e) + ",")
        file.write("],\n")
    file.write("    ),\n")
  file.write(")\n")