import hcl2
import os

class Helper_Functions():
    UNKNOWN = "UNKNOWN"

    # We use os.walk to collect all terraform files in all directories and subdirectories
    def collect_tf_files(repo_path):
        tf_files = []
        for root, dirs, files in os.walk(repo_path):
            for filename in files:
                if filename.endswith(".tf"):
                    tf_files.append(os.path.join(root,filename))
        return tf_files

    # Cleaning extra '' and ""
    def clean_keys(obj):
        if isinstance(obj, dict):
            return {k.strip('"'): clean_keys(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [clean_keys(i) for i in obj]
        if isinstance(obj,str):
            return obj.strip('"')
        return obj

    # we parse the data into a python dictionary first with hcl2 library
    def parse(filePlaceholder):
        with open(filePlaceholder, 'r') as f:
            data = hcl2.load(f)
        return clean_keys(data)

    # we utilize the previous function to parse all .tf files and add them to the same list of data
    def parse_all(repo_path):
        parsed = []
        for path in collect_tf_files(repo_path):
            try:
                parsed.append((path,parse(path)))
            except Exception:
                pass
        return parsed

    # Helper function for unwraping HCL code
    def unwrap(value):
        if isinstance(value, list):
            value = value[0] if value else None
        if isinstance(value, str) and (
            value.startswith("${var.") or
            value.startswith("var.") or
            value.startswith("${local.") or
            value.startswith("local.")
        ):
            return UNKNOWN
        if isinstance(value, str) and value.lower() == "true":
            return True
        if isinstance(value, str) and value.lower() == "false":
            return False
        return value