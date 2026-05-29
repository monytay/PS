import hcl2
import os
import sys

# We use os.walk to collect all terraform files in all directories and subdirectories
def collect_tf_files(repo_path):
    tf_files = []
    for root, dirs, files in os.walk(repo_path):
        for filename in files:
            if filename.endswith(".tf"):
                tf_files.append(os.path.join(root,filename))
    return tf_files

# we parse the data into a python dictionary first with hcl2 library
def parse(filePlaceholder):
    with open(filePlaceholder, 'r') as f:
        data = hcl2.load(f)
    return data

# we utilize the previous function to parse all .tf files and add them to the same list of data
def parse_all(repo_path):
    parsed = []
    for path in collect_tf_files(repo_path):
        parsed.append((path,parse(path)))
    return parsed

# Helper function for unwraping HCL code
def unwrap(value):
    if isinstance(value, list):
        return value[0] if value else None
    return value

def control_28(parsedFiles):
    for path, data in parsedFiles:
        for block in data.get("resource",[]):
            if "aws_iam_account_password_policy" in block:
                policy = block["aws_iam_account_password_policy"]
                for resource_name, args in policy.items():
                    length = unwrap(args.get("minimum_password_length"))
                    if length is not None and length >= 14:
                        return True
    return False

#Method to check public access
def control_314(parsedFiles):
    for path, data in parsedFiles:
        for block in data.get("resource", []):
            if "aws_s3_bucket_public_access_block" in block:
                policy = block["aws_s3_bucket_public_access_block"]
                for rescource_name, args in policy.items():
                    public_acls = unwrap(args.get("block_public_acls"))
                    public_policy = unwrap(args.get("block_public_policy"))
                    ignore_acls = unwrap(args.get("ignore_public_acls"))
                    restrict = unwrap(args.get("restrict_public_buckets"))
                    #Checking all parameters
                    if public_acls == True and public_policy == True and ignore_acls == True and restrict == True:
                        return True
    return False

#Method for confirming DB encryption
def control_321(parsedFiles):
    findings = []
    for path, data in parsedFiles:
        for block in data.get("resource", []):
            #Method to confirm encryption of single rds instances
            if "aws_db_instance" in block:
                db = block["aws_db_instance"]
                for database_name, args in db.items():
                    encrypted = unwrap(args.get("storage_encrypted"))
                    if encrypted != True:
                        findings.append({
                            "file": path,
                            "resource_type": "aws_db_instance",
                            "resource_name": database_name
                        })
            #Method to confirm encryption of cluster rds instances or Aurora
            if "aws_rds_cluster" in block:
                for database_name, args in block["aws_rds_cluster"].items():
                    encrypted = unwrap(args.get("storage_encrypted"))
                    if encrypted != True:
                        findings.append({
                            "file": path,
                            "resource_type":"aws_rds_cluster",
                            "resource_name": database_name
                        })
    return findings

def ScannerApp(filePath):
    # Parse the file using our method so we can run our checks
    parsedFiles = parse_all(filePath)
    #We will record the specific control in the results and add additional information
    results = {
        "CIS 2.8": control_28(parsedFiles),
        "CIS 3.1.4": control_314(parsedFiles),
        "CIS 3.2.1": control_321(parsedFiles)
        }
    
    return results

if __name__ == "__main__":
    repo = sys.argv[1]
    print(ScannerApp(repo))