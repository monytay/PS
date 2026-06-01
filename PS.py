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

#Method ensures length of password for IAM account is at least 14 characters long
def control_28(parsedFiles):
    findings = []
    for path, data in parsedFiles:
        for block in data.get("resource",[]):
            if "aws_iam_account_password_policy" in block:
                policy = block["aws_iam_account_password_policy"]
                for resource_name, args in policy.items():
                    length = unwrap(args.get("minimum_password_length"))
                    if length is None or length < 14:
                        findings.append({
                            "file":path,
                            "resource_type":"aws_iam_account_password_policy",
                            "resource_name":resource_name,
                            "reason":f"minimum_password_length was {length}, required >= 14"
                        })
    return findings

#Method to check public access
def control_314(parsedFiles):
    findings = []
    for path, data in parsedFiles:
        for block in data.get("resource", []):

            if "aws_s3_bucket_public_access_block" in block:
                policy = block["aws_s3_bucket_public_access_block"]
                for resource_name, args in policy.items():
                    public_acls = unwrap(args.get("block_public_acls"))
                    public_policy = unwrap(args.get("block_public_policy"))
                    ignore_acls = unwrap(args.get("ignore_public_acls"))
                    restrict = unwrap(args.get("restrict_public_buckets"))
                    #Checking all parameters
                    if public_acls != True or public_policy != True or ignore_acls != True or restrict != True:
                        findings.append({
                            "file": path,
                            "resource_type":"aws_s3_bucket_public_access_block",
                            "resource_name":resource_name
                        })
        
            if "aws_s3_account_public_access_block" in block:
                policy = block["aws_s3_account_public_access_block"]
                for resource_name, args in policy.items():
                    public_acls = unwrap(args.get("block_public_acls"))
                    public_policy = unwrap(args.get("block_public_policy"))
                    ignore_acls = unwrap(args.get("ignore_public_acls"))
                    restrict = unwrap(args.get("restrict_public_buckets"))
                    #Checking all the parameters
                    if public_acls != True or public_policy != True or ignore_acls != True or restrict != True:
                        findings.append({
                            "file": path,
                            "resource_type":"aws_s3_account_public_access_block",
                            "resource_name":resource_name
                        })

    return findings

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

#Method for ensuring no public access is granted
def control_323(parsedFiles):
    findings = []
    for path, data in parsedFiles:
        for block in data.get("resource", []):

            if "aws_db_instance" in block:
                db = block["aws_db_instance"]
                for database_name, args in db.items():
                    access = unwrap(args.get("publicly_accessible"))
                    if access == True:
                        findings.append({
                            "file":path,
                            "resource_type":"aws_db_instance",
                            "resource_name": database_name,
                            "reason":f"Public access was {access}, CIS requires False or unset"
                        })
            
            if "aws_rds_cluster_instance" in block:
                db = block["aws_rds_cluster_instance"]
                for database_name, args in db.items():
                    access = unwrap(args.get("publicly_accessible"))
                    if access == True:
                        findings.append({
                            "file":path,
                            "resource_type":"aws_rds_cluster_instance",
                            "resource_name":database_name,
                            "reason":f"Public access was {access}, CIS requires False or unset"
                        })
    return findings
                    
#Method for ensuring Cloudtrail is enabled in all regions
def control_41(parsedFiles):
    findings = []
    for path, data in parsedFiles:
        for block in data.get("resource", []):
            if "aws_cloudtrail" in block:
                cloudTrail = block["aws_cloudtrail"]
                for cloudTrail_name, args in cloudTrail.items():
                    regions = unwrap(args.get("is_multi_region_trail"))
                    logging = unwrap(args.get("enable_logging"))
                    if regions != True or logging == False:
                        findings.append({
                            "file":path,
                            "resource_type":"aws_cloudtrail",
                            "resource_name": cloudTrail_name
                        })
    return findings

def ScannerApp(filePath):
    # Parse the file using our method so we can run our checks
    parsedFiles = parse_all(filePath)
    #We will record the specific control in the results and add additional information
    results = {
        "CIS 2.8": control_28(parsedFiles),
        "CIS 3.1.4": control_314(parsedFiles),
        "CIS 3.2.1": control_321(parsedFiles),
        "CIS 3.2.3": control_323(parsedFiles),
        "CIS 4.1": control_41(parsedFiles)
        }
    
    return results

if __name__ == "__main__":
    repo = sys.argv[1]
    print(ScannerApp(repo))