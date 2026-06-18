import hcl2
import os
import sys
from pprint import pprint

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
        parsed.append((path,parse(path)))
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

def control_63(parsedFiles):
    findings = []
    ADMIN_PORTS = [22, 3389]
    OPEN_CIDRS_V4 = ["0.0.0.0/0"]
    OPEN_CIDRS_V6 = ["::/0"]
    OPEN_PROTOCOLS = ["tcp", "udp", "-1"]

    for path, data in parsedFiles:
        for block in data.get("resource", []):

            #Pattern 1: ingress block for security grpups
            if "aws_security_group" in block:
                sg = block["aws_security_group"]
                for sg_name, args in sg.items():
                    ingress_rule = args.get("ingress", [])
                    for rule in ingress_rule:
                        violation = check_legacy_rule(rule)
                        if violation:
                            findings.append({
                                "file": path,
                                "resource_type": "aws_security_group(inline ingress)",
                                "resource_name": sg_name,
                                "reason": violation
                            })

            #Pattern 2: Security group rule
            if "aws_security_group_rule" in block:
                rules = block["aws_security_group_rule"]
                for rule_name, args in rules.items():
                    rule_type = unwrap(args.get("type"))
                    if rule_type != "ingress":
                        continue
                    violation = check_legacy_rule(args)
                    if violation:
                            findings.append({
                                "file": path,
                                "resource_type": "aws_security_group_rule",
                                "resource_name": rule_name,
                                "reason": violation
                            })

            #Pattern 3: modern aws_vpc_security_group_ingress_rule
            if "aws_vpc_security_group_ingress_rule" in block:
                rules = block["aws_vpc_security_group_ingress_rule"]
                for rule_name, args in rules.items():
                    violation = check_modern_rule(args)
                    if violation:
                            findings.append({
                                "file": path,
                                "resource_type": "aws_vpc_security_group_ingress_rule",
                                "resource_name": rule_name,
                                "reason": violation
                            })
    return findings

#Used in Pattern 1 and 2
def check_legacy_rule(rule):
    from_port = unwrap(rule.get("from_port"))
    to_port = unwrap(rule.get("to_port"))
    protocol = unwrap(rule.get("protocol"))
    cidr_blocks = rule.get("cidr_blocks") or []
    ipv6_cidr_blocks = rule.get("ipv6_cidr_blocks") or []

    #Made to handle potential double wrapping from hcl2
    if cidr_blocks and isinstance(cidr_blocks[0], list):
        cidr_blocks = cidr_blocks[0]
    if ipv6_cidr_blocks and isinstance(ipv6_cidr_blocks[0], list):
        ipv6_cidr_blocks = ipv6_cidr_blocks[0]
    
    return evaluate(from_port, to_port, protocol, cidr_blocks, ipv6_cidr_blocks)

#Used in Patern 3
def check_modern_rule(rule):
    from_port = unwrap(rule.get("from_port"))
    to_port = unwrap(rule.get("to_port"))
    protocol = unwrap(rule.get("ip_protocol"))
    cidr_ipv4 = unwrap(rule.get("cidr_ipv4"))
    cidr_ipv6 = unwrap(rule.get("cidr_ipv6"))

    cidr_blocks = [cidr_ipv4] if cidr_ipv4 else []
    ipv6_cidr_blocks = [cidr_ipv6] if cidr_ipv6 else []

    return evaluate(from_port, to_port, protocol, cidr_blocks, ipv6_cidr_blocks)

def evaluate(from_port, to_port, protocol, cidr_v4_list, cidr_v6_list):
    if from_port is None or to_port is None:
        return None
    
    if str(protocol).lower() not in ["tcp", "udp", "-1"]:
        return None
    
    hit_ports = []
    for port in [22, 3389]:
        if from_port <= port <= to_port:
            hit_ports.append(port)
    if not hit_ports:
        return None
    
    if "0.0.0.0/0" in cidr_v4_list:
        return f"Port(s) {hit_ports} open to 0.0.0.0/0 (protocol = {protocol})"
    if "::/0" in cidr_v6_list:
        return f"Port(s) {hit_ports} open to ::/0 (protocol = {protocol})"

    return None


def ScannerApp(filePath):
    # Parse the file using our method so we can run our checks
    parsedFiles = parse_all(filePath)
    print(parsedFiles)
    #We will record the specific control in the results and add additional information
    results = {
        "CIS 2.8": control_28(parsedFiles),
        "CIS 3.1.4": control_314(parsedFiles),
        "CIS 3.2.1": control_321(parsedFiles),
        "CIS 3.2.3": control_323(parsedFiles),
        "CIS 4.1": control_41(parsedFiles),
        "CIS 6.3": control_63(parsedFiles),
        }
    
    return results

if __name__ == "__main__":
    repo = sys.argv[1]
    results = ScannerApp(repo)
    for control, findings in results.items():
        print(f"{control}: {findings}")