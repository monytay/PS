from Helper_Functions import Helper_Functions, unwrap, UNKNOWN
from Helper_Functions_63 import check_legacy_rule, check_modern_rule, evaluate

class Control_Functions(Helper_Functions,Helper63):
    def control_28(parsedFiles):
        findings = []
        unknowns = []
        for path, data in parsedFiles:
            for block in data.get("resource",[]):
                if "aws_iam_account_password_policy" in block:
                    policy = block["aws_iam_account_password_policy"]
                    for resource_name, args in policy.items():
                        length = unwrap(args.get("minimum_password_length"))
                        if length == UNKNOWN:
                            unknowns.append({
                                "file" : path,
                                "resource_type" : "aws_iam_account_password_policy",
                                "resource_name" : resource_name,
                                "reason" : f"The value is recorded in a variable or variable file"
                            })
                        elif length is None or length < 14:
                            findings.append({
                                "file":path,
                                "resource_type":"aws_iam_account_password_policy",
                                "resource_name":resource_name,
                                "reason":f"minimum_password_length was {length}, required >= 14"
                            })
        return findings, unknowns

    #Method to check public access
    def control_314(parsedFiles):
        findings = []
        unknowns = []
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
                        attributes = [
                            ("block_public_acls", public_acls),
                            ("block_public_policy", public_policy),
                            ("ignore_public_acls", ignore_acls),
                            ("restrict_public_buckets", restrict)
                        ]
                        for attribute_name, value in attributes:
                            if value == UNKNOWN:
                                unknowns.append({
                                    "file": path,
                                    "resource_type": "aws_s3_bucket_public_access_block",
                                    "resource_name": resource_name,
                                    "attribute": attribute_name,
                                    "reason": "The value is recorded in a variable or variable file"
                                })
                            elif value != True:
                                findings.append({
                                    "file": path,
                                    "resource_type": "aws_s3_bucket_public_access_block",
                                    "resource_name": resource_name,
                                    "attribute": attribute_name,
                                    "reason": f"{attribute_name} was {value}, required True"
                                })
                    
                if "aws_s3_account_public_access_block" in block:
                    policy = block["aws_s3_account_public_access_block"]
                    for resource_name, args in policy.items():
                        public_acls = unwrap(args.get("block_public_acls"))
                        public_policy = unwrap(args.get("block_public_policy"))
                        ignore_acls = unwrap(args.get("ignore_public_acls"))
                        restrict = unwrap(args.get("restrict_public_buckets"))
                        #Checking all parameters
                        attributes = [
                            ("block_public_acls", public_acls),
                            ("block_public_policy", public_policy),
                            ("ignore_public_acls", ignore_acls),
                            ("restrict_public_buckets", restrict)
                        ]
                        for attribute_name, value in attributes:
                            if value == UNKNOWN:
                                unknowns.append({
                                    "file": path,
                                    "resource_type": "aws_s3_account_public_access_block",
                                    "resource_name": resource_name,
                                    "attribute": attribute_name,
                                    "reason": "The value is recorded in a variable or variable file"
                                })
                            elif value != True:
                                findings.append({
                                    "file": path,
                                    "resource_type": "aws_s3_account_public_access_block",
                                    "resource_name": resource_name,
                                    "attribute": attribute_name,
                                    "reason": f"{attribute_name} was {value}, required True"
                                })
        return findings, unknowns

    #Method for confirming DB encryption
    def control_321(parsedFiles):
        findings = []
        unknowns = []
        for path, data in parsedFiles:
            for block in data.get("resource", []):
                #Method to confirm encryption of single rds instances
                if "aws_db_instance" in block:
                    db = block["aws_db_instance"]
                    for database_name, args in db.items():
                        encrypted = unwrap(args.get("storage_encrypted"))
                        if encrypted == UNKNOWN:
                            unknowns.append({
                                "file": path,
                                "resource_type": "aws_db_instance",
                                "resource_name": database_name,
                                "reason" : "The value is recorded in a variable or variable file"
                            })
                        elif encrypted != True:
                            findings.append({
                                "file": path,
                                "resource_type": "aws_db_instance",
                                "resource_name": database_name
                            })
                #Method to confirm encryption of cluster rds instances or Aurora
                if "aws_rds_cluster" in block:
                    for database_name, args in block["aws_rds_cluster"].items():
                        encrypted = unwrap(args.get("storage_encrypted"))
                        if encrypted == UNKNOWN:
                            unknowns.append({
                                "file": path,
                                "resource_type": "aws_rds_cluster",
                                "resource_name": database_name,
                                "reason" : "The value is recorded in a variable or variable file"
                            })
                        elif encrypted != True:
                            findings.append({
                                "file": path,
                                "resource_type":"aws_rds_cluster",
                                "resource_name": database_name
                            })
        return findings, unknowns

    #Method for ensuring no public access is granted
    def control_323(parsedFiles):
        findings = []
        unknowns = []
        for path, data in parsedFiles:
            for block in data.get("resource", []):

                if "aws_db_instance" in block:
                    db = block["aws_db_instance"]
                    for database_name, args in db.items():
                        access = unwrap(args.get("publicly_accessible"))
                        if access == UNKNOWN:
                            unknowns.append({
                                "file":path,
                                "resource_type":"aws_db_instance",
                                "resource_name": database_name,
                                "reason":f"The value is recorded in a variable or variable file"
                            })
                        elif access == True:
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
                        if access == UNKNOWN:
                            unknowns.append({
                                "file":path,
                                "resource_type":"aws_rds_cluster_instance",
                                "resource_name": database_name,
                                "reason":f"The value is recorded in a variable or variable file"
                            })
                        elif access == True:
                            findings.append({
                                "file":path,
                                "resource_type":"aws_rds_cluster_instance",
                                "resource_name":database_name,
                                "reason":f"Public access was {access}, CIS requires False or unset"
                            })
        return findings, unknowns
                        
    #Method for ensuring Cloudtrail is enabled in all regions
    def control_41(parsedFiles):
        findings = []
        unknowns = []
        for path, data in parsedFiles:
            for block in data.get("resource", []):
                if "aws_cloudtrail" in block:
                    cloudTrail = block["aws_cloudtrail"]
                    for cloudTrail_name, args in cloudTrail.items():
                        regions = unwrap(args.get("is_multi_region_trail"))
                        logging = unwrap(args.get("enable_logging"))
                        if regions == UNKNOWN or logging == UNKNOWN:
                            unknowns.append({
                                "file":path,
                                "resource_type":"aws_cloudtrail",
                                "resource_name": cloudTrail_name,
                                "reason" : "The value is recorded in a variable or variable file"
                            })
                        elif regions != True or logging != True:
                            findings.append({
                                "file":path,
                                "resource_type":"aws_cloudtrail",
                                "resource_name": cloudTrail_name
                            })
        return findings, unknowns

    def control_63(parsedFiles):
        findings = []
        unknowns = []
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
                            if violation == UNKNOWN:
                                unknowns.append({
                                    "file": path,
                                    "resource_type": "aws_security_group(inline ingress)",
                                    "resource_name": sg_name,
                                    "reason": "The value is recorded in a variable or variable file"
                                })
                            elif violation:
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
                        if violation == UNKNOWN:
                            unknowns.append({
                                "file": path,
                                "resource_type": "aws_security_group_rule",
                                "resource_name": rule_name,
                                "reason": "The value is recorded in a variable or variable file"
                            })
                        elif violation:
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
                        if violation == UNKNOWN:
                            unknowns.append({
                                "file": path,
                                    "resource_type": "aws_vpc_security_group_ingress_rule",
                                    "resource_name": rule_name,
                                    "reason": "The value is recorded in a variable or variable file"
                            })
                        elif violation:
                                findings.append({
                                    "file": path,
                                    "resource_type": "aws_vpc_security_group_ingress_rule",
                                    "resource_name": rule_name,
                                    "reason": violation
                                })
        return findings, unknowns