resource "aws_rds_cluster" "unencrypted_cluster" {
  cluster_identifier  = "test-cluster"
  engine              = "aurora-postgresql"
  storage_encrypted   = true
}