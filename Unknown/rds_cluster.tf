resource "aws_rds_cluster" "unknown_cluster" {
  cluster_identifier = "unknown-cluster"
  engine             = "aurora-postgresql"
  storage_encrypted  = var.cluster_encrypted
}

resource "aws_rds_cluster_instance" "unknown_instance" {
  identifier          = "unknown-instance"
  cluster_identifier  = "unknown-cluster"
  instance_class      = "db.t3.medium"
  engine              = "aurora-postgresql"
  publicly_accessible = var.instance_public
}