resource "aws_db_instance" "unknown_db" {
  identifier          = "unknown-db"
  engine              = "postgres"
  instance_class      = "db.t3.micro"
  allocated_storage   = 20
  storage_encrypted   = var.db_encrypted
  publicly_accessible = var.db_public
}