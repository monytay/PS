resource "aws_db_instance" "exposed_db" {
  engine = "postgres"
  publicly_accessible = false
  instance_class = "db.t3.micro"
}ß