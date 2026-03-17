terraform {
  backend "s3" {
    bucket = "fastapi-terraform-state-12345"
    key = "ecs/terraform.tfstate"
    region = "us-east-1"
    dynamodb_table = "terraform-lock"
    encrypt = true
  }
}