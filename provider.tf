# Configure the AWS Provider
provider "aws" {
  region = "eu-west-1"
  profile = "Team2access"
}

locals {
  name = "EU2ACP"
}