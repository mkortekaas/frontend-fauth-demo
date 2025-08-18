terraform {
  required_providers {
    aws = {
      source                    = "hashicorp/aws"
      version                   = ">=6.9.0"
    }
    fusionauth = {
      source                    = "FusionAuth/fusionauth"
      version                   = ">=1.1.0"
    }
  }
  required_version              = ">=1.10.3"

  backend "s3" {
    bucket                      = "XXXX-tf-state"
    key                         = "XXXX-fa-dev.tfstate"
    region                      = "us-east-2"
  }
}

# this pulls in from the envvars FA_API_KEY and FA_DOMAIN
provider "fusionauth" { }
provider "aws" {
  region = "us-east-2"
}

## this is just a reference to a module that has outputs defined in it
module "global-variables" {  source = "../../environments-aws/modules/global-variables" }

data "fusionauth_tenant" "default"{
  name                       = "Default"
}

data "fusionauth_application" "FusionAuth" {
  name                       = "FusionAuth"
}

# you may not have this if not enterprise edition of FA
data "fusionauth_application" "TenantManager" {
  name                       = "Tenant manager"
}
