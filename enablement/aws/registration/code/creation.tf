# CrowdStrike - Falcon Encounter Terraform Template
# Version: 23.12.19 - No Gateway with Admin for SE Cloud

# variables
variable "revision" {
  type      = string
  default   = "23.12.19"
}

variable "config_name" {
  type      = string
  default   = "dynamic"
}

variable "template" {
  type      = string
  #types: no-gateway|no-gateway-admin|gateway|hub|spoke
  default   = "no-gateway-admin"
}

variable "backend" {
  type      = string
  default   = "production"
}

# locals
locals {
  config                       = jsondecode(data.http.config.response_body).resources
  networking                   = jsondecode(data.http.networking.response_body).resources
  environment                  = try(local.config.environment, {})
  required_tags = {
	#cstag-owner                = local.config.tags.owner
	#cstag-business             = local.config.tags.department
	#cstag-department           = local.config.tags.department_code
	#cstag-accounting           = local.config.tags.accounting
    cstag-owner                = "ryan.payne"
    cstag-business             = "Sales"
    cstag-department           = "Sales - 310000"
    cstag-accounting           = "dev"
    cstag-user                 = try(local.config.tags.user, var.CS_Owner_Email)
    cstag-envid                = var.CS_Env_Id
    cstag-envalias             = try(local.environment.alias, "")
  }
  networks = {
    vpc_subnet      = try(local.config.variables.vpc_network, "172.17.0.0/16")
    public_subnet   = try(local.config.variables.public_network, "172.17.1.0/24")
    private_subnet  = try(local.config.variables.private_network, "172.17.0.0/24")
  }
}

# context
data "aws_region" "current" {}

data "aws_caller_identity" "current" {}

data "aws_availability_zones" "available" {
  state = "available"
}

# encounter user
data "http" "encounter_metadata" {
  url = "https://falcon.events/sso/idp/cloudshare_aws/metadata.xml"
  #url = "https://falcon.events/sso/idp/aws/metadata.xml"
  request_headers = {
    #Accept = "application/xml" 
  }
}

resource "aws_iam_saml_provider" "default" {
  name                   = "EncounterIdentityProvider"
  saml_metadata_document = data.http.encounter_metadata.body
}

data "http" "BoundaryForAdministratorAccess" {
  url = "https://api.falcon.events/api/environments/cloudshare/class/overview?template_id=cloudshare___cloudshare-boundaryforadministratoraccess_json&environment_id=${var.CS_Env_Id}"
  request_headers = {
    Accept = "application/json"
    User-Agent = "Cloudshare Terraform Runtime"
  }
}

resource "random_id" "id" {
  byte_length = 4
}

resource "aws_iam_policy" "EncounterBoundaryPolicy" {
  name   = "BoundaryForAdministratorAccess"
  policy = data.http.BoundaryForAdministratorAccess.response_body
  tags = merge({
    Name = "Boundary Policy"
  }, local.required_tags)
}

data "aws_iam_policy" "EncounterAdminPolicy" {
  arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_iam_role" "EncounterUser" {
  name = "EncounterAdminRole"
  #path = "/Falcon/"
  permissions_boundary = aws_iam_policy.EncounterBoundaryPolicy.arn
  managed_policy_arns = [data.aws_iam_policy.EncounterAdminPolicy.arn]
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }, {
        Effect = "Allow",
		Principal = {
		  Federated: aws_iam_saml_provider.default.arn
		},
		Action: "sts:AssumeRoleWithSAML",
		  Condition: {
			StringEquals: {
			  "SAML:aud": "https://signin.aws.amazon.com/saml"
			}
		  }
      }
    ]
  })
  tags = {
    tag-key = "tag-value"
  }
}

output "aws_console_url" {
  #value = "https://manage.falcon.events/toolbox/api/host/aws/admin?account=${data.aws_caller_identity.current.id}"
  value = "https://manage.falcon.events/host/cloudshare/aws/admin/:${var.CS_Env_Id}"
}

# infrastructure
data "aws_secretsmanager_secret" "encounter_secrets" {
  arn = "arn:aws:secretsmanager:${data.aws_region.current.name}:710636235725:secret:cloudshare-terraform-secret-x4wkRm"
}

data "aws_secretsmanager_secret_version" "encounter_secrets_version" {
  secret_id  = data.aws_secretsmanager_secret.encounter_secrets.id
}

locals {
  token = sensitive(jsondecode(data.aws_secretsmanager_secret_version.encounter_secrets_version.secret_string)["terraform-key"])
}

data "http" "config" {
  url = "https://api.falcon.events/api/provisioning/config/terraform2/${var.config_name}?environment_id=${var.CS_Env_Id}&region=${data.aws_region.current.name}&revision=${var.revision}&template=${var.template}&account=${data.aws_caller_identity.current.account_id}&_release=${var.backend}"
  request_headers = {
    Accept        = "application/json"
    Authorization = "Bearer ${local.token}"
  }
}

data "http" "networking" {
  url = "https://api.falcon.events/api/provisioning/config/terraform2/networking/${var.config_name}?environment_id=${var.CS_Env_Id}&region=${data.aws_region.current.name}&revision=${var.revision}&template=${var.template}&account=${data.aws_caller_identity.current.account_id}&_release=${var.backend}"
  request_headers = {
    Accept        = "application/json"
    Authorization = "Bearer ${local.token}"
  }
  depends_on = [ data.http.config ]
}


resource "aws_iam_role_policy" "crowdstrike_bootstrap_policy" {
  name = "crowdstrike_bootstrap_policy"
  role = aws_iam_role.crowdstrike_bootstrap_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "ec2:Describe*",
        ]
        Effect   = "Allow"
        Resource = "*"
      },
    ]
  })
}

resource "aws_iam_role" "crowdstrike_bootstrap_role" {
  name = "crowdstrike_bootstrap_role"
  permissions_boundary = aws_iam_policy.EncounterBoundaryPolicy.arn  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      },
    ]
  })
}

resource "aws_iam_role_policy_attachment" "crowdstrike_bootstrap_policy_attach" {
  role       = "${aws_iam_role.crowdstrike_bootstrap_role.name}"
  policy_arn = "${data.aws_iam_policy.EncounterAdminPolicy.arn}"
}

resource "aws_iam_instance_profile" "crowdstrike_bootstrap_profile" {
  name = "crowdstrike_bootstrap_profile"
  role = aws_iam_role.crowdstrike_bootstrap_role.name
}

resource "aws_vpc" "global_vpc" {
  cidr_block = local.networks.vpc_subnet
  tags = merge({
    Name = "Global VPC"
  }, local.required_tags)
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.global_vpc.id
  tags = merge({
    Name = "Internet Gateway"
  }, local.required_tags)
}

resource "aws_subnet" "sn_private" {
  vpc_id     = aws_vpc.global_vpc.id
  cidr_block = local.networks.private_subnet
  availability_zone = data.aws_availability_zones.available.names[0]
  tags = merge({
    Name = "Private Subnet"
  }, local.required_tags)
}

resource "aws_route_table" "rt_private" {
  vpc_id = aws_vpc.global_vpc.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }
  tags = merge({
    Name = "Private Subnet Route Table"
  }, local.required_tags)
}

resource "aws_route_table_association" "rta_private" {
  subnet_id = aws_subnet.sn_private.id
  route_table_id = aws_route_table.rt_private.id
}

resource "aws_security_group" "sg_internal" {
  name        = "Global Security Group"
  description = "Local, Ansible, and Cloudshare Traffic"
  vpc_id = aws_vpc.global_vpc.id
  ingress {
    description = "Allow local traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [ local.networks.vpc_subnet ]
  }
  dynamic "ingress" {
    for_each = local.networking.firewall_rules.ingress
    content {
      description = ingress.value.description
      from_port   = ingress.value.from_port
      to_port     = ingress.value.to_port
      protocol    = ingress.value.protocol
      cidr_blocks = [ ingress.value.cidr ]
    }
  }
  egress {
    from_port       = 0
    to_port         = 0
    protocol        = "-1"
    cidr_blocks     = ["0.0.0.0/0"]
  }
  dynamic "egress" {
    for_each = local.networking.firewall_rules.egress
    content {
      description = egress.value.description
      from_port   = egress.value.from_port
      to_port     = egress.value.to_port
      protocol    = egress.value.protocol
      cidr_blocks = [ egress.value.cidr ]
    }
  }
  tags = merge({
    Name = "Global Security Group"
  }, local.required_tags)
}

# compute
resource "aws_instance" "admin" {
  ami                          = local.config.admin.ami
  instance_type                = local.config.admin.instance_type
  key_name                     = "cs-key"
  iam_instance_profile         = aws_iam_instance_profile.crowdstrike_bootstrap_profile.id
  vpc_security_group_ids       = [ aws_security_group.sg_internal.id ]
  subnet_id                    = aws_subnet.sn_private.id
  private_ip                   = local.config.admin.private_ip
  associate_public_ip_address  = true
  root_block_device {
    volume_size = try(tonumber(local.config.admin.disk_size), 0)
  }
  tags = merge({
    Name                       = local.config.admin.hostname
    ci-key-username            = local.config.admin.ci_key_username
  }, local.required_tags)
  user_data                    = local.config.admin.public_user_data
}