variable "cluster_name" {}
variable "lb_name" {}
variable "vpc_name" {}
variable "vpc_cidr" {}

data "aws_availability_zones" "available" {}

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}


locals {
  # region = "eu-west-1"
  # name   = "ex-${basename(path.cwd)}"

  # vpc_cidr = "10.0.0.0/16"
  azs      = slice(data.aws_availability_zones.available.names, 0, 3)

  # container_name = "ecsdemo-frontend"
  # container_port = 3000

  tags = {
    SE       = "Cristian Ramirez"
    Repository = "https://github.com/terraform-aws-modules/terraform-aws-ecs"
  }
}

resource "aws_iam_role" "ecs_instance_role" {
  name = "ecs_crisdemo_instance_role"

  assume_role_policy = jsonencode({
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Principal": {
          "Service": "ec2.amazonaws.com"
        },
        "Action": "sts:AssumeRole"
      }
    ]
  })

  managed_policy_arns = [
    "arn:aws:iam::aws:policy/service-role/AmazonEC2ContainerServiceforEC2Role",
  ]

  tags = local.tags
}

resource "aws_iam_instance_profile" "ecs_instance_profile" {
  name = "ecs_crisdemo_instance_profile"
  role = aws_iam_role.ecs_instance_role.name
}

resource "aws_iam_role" "ecs_task_execution_role" {
  name = "ecs_crisdemo_task_execution_role"

  assume_role_policy = jsonencode({
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Principal": {
          "Service": "ecs-tasks.amazonaws.com"
        },
        "Action": "sts:AssumeRole"
      }
    ]
  })

  managed_policy_arns = [
    "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy",
  ]

  tags = local.tags
}

resource "aws_iam_role" "ecs_task_role" {
  name = "ecs_crisdemo_task_role"

  assume_role_policy = jsonencode({
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Principal": {
          "Service": "ecs-tasks.amazonaws.com"
        },
        "Action": "sts:AssumeRole"
      }
    ]
  })

  managed_policy_arns = [
    "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy",
  ]

  tags = local.tags
}

################################################################################
# Cluster
################################################################################

module "ecs_cluster" {
  source = "terraform-aws-modules/ecs/aws"

  cluster_name = var.cluster_name

  # Capacity provider
  fargate_capacity_providers = {
    FARGATE = {
      default_capacity_provider_strategy = {
        weight = 50
        base   = 20
      }
    }
    FARGATE_SPOT = {
      default_capacity_provider_strategy = {
        weight = 50
      }
    }
  }

  tags = local.tags
}

################################################################################
# Service
################################################################################

# module "ecs_service" {
#   source = "../../modules/service"

#   name        = local.name
#   cluster_arn = module.ecs_cluster.arn

#   cpu    = 1024
#   memory = 4096

#   # Enables ECS Exec
#   enable_execute_command = true

#   # Container definition(s)
#   container_definitions = {

#     fluent-bit = {
#       cpu       = 512
#       memory    = 1024
#       essential = true
#       image     = nonsensitive(data.aws_ssm_parameter.fluentbit.value)
#       firelens_configuration = {
#         type = "fluentbit"
#       }
#       memory_reservation = 50
#       user               = "0"
#     }

#     (local.container_name) = {
#       cpu       = 512
#       memory    = 1024
#       essential = true
#       image     = "public.ecr.aws/aws-containers/ecsdemo-frontend:776fd50"
#       port_mappings = [
#         {
#           name          = local.container_name
#           containerPort = local.container_port
#           hostPort      = local.container_port
#           protocol      = "tcp"
#         }
#       ]

#       # Example image used requires access to write to root filesystem
#       readonly_root_filesystem = false

#       dependencies = [{
#         containerName = "fluent-bit"
#         condition     = "START"
#       }]

#       enable_cloudwatch_logging = false
#       log_configuration = {
#         logDriver = "awsfirelens"
#         options = {
#           Name                    = "firehose"
#           region                  = local.region
#           delivery_stream         = "my-stream"
#           log-driver-buffer-limit = "2097152"
#         }
#       }

#       linux_parameters = {
#         capabilities = {
#           add = []
#           drop = [
#             "NET_RAW"
#           ]
#         }
#       }

#       # Not required for fluent-bit, just an example
#       volumes_from = [{
#         sourceContainer = "fluent-bit"
#         readOnly        = false
#       }]

#       memory_reservation = 100
#     }
#   }

#   service_connect_configuration = {
#     namespace = aws_service_discovery_http_namespace.this.arn
#     service = {
#       client_alias = {
#         port     = local.container_port
#         dns_name = local.container_name
#       }
#       port_name      = local.container_name
#       discovery_name = local.container_name
#     }
#   }

#   load_balancer = {
#     service = {
#       target_group_arn = module.alb.target_groups["ex_ecs"].arn
#       container_name   = local.container_name
#       container_port   = local.container_port
#     }
#   }

#   subnet_ids = module.vpc.private_subnets
#   security_group_rules = {
#     alb_ingress_3000 = {
#       type                     = "ingress"
#       from_port                = local.container_port
#       to_port                  = local.container_port
#       protocol                 = "tcp"
#       description              = "Service port"
#       source_security_group_id = module.alb.security_group_id
#     }
#     egress_all = {
#       type        = "egress"
#       from_port   = 0
#       to_port     = 0
#       protocol    = "-1"
#       cidr_blocks = ["0.0.0.0/0"]
#     }
#   }

#   service_tags = {
#     "ServiceTag" = "Tag on service level"
#   }

#   tags = local.tags
# }

################################################################################
# Standalone Task Definition (w/o Service)
################################################################################

# module "ecs_task_definition" {
#   source = "../../modules/service"

#   # Service
#   name        = "${var.service_name}-standalone"
#   cluster_arn = module.ecs_cluster.arn

#   # Task Definition
#   volume = {
#     ex-vol = {}
#   }

#   runtime_platform = {
#     cpu_architecture        = "ARM64"
#     operating_system_family = "LINUX"
#   }

#   # Container definition(s)
#   container_definitions = {
#     al2023 = {
#       image = "public.ecr.aws/amazonlinux/amazonlinux:2023-minimal"

#       mount_points = [
#         {
#           sourceVolume  = "ex-vol",
#           containerPath = "/var/www/ex-vol"
#         }
#       ]

#       command    = ["echo hello world"]
#       entrypoint = ["/usr/bin/sh", "-c"]
#     }
#   }

#   subnet_ids = module.vpc.private_subnets

#   security_group_rules = {
#     egress_all = {
#       type        = "egress"
#       from_port   = 0
#       to_port     = 0
#       protocol    = "-1"
#       cidr_blocks = ["0.0.0.0/0"]
#     }
#   }

#   tags = local.tags
# }

################################################################################
# Supporting Resources
################################################################################

# module "alb" {
#   source  = "terraform-aws-modules/alb/aws"
#   version = "~> 9.0"

#   name = var.lb_name

#   load_balancer_type = "network"

#   vpc_id  = module.vpc.vpc_id
#   subnets = module.vpc.public_subnets

#   # For example only
#   enable_deletion_protection = false

#   # security_groups = []

#   # Security Group
#   security_group_ingress_rules = {
#     all = {
#       ip_protocol = "-1"
#       cidr_ipv4   = module.vpc.vpc_cidr_block
#     }
#   }
#   security_group_egress_rules = {
#     all = {
#       ip_protocol = "-1"
#       cidr_ipv4   = module.vpc.vpc_cidr_block
#     }
#   }

#   listeners = {
#     ex_http = {
#       port     = 80
#       protocol = "TCP"

#       forward = {
#         target_group_key = "ex_ecs"
#       }
#     }
#   }

#   target_groups = {
#     ex_ecs = {
#       backend_protocol                  = "TCP"
#       backend_port                      = 80
#       target_type                       = "instance"

#       health_check = {
#         port                = "traffic-port"
#         protocol            = "TCP"
#       }

#       # There's nothing to attach here in this definition. Instead,
#       # ECS will attach the IPs of the tasks to this target group
#       create_attachment = false
#     }
#   }

#   tags = local.tags
# }

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.0"

  name = var.vpc_name
  cidr = var.vpc_cidr

  azs             = local.azs
  private_subnets = [for k, v in local.azs : cidrsubnet(var.vpc_cidr, 4, k)]
  public_subnets  = [for k, v in local.azs : cidrsubnet(var.vpc_cidr, 8, k + 48)]

  enable_nat_gateway = true
  single_nat_gateway = true

  tags = local.tags
}


output "cluster_arn" {
  description = "ARN that identifies the cluster"
  value       = module.ecs_cluster.cluster_arn
}

output "cluster_id" {
  description = "ID that identifies the cluster"
  value       = module.ecs_cluster.cluster_id
}

output "cluster_name" {
  description = "Name that identifies the cluster"
  value       = module.ecs_cluster.cluster_name
}

output "cluster_capacity_providers" {
  description = "Map of cluster capacity providers attributes"
  value       = module.ecs_cluster.cluster_capacity_providers
}

output "cluster_autoscaling_capacity_providers" {
  description = "Map of capacity providers created and their attributes"
  value       = module.ecs_cluster.autoscaling_capacity_providers
}

output "ecs_task_role_arn" {
  description = "ECS Task Role ARN"
  value       = aws_iam_role.ecs_task_role.arn
}

output "ecs_task_execution_role_arn" {
  description = "ECS Task Execution Role ARN"
  value       = aws_iam_role.ecs_task_execution_role.arn
}

output "ecs_instance_profile_name" {
  description = "Instance Profile Name"
  value       = aws_iam_instance_profile.ecs_instance_profile.name
}

# output "lb_arn" {
#   value = module.alb.arn
# }
# output "lb_id" {
#   value = module.alb.id
# }
# output "lb_security_group_arn" {
#   value = module.alb.security_group_arn
# }
# output "lb_security_group_id" {
#   value = module.alb.security_group_id
# }
# output "lb_target_groups" {
#   value = module.alb.target_groups
# }

output "vpc_id"  {
  value = module.vpc.vpc_id
}
output "subnets" {
  value = module.vpc.public_subnets
}