data "aws_caller_identity" "current" {}

resource "aws_vpc" "main_vpc" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = { Name = "ecs-vpc" }
}

resource "aws_internet_gateway" "IGW" {
  vpc_id = aws_vpc.main_vpc.id
}

# ✅ FIXED (public subnet must assign IP)
resource "aws_subnet" "public_1" {
  vpc_id                  = aws_vpc.main_vpc.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "${var.aws_region}a"
  map_public_ip_on_launch = true
}

resource "aws_subnet" "public_2" {
  vpc_id                  = aws_vpc.main_vpc.id
  cidr_block              = "10.0.2.0/24"
  availability_zone       = "${var.aws_region}b"
  map_public_ip_on_launch = true
}

resource "aws_route_table" "public_rt" {
  vpc_id = aws_vpc.main_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.IGW.id
  }
}

resource "aws_route_table_association" "public_1_asso" {
  subnet_id      = aws_subnet.public_1.id
  route_table_id = aws_route_table.public_rt.id
}

resource "aws_route_table_association" "public_2_asso" {
  subnet_id      = aws_subnet.public_2.id
  route_table_id = aws_route_table.public_rt.id
}

resource "aws_default_security_group" "default" {
  vpc_id = aws_vpc.main_vpc.id
  ingress = []
  egress  = []
}

resource "aws_security_group" "alb_sg" {
  name        = "ecs-alb-sg"
  description = "ALB security group"
  vpc_id      = aws_vpc.main_vpc.id

  ingress {
    description = "Allow HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "Allow HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "Allow all outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "ecs_sg" {
  name        = "ecs-task-sg"
  description = "Allow traffic only from ALB"
  vpc_id      = aws_vpc.main_vpc.id

  ingress {
    description     = "Allow app traffic from ALB"
    from_port       = 8000
    to_port         = 8000
    protocol        = "tcp"
    security_groups = [aws_security_group.alb_sg.id]
  }

  egress {
    description = "Allow HTTPS outbound"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# ---------------- WAF ----------------

resource "aws_wafv2_web_acl" "alb_waf" {
  name  = "ecs-waf"
  scope = "REGIONAL"

  default_action {
    allow {}
  }

  # ✅ Rule 1 - Common protections
  rule {
    name     = "AWSManagedCommonRules"
    priority = 1

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "common-rules"
      sampled_requests_enabled   = true
    }
  }

  # ✅ Rule 2 - Bad inputs (SQLi, XSS)
  rule {
    name     = "AWSManagedBadInputs"
    priority = 2

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "bad-inputs"
      sampled_requests_enabled   = true
    }
  }

  # ✅ REQUIRED (main visibility)
  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "ecs-waf"
    sampled_requests_enabled   = true
  }
}

resource "aws_wafv2_web_acl_association" "alb_assoc" {
  resource_arn = aws_lb.app_alb.arn
  web_acl_arn  = aws_wafv2_web_acl.alb_waf.arn
}

# ---------------- S3 ----------------

resource "aws_s3_bucket" "waf_logs" {
  bucket = "fastapi-waf-logs-${data.aws_caller_identity.current.account_id}"
}

resource "aws_s3_bucket_public_access_block" "waf_block" {
  bucket = aws_s3_bucket.waf_logs.id

  block_public_acls   = true
  block_public_policy = true
}

# ✅ MERGED POLICY
resource "aws_s3_bucket_policy" "combined_policy" {
  bucket = aws_s3_bucket.waf_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "logdelivery.elasticloadbalancing.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.waf_logs.arn}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      }
    ]
  })
}

# ---------------- ALB ----------------

resource "aws_lb" "app_alb" {
  name               = "ecs-app-alb"
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb_sg.id]
  subnets            = [aws_subnet.public_1.id, aws_subnet.public_2.id]

  access_logs {
    bucket  = aws_s3_bucket.waf_logs.id   # ✅ FIXED
    enabled = true
  }
}

resource "aws_lb_target_group" "app_tg" {
  name     = "ecs-app-tg"
  port     = 8000
  protocol = "HTTP"
  vpc_id   = aws_vpc.main_vpc.id
  target_type = "ip"
  health_check {
    path                = "/health"   
    interval            = 30
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 2
    matcher             = "200"
  }
}

# ✅ FIXED LISTENER
resource "aws_lb_listener" "http_listener" {
  load_balancer_arn = aws_lb.app_alb.arn
  port     = 80
  protocol = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app_tg.arn
  }
  
}

# ---------------- ECS ----------------

resource "aws_ecs_cluster" "app_cluster" {
  name = "ecs-app-cluster"
}

resource "aws_cloudwatch_log_group" "ecs_logs" {
  name = "/ecs/app"
  retention_in_days = 7
}

resource "aws_iam_role" "ecs_task_execution_role" {
  name = "ecsTaskExecutionRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ecs_task_execution_policy" {
  role = aws_iam_role.ecs_task_execution_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_ecs_task_definition" "app_task" {
  family                   = "ecs-app-task"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"

  cpu    = "256"
  memory = "512"

  execution_role_arn = aws_iam_role.ecs_task_execution_role.arn

  container_definitions = jsonencode([
  {
    name  = "app-container"
    essential = true
    image = "272206396644.dkr.ecr.us-east-1.amazonaws.com/fastapi-repo:latest"

    portMappings = [
      {
        containerPort = 8000
        hostPort      = 8000
      }
    ]
    environment = [
      {
        name  = "DATABASE_URL"
        value = "sqlite:///./test.db"
      }
    ]

    # ✅ ADD THIS BLOCK
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        awslogs-group         = "/ecs/app"
        awslogs-region        = var.aws_region
        awslogs-stream-prefix = "ecs"
      }
    }
  }
])
}

resource "aws_ecs_service" "app_service" {
  name            = "ecs-app-service"
  cluster         = aws_ecs_cluster.app_cluster.id
  task_definition = aws_ecs_task_definition.app_task.arn
  launch_type     = "FARGATE"
  desired_count   = 1

  network_configuration {
    subnets         = [aws_subnet.public_1.id, aws_subnet.public_2.id]
    security_groups = [aws_security_group.ecs_sg.id]
    assign_public_ip = true   # ✅ FIXED
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.app_tg.arn
    container_name   = "app-container"
    container_port   = 8000
  }

  depends_on = [aws_lb_listener.http_listener]
}

resource "aws_ecr_repository" "fastapi_repo" {
  name                 = "fastapi-repo"
  image_tag_mutability = "IMMUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }
}