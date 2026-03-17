resource "aws_vpc" "main_vpc" {
  cidr_block = var.vpc_cidr
  enable_dns_support = true
  enable_dns_hostnames = true

  tags = {
    Name = "ecs-vpc"
  }
}

resource "aws_internet_gateway" "IGW" {
  vpc_id = aws_vpc.main_vpc.id

  tags = {
    Name = "ecs-igw"
  }
}

resource "aws_subnet" "public_1" {
  vpc_id = aws_vpc.main_vpc.id
  cidr_block = "10.0.1.0/24"
  availability_zone = "${var.aws_region}a"
  map_public_ip_on_launch = true

  tags = {
    Name = "Public-subnet-1"
  }
}

resource "aws_subnet" "public_2" {
  cidr_block = "10.0.2.0/24"
  vpc_id = aws_vpc.main_vpc.id
  availability_zone = "${var.aws_region}b"
  map_public_ip_on_launch = true

  tags = {
    Name = "Public-subnet-2"
  }
}

resource "aws_route_table" "public_rt" {
  vpc_id = aws_vpc.main_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.IGW.id
  }

  tags = {
    Name = "public-route-table"
  }
}

resource "aws_route_table_association" "public_1_asso" {
  subnet_id = aws_subnet.public_1.id
  route_table_id = aws_route_table.public_rt.id
}


resource "aws_route_table_association" "public_2_asso" {
  subnet_id = aws_subnet.public_2.id
  route_table_id = aws_route_table.public_rt.id
}

resource "aws_security_group" "alb_sg" {
  name = "ecs-alb-sg"
  description = "Allow http/https from internet"
  vpc_id = aws_vpc.main_vpc.id

  ingress {
    description = "HTTP"
    from_port = 80
    to_port = 80
    protocol = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTPS"
    from_port = 443
    to_port = 443
    protocol = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port = 0
    to_port = 0
    protocol = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    Name = "ecs-alb-sg"
  }
}

resource "aws_security_group" "ecs_sg" {
    name = "ecs-task-sg"
    description = "Allow traffic only from ALB"
    vpc_id = aws_vpc.main_vpc.id

    ingress {
        description = "Allow traffic from ALB"
        from_port = 8000
        to_port = 8000
        protocol = "tcp"
        security_groups = [aws_security_group.alb_sg.id]
    }

    egress {
        from_port = 0
        to_port = 0
        protocol = "-1"
        cidr_blocks = ["0.0.0.0/0"]
    }
    tags = {
      Name = "ecs-task-sg"
    }
}

resource "aws_lb" "app_alb" {
  name = "ecs-app-alb"
  load_balancer_type = "application"
  security_groups = [aws_security_group.alb_sg.id]
  subnets = [
    aws_subnet.public_1.id ,
    aws_subnet.public_2.id
  ]

  tags = {
    Name = "ecs-app-alb"
  }
}

resource "aws_lb_target_group" "app_tg" {
  name = "ecs-app-tg"
  port = 8000
  protocol = "HTTP"
  vpc_id = aws_vpc.main_vpc.id
  target_type = "ip"

  health_check {
    path = "/docs"
    protocol = "HTTP"
    matcher = "200"
    interval = 30
    timeout = 5
    healthy_threshold = 2
    unhealthy_threshold = 2
  }
  tags = {
    Name = "ecs-app-tg"
  }
}

resource "aws_lb_target_group" "blue" {
  name = "ecs-blue-tg"
  port = 80
  protocol = "HTTP"
  vpc_id = aws_vpc.main_vpc.id
}

resource "aws_lb_target_group" "green" {
  name = "ecs-green-tg"
  port = 80
  protocol = "HTTP"
  vpc_id = aws_vpc.main_vpc.id
}

resource "aws_lb_listener" "http_listener" {
  load_balancer_arn = aws_lb.app_alb.arn
  port = 80
  protocol = "HTTP"

  default_action {
    type = "forward"
    target_group_arn = aws_lb_target_group.app_tg.arn
  }
}

resource "aws_ecs_cluster" "app_cluster" {
  name = "ecs-app-cluster"

  tags = {
    Name = "ecs-app-cluster"
  }
}

resource "aws_cloudwatch_log_group" "ecs_logs" {
  name = "/ecs/app"
  retention_in_days = 7
}

resource "aws_iam_role" "ecs_task_execution_role" {
  name = "ecsTaskExecutionRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "ecs_task_execution_policy" {
  role = aws_iam_role.ecs_task_execution_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_ecs_task_definition" "app_task" {
  family = "ecs-app-task"
  requires_compatibilities = ["FARGATE"]
  network_mode = "awsvpc"

  cpu = "256"
  memory = "512"

  execution_role_arn = aws_iam_role.ecs_task_execution_role.arn
  container_definitions = jsonencode([
    {
      name = "app-container"
      image = "272206396644.dkr.ecr.us-east-1.amazonaws.com/fastapi-repo:latest"

      essential = true


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

      logConfiguration = {
        logdriver = "awslogs"

        options = {
          awslogs-group = aws_cloudwatch_log_group.ecs_logs.name
          awslogs-region = var.aws_region
          awslogs-stream-prefix = "ecs"
        }
      }
    }
  ])
}

resource "aws_ecs_service" "app_service" {
  name = "ecs-app-service"
  cluster = aws_ecs_cluster.app_cluster.id
  task_definition = aws_ecs_task_definition.app_task.arn
  desired_count = 1
  launch_type = "FARGATE"

  network_configuration {
    subnets = [
      aws_subnet.public_1.id , 
      aws_subnet.public_2.id
    ]

    security_groups = [aws_security_group.ecs_sg.id]
    assign_public_ip = true
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.app_tg.arn
    container_name = "app-container"
    container_port = 8000
  }

  depends_on = [ 
    aws_lb_listener.http_listener
   ]
}

resource "aws_ecr_repository" "fastapi_repo" {
  name = "fastapi-repo"
}
