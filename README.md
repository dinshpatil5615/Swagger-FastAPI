# 🚀 FastAPI Deployment on AWS ECS with CI/CD & DevSecOps

## 📌 Project Overview

This project demonstrates a **production-grade DevOps pipeline** to deploy a containerized FastAPI application on AWS using modern DevOps practices.

It includes:

* Containerization using Docker
* Deployment on AWS ECS (Fargate)
* CI/CD pipeline using GitHub Actions
* Security scanning integrated into pipeline (DevSecOps)
* Infrastructure provisioning using Terraform
* Remote state management using S3 & DynamoDB

---

## 🏗️ Architecture

```
Developer → GitHub → GitHub Actions CI/CD
        ↓
Docker Build + Security Scan
        ↓
Push Image → Amazon ECR
        ↓
Amazon ECS (Fargate)
        ↓
Application Load Balancer (ALB)
        ↓
FastAPI Application (/docs)
```

---

## ⚙️ Tech Stack

* AWS ECS (Fargate)
* AWS ECR
* AWS ALB
* Terraform
* GitHub Actions
* Docker
* FastAPI

---

## 🔐 DevSecOps Implementation

Security is integrated directly into the CI/CD pipeline:

* Dependency vulnerability scanning
* Container image scanning
* Secure secrets management using GitHub Secrets

---

## 🔄 CI/CD Pipeline Flow

1. Code pushed to GitHub
2. GitHub Actions pipeline triggered
3. Security scans executed
4. Docker image built
5. Image tagged using build number
6. Image pushed to Amazon ECR
7. ECS service updated with new image
8. Application deployed via ALB

---

## 🏷️ Image Versioning Strategy

Instead of using only `latest`, the pipeline uses versioned tags:

```
build-1
build-2
build-3
latest
```

### ✅ Benefits:

* Easy rollback
* Traceable deployments
* Production-ready approach

---

## 🧱 Terraform Setup

Infrastructure is fully managed using Terraform:

* ECS Cluster & Service
* Load Balancer & Target Groups
* Networking (VPC, Subnets, IGW)

### Remote State Configuration:

* S3 bucket for storing state
* DynamoDB table for state locking

---

## 🌐 Application Access

After deployment:

```
http://<ALB-DNS>/docs
```

Access FastAPI Swagger UI.

---

## 📂 Project Structure

```
.
├── app/
├── terraform/
│   ├── main.tf
│   ├── variables.tf
│   ├── outputs.tf
│   ├── backend.tf
│   └── provider.tf
├── .github/workflows/
│   └── pipeline.yml
├── Dockerfile
├── requirements.txt
├── .gitignore
└── README.md
```

---

## 🚀 Key Features

* Fully automated CI/CD pipeline
* Secure DevSecOps workflow
* Scalable container deployment using ECS
* Infrastructure as Code using Terraform
* Production-style architecture

---

## 🎯 Learning Outcomes

* Hands-on experience with AWS ECS & ECR
* Built end-to-end CI/CD pipeline
* Implemented security in DevOps workflow
* Learned Terraform remote state management
* Understood production deployment patterns

---

## 🧠 Future Improvements

* Blue-Green Deployment
* Monitoring with CloudWatch
* Auto Scaling for ECS
* Custom domain with HTTPS

---

## 🙌 Conclusion

This project demonstrates a **real-world DevOps workflow** combining CI/CD, security, cloud infrastructure, and containerization — making it production-ready and scalable.

---
