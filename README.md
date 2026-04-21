# 🔐 FastAPI Authentication Service

![Python](https://img.shields.io/badge/Python-3.11-3776AB?style=for-the-badge&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-009688?style=for-the-badge&logo=fastapi&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-316192?style=for-the-badge&logo=postgresql&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-2496ED?style=for-the-badge&logo=docker&logoColor=white)
![Kubernetes](https://img.shields.io/badge/Kubernetes-326CE5?style=for-the-badge&logo=kubernetes&logoColor=white)
![AWS EKS](https://img.shields.io/badge/AWS_EKS-232F3E?style=for-the-badge&logo=amazon-aws&logoColor=white)
![GitHub Actions](https://img.shields.io/badge/GitHub_Actions-2088FF?style=for-the-badge&logo=github-actions&logoColor=white)
![Trivy](https://img.shields.io/badge/Trivy-1904DA?style=for-the-badge&logo=aqua&logoColor=white)

> A production-ready authentication microservice built with FastAPI and PostgreSQL, containerized with Docker, deployed on AWS EKS, and secured with a full DevSecOps CI/CD pipeline using GitHub Actions.

---

## 📌 Project Overview

This project is a **cloud-native authentication service** built using **FastAPI (Python 3.11)** with **PostgreSQL** as the database. It provides secure user registration and login with **JWT-based authentication**. The service follows a complete **DevSecOps pipeline** — including SAST, dependency scanning, Terraform security scanning, and container image scanning — before deploying to **Amazon EKS**.

---

## ✨ Features

- ✅ User Registration with password hashing (bcrypt)
- ✅ User Login with **JWT Access Token** generation
- ✅ Token-based authentication for protected routes
- ✅ PostgreSQL database via SQLAlchemy ORM
- ✅ Auto-generated Swagger API docs at `/docs`
- ✅ Fully Dockerized & Kubernetes-ready
- ✅ End-to-end DevSecOps pipeline with GitHub Actions

---

## 🏗️ Architecture

```
Client Request
      ↓
Kubernetes Ingress (Nginx)
      ↓
FastAPI Service (EKS Pod)
      ↓
PostgreSQL Database

─────────────────────────────
CI/CD Flow:
─────────────────────────────
GitHub Push (main)
      ↓
GitHub Actions Pipeline
      ↓
Bandit (Python SAST)
      ↓
pip-audit (Dependency Scan)
      ↓
Checkov (Terraform IaC Scan)
      ↓
Docker Build
      ↓
Trivy (Container Image Scan)
      ↓
Push to Amazon ECR
      ↓
Deploy to Amazon EKS
```

---

## 🚀 Tech Stack

| Category | Tool |
|---|---|
| **Language** | Python 3.11 |
| **Framework** | FastAPI |
| **Database** | PostgreSQL (SQLAlchemy ORM) |
| **Authentication** | JWT (python-jose), bcrypt |
| **Containerization** | Docker |
| **Container Registry** | Amazon ECR |
| **Orchestration** | Kubernetes (Amazon EKS) |
| **CI/CD** | GitHub Actions |
| **SAST** | Bandit (Python security scan) |
| **Dependency Scan** | pip-audit |
| **IaC Security** | Checkov (Terraform scan) |
| **Image Scan** | Trivy |
| **Cloud** | AWS (EKS, ECR, IAM) |

---

## ⚙️ DevSecOps CI/CD Pipeline

The pipeline is triggered on every push to the `main` branch and runs the following stages in order:

### 🔒 Stage 1 — Python SAST (Bandit)
```bash
bandit -r app
```
Scans all Python source code for common security vulnerabilities.

### 🔒 Stage 2 — Dependency Vulnerability Scan (pip-audit)
```bash
pip-audit --strict
```
Audits all Python dependencies for known CVEs. Pipeline fails if any vulnerable package is found.

### 🔒 Stage 3 — Terraform IaC Security Scan (Checkov)
```bash
checkov -d terraform/ --soft-fail
```
Scans Terraform configurations for misconfigurations and compliance violations.

### 🐳 Stage 4 — Docker Build
```bash
docker build -t fastapi-app:${{ github.run_number }} ./auth-service
```
Builds the Docker image tagged with the pipeline run number for traceability.

### 🔒 Stage 5 — Container Image Scan (Trivy)
```yaml
uses: aquasecurity/trivy-action@v0.20.0
```
Scans the Docker image for OS and application-level CVEs before pushing to ECR.

### 🚀 Stage 6 — Push to Amazon ECR
Pushes both versioned (`run_number`) and `latest` tags to ECR for traceability and rollback capability.

### 🚀 Stage 7 — Deploy to Amazon EKS
```bash
aws eks update-kubeconfig --region us-east-1 --name fastapi-eks-cluster
kubectl apply -f ./k8s
kubectl rollout restart deployment fastapi-app
```
Updates kubeconfig and applies Kubernetes manifests with a rolling restart for zero-downtime deployment.

---

## 📂 Project Structure

```
fastapi-auth-service/
├── auth-service/
│   ├── app/
│   │   ├── main.py            # FastAPI app entry point
│   │   ├── models.py          # SQLAlchemy DB models
│   │   ├── schemas.py         # Pydantic request/response schemas
│   │   ├── auth.py            # JWT token logic
│   │   └── database.py        # DB connection setup
│   ├── Dockerfile
│   └── requirements.txt
├── k8s/
│   ├── deployment.yaml        # Kubernetes Deployment
│   ├── service.yaml           # Kubernetes Service
│   └── ingress.yaml           # Nginx Ingress
├── terraform/
│   ├── main.tf                # EKS + ECR + VPC provisioning
│   └── variables.tf
└── .github/
    └── workflows/
        └── ci-cd.yml          # GitHub Actions DevSecOps pipeline
```

---

## 🔗 API Endpoints

| Method | Endpoint | Description | Auth Required |
|---|---|---|---|
| `POST` | `/auth/register` | Register a new user | ❌ |
| `POST` | `/auth/login` | Login & receive JWT token | ❌ |
| `GET` | `/users/me` | Get current user profile | ✅ JWT |
| `GET` | `/health` | Health check endpoint | ❌ |

---

## 🛠️ Local Setup

### Prerequisites
- Python 3.11+
- Docker & Docker Compose
- PostgreSQL

### Run Locally

```bash
# Clone the repository
git clone https://github.com/dinshpatil5615/fastapi-auth-service.git
cd fastapi-auth-service/auth-service

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Set environment variables
export DATABASE_URL=postgresql://user:password@localhost:5432/authdb
export SECRET_KEY=your-secret-key

# Run the application
uvicorn app.main:app --reload
```

Swagger docs available at: `http://localhost:8000/docs`

### Run with Docker Compose

```bash
docker-compose up --build
```

---

## 🔐 Security Highlights

| Layer | Tool | What It Catches |
|---|---|---|
| Python Code | **Bandit** | Hardcoded secrets, SQL injection, insecure functions |
| Dependencies | **pip-audit** | Known CVEs in Python packages |
| Terraform | **Checkov** | Misconfigured AWS resources, open security groups |
| Docker Image | **Trivy** | OS-level and app-level CVEs |
| App Level | **bcrypt + JWT** | Secure password storage & stateless auth |

---

## ☁️ AWS Infrastructure

| Resource | Purpose |
|---|---|
| **Amazon EKS** | Kubernetes cluster for running the FastAPI service |
| **Amazon ECR** | Private Docker image registry |
| **AWS IAM** | Least-privilege roles for GitHub Actions & EKS |

---

## 📊 Key Highlights

| Metric | Detail |
|---|---|
| Pipeline Trigger | Every push to `main` branch |
| Security Stages | 4 automated security scans before any deployment |
| Deployment Strategy | Zero-downtime rolling restart on EKS |
| Image Tagging | Versioned by GitHub run number + `latest` tag |

---

## 👨‍💻 Author

**Dinesh Patil**
- LinkedIn: (https://www.linkedin.com/in/dinesh-patil-devops)
- GitHub: (https://github.com/dinshpatil5615)
