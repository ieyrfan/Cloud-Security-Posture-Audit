.PHONY: help init plan apply scan report clean lint validate

help:
	@echo "Cloud Security Posture Audit - Make Commands"
	@echo ""
	@echo "  init          Initialize Terraform"
	@echo "  plan          Plan Terraform deployment"
	@echo "  apply         Apply Terraform changes"
	@echo "  scan          Run security posture scan"
	@echo "  compliance    Run CIS compliance check"
	@echo "  report        Generate comprehensive report"
	@echo "  full-audit    Run complete audit pipeline"
	@echo "  docker-build  Build security scanner Docker"
	@echo "  docker-up     Start Docker services"
	@echo "  lint          Run pre-commit hooks"
	@echo "  validate      Validate Terraform config"
	@echo "  clean         Clean temporary files"
	@echo "  docs          Serve documentation locally"
	@echo ""

init:
	cd terraform && terraform init

plan:
	cd terraform && terraform plan -var-file="environments/$(ENV).tfvars"

apply:
	cd terraform && terraform apply -var-file="environments/$(ENV).tfvars"

scan:
	python scripts/security-scan.py --environment $(ENV) --full

compliance:
	python scripts/compliance-check.py --environment $(ENV) --benchmark cis

report:
	mkdir -p reports
	python scripts/generate-report.py --environment $(ENV) --format md,html,json

full-audit: scan compliance report
	@echo "Audit complete. Check reports/ directory for outputs."

docker-build:
	docker build -t security-scanner:latest ./docker
	docker build -t security-scanner:dev ./docker -f ./docker/Dockerfile.dev

docker-up:
	docker-compose -f ./docker/docker-compose.yml up -d

lint:
	pre-commit run --all-files

validate:
	cd terraform && terraform validate

clean:
	rm -f reports/*.json reports/*.md reports/*.html
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	terraform -chdir=terraform init -upgrade

docs:
	cd docs && python -m http.server 8080
