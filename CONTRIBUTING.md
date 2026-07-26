# Contributing

Thank you for your interest in the Cloud Security Posture Audit project!

## How to Contribute

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/new-control`
3. Make changes and test locally
4. Commit with conventional format: `git commit -m "feat: add S3 encryption check"`
5. Push and create a Pull Request

## Commit Convention

- `feat:` - New features
- `fix:` - Bug fixes
- `docs:` - Documentation changes
- `refactor:` - Code refactoring
- `test:` - Test additions/changes
- `security:` - Security improvements

## Guidelines

- Follow CIS AWS Foundations Benchmark
- Write tests for new scanner checks
- Update documentation for new features
- Ensure linting passes: `make lint`
