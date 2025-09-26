# Contributing to Nimbulite
First off, thank you for considering contributing to Nimbulite! We're excited you're here. This project is in its early stages, and every contribution, from a bug report to a new feature, is incredibly valuable.

This document provides a set of guidelines for contributing to Nimbulite. These are mostly guidelines, not strict rules. Use your best judgment, and feel free to propose changes to this document in a pull request.

## How Can I Contribute?
There are many ways to contribute to the project. We welcome help in any of the following areas:
- **Reporting Bugs**: If you find a bug, please let us know!
- **Suggesting Enhancements**: Have an idea for a new feature or an improvement to an existing one? We'd love to hear it.
- **Writing Code**: Help us build new features or fix existing bugs.
- **Improving Documentation**: Good documentation is key. If you see something that could be clearer, please help us improve it.

## Getting Started
As Nimbulite is in pre-alpha, the development setup is still evolving. The basic steps to get started are:
1. Fork the repository on GitHub.
2. Clone your fork locally:
```bash
git clone [https://github.com/your-username/nimbulite.git](https://github.com/your-username/nimbulite.git)
```
3. Set up your development environment. We recommend using a virtual environment. The project will use uv for package management.
```bash
# (Instructions for setting up with uv will be added here)
```
4. Install the dependencies.
```bash
# (Command for installing dependencies will be added here)
```
## Submitting a Pull Request
To ensure a smooth process, please follow these steps when submitting code:
1. Create a new branch for your feature or bug fix. Please use a descriptive name.
```bash
git checkout -b feature/your-awesome-feature
```
2. Write your code. Make sure to adhere to the project's style guides.
3. Add or update tests for your changes. We aim for high test coverage to maintain quality.
4. Ensure all tests pass locally.
5. Commit your changes with a clear and descriptive commit message.
6. Push your branch to your fork on GitHub.
```bash
git push origin feature/your-awesome-feature
```
7. Open a pull request to the main branch of the main Nimbulite repository. Provide a clear title and a detailed description of your changes.

## Style Guides
We use a set of automated tools to maintain a consistent code style across the project. Please ensure your contributions conform to these standards.
- Code Formatting: We use Black for uncompromising code formatting.
- Import Sorting: We use isort to keep our imports organized.
- Type Checking: We use Mypy for static type analysis.
Before committing, you can run these tools locally to format and check your code.

## Reporting Bugs
When reporting a bug, please include as much detail as possible to help us reproduce and fix the issue. Use the "Bug Report" issue template and include:
- A clear and descriptive title.
- The version of Nimbulite you are using.
- Steps to reproduce the bug.
- The expected behavior.
- The actual behavior, including any error messages or logs.

## Suggesting Enhancements
We welcome suggestions for new features! When submitting an enhancement suggestion, please use the "Feature Request" issue template and provide a clear and detailed description of your idea and why it would be valuable to the project.

Thank you for helping us make Nimbulite a great tool!