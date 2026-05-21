# Python Package Security Pipeline

A demo project based on my Bachelor thesis on software supply chain security for Python package provisioning.

## Overview

This repository demonstrates an automated vulnerability scanning pipeline for Python package lists.  
The goal is to show how Software Composition Analysis (SCA) can be integrated into a CI/CD workflow to detect vulnerable dependencies early and support a controlled package approval process.

The original thesis project was implemented in an enterprise context.  
This public repository contains a simplified and anonymized demo version only.

## Tech Stack

- Trivy
- GitLab CI/CD
- Docker
- Python
- Bash
- YAML

## Key Features

- Automated vulnerability scanning for Python package lists
- CI/CD-based security gate for merge requests
- Version-specific scan concept for multiple Python versions
- CVSS-based classification of detected vulnerabilities
- Example workflow for merge request labeling
- Example notification and escalation logic

## Architecture

The demo pipeline consists of the following components:

1. Python package list, for example `requirements.txt`
2. GitLab CI/CD pipeline configuration
3. Trivy-based vulnerability scan job
4. Python helper scripts for result handling
5. Optional notification and merge request labeling logic

## Project Status

Work in progress.

The first version of the README is already available.  
A simplified demo implementation will be published shortly.

## Disclaimer

This repository does not contain any confidential company information, internal infrastructure details, real vulnerability reports, or production configuration files.  
It is a generalized demo project created for portfolio and learning purposes.

## Author

Yuya Kayanuma  
B.Sc. Wirtschaftsinformatik, DHBW Karlsruhe  
Focus: DevOps, Platform Engineering, DevSecOps
