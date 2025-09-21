#!/bin/bash

# Setup script for Jenkins-QEMU integration

set -euo pipefail

echo "Setting up Jenkins for QEMU integration..."

# Install Jenkins plugins
JENKINS_PLUGINS=(
    "workflow-aggregator"
    "docker-workflow"
    "ansible"
    "pipeline-stage-view"
    "blueocean"
    "slack"
    "github"
    "credentials-binding"
    "build-timeout"
    "pipeline-utility-steps"
    "htmlpublisher"
)

echo "Required Jenkins plugins:"
for plugin in "${JENKINS_PLUGINS[@]}"; do
    echo "  - $plugin"
done

echo ""
echo "Manual setup steps:"
echo "==================="
echo "1. Install required Jenkins plugins listed above"
echo "2. Configure credentials:"
echo "   - 'qemu-ssh-key': SSH private key for QEMU VMs"
echo "   - 'ansible-vault-password': Ansible vault password"
echo "   - 'github-credentials': GitHub access token"
echo "   - 'slack-webhook-url': Slack webhook for notifications"
echo ""
echo "3. Create new pipeline job:"
echo "   - Use the generated jenkins-job-config.xml"
echo "   - Point to Jenkinsfile.qemu in your repository"
echo ""
echo "4. Configure Jenkins agent with:"
echo "   - Docker access"
echo "   - QEMU/KVM access (if running VMs on Jenkins agent)"
echo "   - Ansible installed"
echo "   - Network access to QEMU VMs (192.168.100.0/24)"
echo ""
echo "5. Set up environment variables:"
echo "   - DOCKER_REGISTRY: Your Docker registry URL"
echo "   - SLACK_WEBHOOK_URL: Slack webhook for notifications"
echo ""
echo "6. Configure build triggers:"
echo "   - GitHub webhooks for automatic builds"
echo "   - Scheduled builds for periodic deployment tests"
