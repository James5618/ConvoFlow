#!/bin/bash

# Jenkins-QEMU Integration Script
# This script integrates Jenkins CI/CD with QEMU VM environment

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_step() {
    echo -e "${BLUE}[STEP]${NC} $1"
}

# Jenkins pipeline script for QEMU deployment
create_jenkins_qemu_pipeline() {
    log_step "Creating Jenkins pipeline for QEMU deployment..."
    
    cat > "$PROJECT_ROOT/Jenkinsfile.qemu" << 'EOF'
pipeline {
    agent any
    
    environment {
        DOCKER_REGISTRY = 'your-registry.com'
        IMAGE_NAME = 'encrypted-chat-app'
        QEMU_SSH_KEY = credentials('qemu-ssh-key')
        ANSIBLE_VAULT_PASSWORD = credentials('ansible-vault-password')
    }
    
    stages {
        stage('Checkout') {
            steps {
                checkout scm
                script {
                    env.GIT_COMMIT_SHORT = sh(
                        script: 'git rev-parse --short HEAD',
                        returnStdout: true
                    ).trim()
                }
            }
        }
        
        stage('Build Application') {
            steps {
                script {
                    log_info "Building application..."
                    sh 'docker build -t ${IMAGE_NAME}:${GIT_COMMIT_SHORT} .'
                    sh 'docker tag ${IMAGE_NAME}:${GIT_COMMIT_SHORT} ${IMAGE_NAME}:latest'
                }
            }
        }
        
        stage('Security Scan') {
            parallel {
                stage('Container Scan') {
                    steps {
                        sh 'docker run --rm -v /var/run/docker.sock:/var/run/docker.sock aquasec/trivy image ${IMAGE_NAME}:${GIT_COMMIT_SHORT}'
                    }
                }
                stage('Code Scan') {
                    steps {
                        sh 'npm audit --audit-level high'
                    }
                }
            }
        }
        
        stage('Test') {
            parallel {
                stage('Unit Tests') {
                    steps {
                        sh 'npm test'
                    }
                    post {
                        always {
                            publishTestResults testResultsPattern: 'test-results.xml'
                        }
                    }
                }
                stage('Integration Tests') {
                    steps {
                        sh 'npm run test:integration'
                    }
                }
            }
        }
        
        stage('QEMU Environment Check') {
            steps {
                script {
                    log_info "Checking QEMU environment..."
                    sh '''
                        cd qemu/vms
                        ./status.sh > vm_status.txt
                        if grep -q "STOPPED" vm_status.txt; then
                            echo "Some VMs are stopped. Starting all VMs..."
                            sudo ./start-all.sh
                            sleep 30
                        fi
                    '''
                }
            }
        }
        
        stage('Deploy to QEMU Staging') {
            when {
                anyOf {
                    branch 'develop'
                    branch 'staging'
                }
            }
            steps {
                script {
                    log_info "Deploying to QEMU staging environment..."
                    sh '''
                        # Copy SSH key
                        cp ${QEMU_SSH_KEY} ~/.ssh/id_rsa
                        chmod 600 ~/.ssh/id_rsa
                        
                        # Update application image in ansible vars
                        echo "app_image: ${IMAGE_NAME}:${GIT_COMMIT_SHORT}" > ansible/group_vars/staging.yml
                        
                        # Deploy with Ansible
                        cd ansible
                        ansible-playbook -i inventory.staging.ini site.yml --vault-password-file ${ANSIBLE_VAULT_PASSWORD}
                    '''
                }
            }
            post {
                always {
                    script {
                        // Run post-deployment tests
                        sh 'cd ansible && ./test-deployment.sh staging'
                    }
                }
            }
        }
        
        stage('Smoke Tests on QEMU') {
            when {
                anyOf {
                    branch 'develop'
                    branch 'staging'
                }
            }
            steps {
                script {
                    sh '''
                        # Wait for services to be ready
                        timeout 300 bash -c 'until curl -k -s https://192.168.100.12/health; do sleep 5; done'
                        
                        # Run smoke tests
                        cd tests
                        npm run test:smoke -- --baseUrl=https://192.168.100.12
                    '''
                }
            }
        }
        
        stage('Deploy to QEMU Production') {
            when {
                branch 'main'
            }
            steps {
                script {
                    // Require manual approval for production
                    input message: 'Deploy to QEMU Production?', ok: 'Deploy',
                          submitterParameter: 'APPROVER'
                    
                    log_info "Deploying to QEMU production environment..."
                    sh '''
                        # Copy SSH key
                        cp ${QEMU_SSH_KEY} ~/.ssh/id_rsa
                        chmod 600 ~/.ssh/id_rsa
                        
                        # Update application image in ansible vars
                        echo "app_image: ${IMAGE_NAME}:${GIT_COMMIT_SHORT}" > ansible/group_vars/production.yml
                        
                        # Deploy with Ansible
                        cd ansible
                        ansible-playbook -i inventory.ini site.yml --vault-password-file ${ANSIBLE_VAULT_PASSWORD}
                    '''
                }
            }
            post {
                success {
                    script {
                        // Notify success
                        sh '''
                            curl -X POST -H 'Content-type: application/json' \
                            --data '{"text":"✅ QEMU Production deployment successful for commit ${GIT_COMMIT_SHORT}"}' \
                            ${SLACK_WEBHOOK_URL}
                        '''
                    }
                }
                failure {
                    script {
                        // Notify failure and rollback
                        sh '''
                            curl -X POST -H 'Content-type: application/json' \
                            --data '{"text":"❌ QEMU Production deployment failed for commit ${GIT_COMMIT_SHORT}"}' \
                            ${SLACK_WEBHOOK_URL}
                            
                            # Trigger rollback
                            cd ansible
                            ansible-playbook -i inventory.ini rollback.yml --vault-password-file ${ANSIBLE_VAULT_PASSWORD}
                        '''
                    }
                }
            }
        }
        
        stage('Performance Tests') {
            when {
                branch 'main'
            }
            steps {
                script {
                    sh '''
                        # Run performance tests against QEMU environment
                        cd performance-tests
                        npm run test:load -- --baseUrl=https://192.168.100.12
                    '''
                }
            }
            post {
                always {
                    publishHTML([
                        allowMissing: false,
                        alwaysLinkToLastBuild: true,
                        keepAll: true,
                        reportDir: 'performance-tests/reports',
                        reportFiles: 'index.html',
                        reportName: 'Performance Test Report'
                    ])
                }
            }
        }
    }
    
    post {
        always {
            // Clean up
            sh '''
                docker system prune -f
                rm -f ~/.ssh/id_rsa
            '''
        }
        success {
            script {
                if (env.BRANCH_NAME == 'main') {
                    // Tag successful production deployment
                    sh "git tag -a v${BUILD_NUMBER} -m 'Production deployment ${BUILD_NUMBER}'"
                    sh "git push origin v${BUILD_NUMBER}"
                }
            }
        }
    }
}
EOF

    log_info "Jenkins QEMU pipeline created: Jenkinsfile.qemu"
}

# Create staging inventory for Jenkins
create_staging_inventory() {
    log_step "Creating staging inventory for Jenkins..."
    
    cat > "$PROJECT_ROOT/ansible/inventory.staging.ini" << 'EOF'
# Staging Inventory for QEMU VMs

[app_servers]
chat-app-staging ansible_host=192.168.100.10 ansible_user=ubuntu

[database_servers] 
chat-db-staging ansible_host=192.168.100.11 ansible_user=ubuntu

[load_balancers]
chat-lb-staging ansible_host=192.168.100.12 ansible_user=ubuntu

[monitoring_servers]
chat-monitor-staging ansible_host=192.168.100.13 ansible_user=ubuntu

[all:vars]
ansible_ssh_private_key_file=~/.ssh/id_rsa
ansible_ssh_common_args='-o StrictHostKeyChecking=no'
environment=staging

[app_servers:vars]
server_role=application
docker_compose_file=docker-compose.app.yml

[database_servers:vars]
server_role=database
docker_compose_file=docker-compose.db.yml

[load_balancers:vars]
server_role=loadbalancer
docker_compose_file=docker-compose.lb.yml

[monitoring_servers:vars]
server_role=monitoring  
docker_compose_file=docker-compose.monitoring.yml
EOF

    log_info "Staging inventory created"
}

# Create deployment test script
create_deployment_test() {
    log_step "Creating deployment test script..."
    
    cat > "$PROJECT_ROOT/ansible/test-deployment.sh" << 'EOF'
#!/bin/bash

# Deployment test script for Jenkins integration

ENVIRONMENT=${1:-production}
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Test endpoints
ENDPOINTS=(
    "https://192.168.100.12/health:Load Balancer Health"
    "http://192.168.100.10:3000/health:Application Health"
    "http://192.168.100.13:9090/-/healthy:Prometheus Health"
    "http://192.168.100.13:3000/api/health:Grafana Health"
)

# Database connectivity tests
DB_TESTS=(
    "192.168.100.11:5432:PostgreSQL"
    "192.168.100.11:6379:Redis"
)

echo "Testing deployment for environment: $ENVIRONMENT"
echo "================================================="

failed_tests=0

# Test HTTP endpoints
for endpoint_info in "${ENDPOINTS[@]}"; do
    IFS=':' read -r url description <<< "$endpoint_info"
    echo -n "Testing $description... "
    
    if curl -k -s --max-time 10 "$url" > /dev/null; then
        echo "✓ PASS"
    else
        echo "✗ FAIL"
        failed_tests=$((failed_tests + 1))
    fi
done

# Test database connectivity
for db_info in "${DB_TESTS[@]}"; do
    IFS=':' read -r host_port service <<< "$db_info"
    IFS=':' read -r host port <<< "$host_port"
    echo -n "Testing $service connectivity... "
    
    if nc -z "$host" "$port"; then
        echo "✓ PASS"
    else
        echo "✗ FAIL"
        failed_tests=$((failed_tests + 1))
    fi
done

# Test application functionality
echo -n "Testing application registration... "
if curl -k -X POST -H "Content-Type: application/json" \
   -d '{"username":"testuser","email":"test@example.com","password":"testpass"}' \
   -s https://192.168.100.12/api/auth/register | grep -q "success\|token\|user"; then
    echo "✓ PASS"
else
    echo "✗ FAIL"
    failed_tests=$((failed_tests + 1))
fi

# Summary
echo ""
echo "Test Summary:"
echo "============="
if [ $failed_tests -eq 0 ]; then
    echo "✅ All tests passed! Deployment is healthy."
    exit 0
else
    echo "❌ $failed_tests test(s) failed! Deployment has issues."
    exit 1
fi
EOF

    chmod +x "$PROJECT_ROOT/ansible/test-deployment.sh"
    log_info "Deployment test script created"
}

# Create rollback playbook
create_rollback_playbook() {
    log_step "Creating rollback playbook..."
    
    cat > "$PROJECT_ROOT/ansible/rollback.yml" << 'EOF'
---
# Rollback playbook for failed deployments

- name: Rollback application deployment
  hosts: app_servers
  become: yes
  vars:
    previous_image: "{{ previous_app_image | default('chat-app:previous') }}"
  tasks:
    - name: Stop current application
      docker_compose:
        project_src: /opt/chat-app
        services:
          - app
        state: absent

    - name: Pull previous image
      docker_image:
        name: "{{ previous_image }}"
        source: pull

    - name: Update docker-compose to use previous image
      lineinfile:
        path: /opt/chat-app/docker-compose.yml
        regexp: 'image: chat-app:.*'
        line: '    image: {{ previous_image }}'

    - name: Start application with previous image
      docker_compose:
        project_src: /opt/chat-app
        services:
          - app
        state: present

    - name: Wait for application to be ready
      wait_for:
        port: 3000
        host: "{{ ansible_default_ipv4.address }}"
        delay: 10
        timeout: 60

    - name: Verify rollback
      uri:
        url: "http://{{ ansible_default_ipv4.address }}:3000/health"
        method: GET
        timeout: 10
      register: health_check
      failed_when: health_check.status != 200

- name: Notify rollback completion
  hosts: localhost
  tasks:
    - name: Send rollback notification
      uri:
        url: "{{ slack_webhook_url | default('') }}"
        method: POST
        body_format: json
        body:
          text: "🔄 Rollback completed for QEMU environment"
      when: slack_webhook_url is defined
EOF

    log_info "Rollback playbook created"
}

# Create Jenkins job configuration
create_jenkins_job_config() {
    log_step "Creating Jenkins job configuration..."
    
    cat > "$PROJECT_ROOT/jenkins-job-config.xml" << 'EOF'
<?xml version='1.1' encoding='UTF-8'?>
<flow-definition plugin="workflow-job@2.40">
  <actions/>
  <description>Encrypted Chat App - QEMU Deployment Pipeline</description>
  <keepDependencies>false</keepDependencies>
  <properties>
    <hudson.plugins.jira.JiraProjectProperty plugin="jira@3.1.1"/>
    <org.jenkinsci.plugins.workflow.job.properties.PipelineTriggersJobProperty>
      <triggers>
        <hudson.triggers.SCMTrigger>
          <spec>H/5 * * * *</spec>
          <ignorePostCommitHooks>false</ignorePostCommitHooks>
        </hudson.triggers.SCMTrigger>
      </triggers>
    </org.jenkinsci.plugins.workflow.job.properties.PipelineTriggersJobProperty>
  </properties>
  <definition class="org.jenkinsci.plugins.workflow.cps.CpsScmFlowDefinition" plugin="workflow-cps@2.92">
    <scm class="hudson.plugins.git.GitSCM" plugin="git@4.8.3">
      <configVersion>2</configVersion>
      <userRemoteConfigs>
        <hudson.plugins.git.UserRemoteConfig>
          <url>https://github.com/your-org/encrypted-chat-app.git</url>
          <credentialsId>github-credentials</credentialsId>
        </hudson.plugins.git.UserRemoteConfig>
      </userRemoteConfigs>
      <branches>
        <hudson.plugins.git.BranchSpec>
          <name>*/main</name>
        </hudson.plugins.git.BranchSpec>
        <hudson.plugins.git.BranchSpec>
          <name>*/develop</name>
        </hudson.plugins.git.BranchSpec>
      </branches>
      <doGenerateSubmoduleConfigurations>false</doGenerateSubmoduleConfigurations>
      <submoduleCfg class="list"/>
      <extensions/>
    </scm>
    <scriptPath>Jenkinsfile.qemu</scriptPath>
    <lightweight>true</lightweight>
  </definition>
  <triggers/>
  <disabled>false</disabled>
</flow-definition>
EOF

    log_info "Jenkins job configuration created"
}

# Create setup script for Jenkins integration
create_jenkins_setup() {
    log_step "Creating Jenkins setup script..."
    
    cat > "$PROJECT_ROOT/scripts/setup-jenkins-qemu.sh" << 'EOF'
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
EOF

    chmod +x "$PROJECT_ROOT/scripts/setup-jenkins-qemu.sh"
    log_info "Jenkins setup script created"
}

# Print integration summary
print_integration_summary() {
    echo ""
    log_info "Jenkins-QEMU Integration Complete!"
    echo ""
    echo "Generated Files:"
    echo "================"
    echo "  - Jenkinsfile.qemu: Main pipeline for QEMU deployment"
    echo "  - ansible/inventory.staging.ini: Staging environment inventory"
    echo "  - ansible/test-deployment.sh: Post-deployment testing script"
    echo "  - ansible/rollback.yml: Rollback playbook for failed deployments"
    echo "  - jenkins-job-config.xml: Jenkins job configuration"
    echo "  - scripts/setup-jenkins-qemu.sh: Jenkins setup instructions"
    echo ""
    echo "Next Steps:"
    echo "==========="
    echo "1. Set up Jenkins with required plugins and credentials"
    echo "2. Create new pipeline job using jenkins-job-config.xml"
    echo "3. Configure GitHub webhooks for automatic triggers"
    echo "4. Test the pipeline with a sample deployment"
    echo ""
    echo "Pipeline Features:"
    echo "=================="
    echo "  ✓ Automated building and testing"
    echo "  ✓ Security scanning (container and code)"
    echo "  ✓ QEMU VM environment management"
    echo "  ✓ Automated deployment with Ansible"
    echo "  ✓ Post-deployment testing and validation"
    echo "  ✓ Automatic rollback on failures"
    echo "  ✓ Performance testing for production"
    echo "  ✓ Slack notifications"
    echo "  ✓ Git tagging for successful deployments"
    echo ""
    echo "Environments:"
    echo "============="
    echo "  - Staging: develop/staging branches → QEMU VMs"
    echo "  - Production: main branch → QEMU VMs (with approval)"
    echo ""
    echo "Access Points:"
    echo "=============="
    echo "  - Application: https://192.168.100.12"
    echo "  - Monitoring: http://192.168.100.13:3000"
    echo "  - Jenkins: Configure according to your setup"
}

# Main function
main() {
    log_info "Setting up Jenkins-QEMU Integration"
    
    create_jenkins_qemu_pipeline
    create_staging_inventory
    create_deployment_test
    create_rollback_playbook
    create_jenkins_job_config
    create_jenkins_setup
    print_integration_summary
}

# Run main function
main "$@"
