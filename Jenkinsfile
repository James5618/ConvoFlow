pipeline {
    agent any
    
    environment {
        DOCKER_REGISTRY = credentials('docker-registry-url')
        REGISTRY_CREDENTIALS = credentials('docker-registry-credentials')
        KUBECONFIG = credentials('kubeconfig')
        ANSIBLE_HOST_KEY_CHECKING = 'False'
        
        // Environment specific variables
        DEV_ENV = 'development'
        STAGING_ENV = 'staging' 
        PROD_ENV = 'production'
        
        // Image names
        BACKEND_IMAGE = "encrypted-chat-backend"
        FRONTEND_IMAGE = "encrypted-chat-frontend"
    }
    
    parameters {
        choice(
            name: 'DEPLOY_ENVIRONMENT',
            choices: ['none', 'development', 'staging', 'production'],
            description: 'Select deployment environment'
        )
        choice(
            name: 'DEPLOYMENT_TYPE',
            choices: ['docker-compose', 'kubernetes', 'ansible-vms'],
            description: 'Select deployment method'
        )
        booleanParam(
            name: 'SKIP_TESTS',
            defaultValue: false,
            description: 'Skip test execution'
        )
        booleanParam(
            name: 'FORCE_DEPLOY',
            defaultValue: false,
            description: 'Force deployment even if tests fail'
        )
    }
    
    options {
        buildDiscarder(logRotator(numToKeepStr: '10'))
        timeout(time: 60, unit: 'MINUTES')
        skipStagesAfterUnstable()
        retry(2)
    }
    
    triggers {
        // Poll SCM every 5 minutes for changes
        pollSCM('H/5 * * * *')
        
        // Nightly builds
        cron('H 2 * * *')
    }
    
    stages {
        stage('Checkout') {
            steps {
                script {
                    // Clean workspace
                    cleanWs()
                    
                    // Checkout code
                    checkout scm
                    
                    // Set build info
                    env.GIT_COMMIT_SHORT = sh(
                        script: "git rev-parse --short HEAD",
                        returnStdout: true
                    ).trim()
                    
                    env.BUILD_VERSION = "${env.BUILD_NUMBER}-${env.GIT_COMMIT_SHORT}"
                    env.IMAGE_TAG = env.BRANCH_NAME == 'main' ? 'latest' : env.BUILD_VERSION
                    
                    echo "Building version: ${env.BUILD_VERSION}"
                    echo "Image tag: ${env.IMAGE_TAG}"
                }
            }
        }
        
        stage('Environment Setup') {
            steps {
                script {
                    // Install dependencies
                    sh 'npm ci'
                    sh 'cd client && npm ci'
                    
                    // Setup environment files
                    sh '''
                        if [ ! -f .env.${DEV_ENV} ]; then
                            cp .env.development.example .env.${DEV_ENV} || true
                        fi
                    '''
                }
            }
        }
        
        stage('Code Quality & Security') {
            parallel {
                stage('Lint') {
                    steps {
                        script {
                            try {
                                sh 'npm run lint'
                                currentBuild.result = 'SUCCESS'
                            } catch (Exception e) {
                                echo "Linting failed: ${e.getMessage()}"
                                currentBuild.result = 'UNSTABLE'
                            }
                        }
                    }
                    post {
                        always {
                            // Publish lint results
                            publishHTML([
                                allowMissing: false,
                                alwaysLinkToLastBuild: true,
                                keepAll: true,
                                reportDir: 'lint-results',
                                reportFiles: '*.html',
                                reportName: 'Lint Report'
                            ])
                        }
                    }
                }
                
                stage('Security Scan') {
                    steps {
                        script {
                            // Dependency vulnerability scan
                            sh 'npm audit --audit-level=high || true'
                            
                            // SAST scanning with semgrep
                            sh '''
                                docker run --rm -v "${PWD}:/src" \
                                    returntocorp/semgrep:latest \
                                    --config=auto /src || true
                            '''
                            
                            // Container security scan
                            sh '''
                                docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
                                    -v "${PWD}:/code" \
                                    aquasec/trivy:latest fs /code || true
                            '''
                        }
                    }
                }
            }
        }
        
        stage('Tests') {
            when {
                not { params.SKIP_TESTS }
            }
            parallel {
                stage('Unit Tests - Backend') {
                    steps {
                        sh 'npm run test:server'
                    }
                    post {
                        always {
                            publishTestResults testResultsPattern: 'test-results/backend/*.xml'
                            publishCoverage adapters: [
                                coberturaAdapter('coverage/backend/cobertura-coverage.xml')
                            ], sourceFileResolver: sourceFiles('STORE_LAST_BUILD')
                        }
                    }
                }
                
                stage('Unit Tests - Frontend') {
                    steps {
                        sh 'cd client && npm run test:ci'
                    }
                    post {
                        always {
                            publishTestResults testResultsPattern: 'client/test-results/*.xml'
                            publishCoverage adapters: [
                                coberturaAdapter('client/coverage/cobertura-coverage.xml')
                            ], sourceFileResolver: sourceFiles('STORE_LAST_BUILD')
                        }
                    }
                }
                
                stage('Integration Tests') {
                    steps {
                        script {
                            try {
                                sh 'docker-compose -f docker-compose.test.yml up --build --abort-on-container-exit'
                            } finally {
                                sh 'docker-compose -f docker-compose.test.yml down -v'
                            }
                        }
                    }
                }
            }
        }
        
        stage('Build Images') {
            parallel {
                stage('Build Backend') {
                    steps {
                        script {
                            def backendImage = docker.build(
                                "${BACKEND_IMAGE}:${env.IMAGE_TAG}",
                                "-f Dockerfile ."
                            )
                            
                            // Tag for registry
                            backendImage.tag("${DOCKER_REGISTRY}/${BACKEND_IMAGE}:${env.IMAGE_TAG}")
                            if (env.BRANCH_NAME == 'main') {
                                backendImage.tag("${DOCKER_REGISTRY}/${BACKEND_IMAGE}:latest")
                            }
                            
                            env.BACKEND_IMAGE_FULL = "${DOCKER_REGISTRY}/${BACKEND_IMAGE}:${env.IMAGE_TAG}"
                        }
                    }
                }
                
                stage('Build Frontend') {
                    steps {
                        script {
                            def frontendImage = docker.build(
                                "${FRONTEND_IMAGE}:${env.IMAGE_TAG}",
                                "-f Dockerfile.client ."
                            )
                            
                            // Tag for registry
                            frontendImage.tag("${DOCKER_REGISTRY}/${FRONTEND_IMAGE}:${env.IMAGE_TAG}")
                            if (env.BRANCH_NAME == 'main') {
                                frontendImage.tag("${DOCKER_REGISTRY}/${FRONTEND_IMAGE}:latest")
                            }
                            
                            env.FRONTEND_IMAGE_FULL = "${DOCKER_REGISTRY}/${FRONTEND_IMAGE}:${env.IMAGE_TAG}"
                        }
                    }
                }
            }
        }
        
        stage('Image Security Scan') {
            parallel {
                stage('Scan Backend Image') {
                    steps {
                        sh """
                            docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
                                aquasec/trivy:latest image \
                                --exit-code 0 \
                                --severity HIGH,CRITICAL \
                                --format json \
                                --output backend-security-report.json \
                                ${BACKEND_IMAGE}:${env.IMAGE_TAG}
                        """
                    }
                }
                
                stage('Scan Frontend Image') {
                    steps {
                        sh """
                            docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
                                aquasec/trivy:latest image \
                                --exit-code 0 \
                                --severity HIGH,CRITICAL \
                                --format json \
                                --output frontend-security-report.json \
                                ${FRONTEND_IMAGE}:${env.IMAGE_TAG}
                        """
                    }
                }
            }
            post {
                always {
                    archiveArtifacts artifacts: '*-security-report.json', fingerprint: true
                }
            }
        }
        
        stage('Push Images') {
            when {
                anyOf {
                    branch 'main'
                    branch 'develop'
                    params.FORCE_DEPLOY
                }
            }
            steps {
                script {
                    docker.withRegistry("https://${DOCKER_REGISTRY}", env.REGISTRY_CREDENTIALS) {
                        // Push backend image
                        docker.image("${DOCKER_REGISTRY}/${BACKEND_IMAGE}:${env.IMAGE_TAG}").push()
                        
                        // Push frontend image
                        docker.image("${DOCKER_REGISTRY}/${FRONTEND_IMAGE}:${env.IMAGE_TAG}").push()
                        
                        // Push latest tags for main branch
                        if (env.BRANCH_NAME == 'main') {
                            docker.image("${DOCKER_REGISTRY}/${BACKEND_IMAGE}:latest").push()
                            docker.image("${DOCKER_REGISTRY}/${FRONTEND_IMAGE}:latest").push()
                        }
                    }
                }
            }
        }
        
        stage('Deploy') {
            when {
                not { equals expected: 'none', actual: params.DEPLOY_ENVIRONMENT }
            }
            steps {
                script {
                    switch(params.DEPLOYMENT_TYPE) {
                        case 'docker-compose':
                            deployDockerCompose()
                            break
                        case 'kubernetes':
                            deployKubernetes()
                            break
                        case 'ansible-vms':
                            deployAnsibleVMs()
                            break
                        default:
                            error("Unknown deployment type: ${params.DEPLOYMENT_TYPE}")
                    }
                }
            }
        }
        
        stage('E2E Tests') {
            when {
                anyOf {
                    equals expected: 'staging', actual: params.DEPLOY_ENVIRONMENT
                    equals expected: 'production', actual: params.DEPLOY_ENVIRONMENT
                }
            }
            steps {
                script {
                    try {
                        sh """
                            docker run --rm \
                                -e BASE_URL=https://${params.DEPLOY_ENVIRONMENT}.encrypted-chat.example.com \
                                -v \$(pwd)/e2e-results:/app/results \
                                ${DOCKER_REGISTRY}/encrypted-chat-e2e:${env.IMAGE_TAG}
                        """
                    } catch (Exception e) {
                        echo "E2E tests failed: ${e.getMessage()}"
                        currentBuild.result = 'UNSTABLE'
                    }
                }
            }
            post {
                always {
                    publishHTML([
                        allowMissing: true,
                        alwaysLinkToLastBuild: true,
                        keepAll: true,
                        reportDir: 'e2e-results',
                        reportFiles: '*.html',
                        reportName: 'E2E Test Report'
                    ])
                }
            }
        }
        
        stage('Performance Tests') {
            when {
                equals expected: 'production', actual: params.DEPLOY_ENVIRONMENT
            }
            steps {
                script {
                    sh """
                        docker run --rm \
                            -v \$(pwd)/performance-results:/app/results \
                            -e TARGET_URL=https://encrypted-chat.example.com \
                            ${DOCKER_REGISTRY}/encrypted-chat-performance:${env.IMAGE_TAG}
                    """
                }
            }
            post {
                always {
                    publishHTML([
                        allowMissing: true,
                        alwaysLinkToLastBuild: true,
                        keepAll: true,
                        reportDir: 'performance-results',
                        reportFiles: '*.html',
                        reportName: 'Performance Test Report'
                    ])
                }
            }
        }
    }
    
    post {
        always {
            // Clean up Docker images
            sh '''
                docker image prune -f
                docker system prune -f --volumes
            '''
            
            // Archive build artifacts
            archiveArtifacts artifacts: 'logs/**/*', allowEmptyArchive: true
            
            // Publish build info
            publishHTML([
                allowMissing: false,
                alwaysLinkToLastBuild: true,
                keepAll: true,
                reportDir: 'build-info',
                reportFiles: 'build-info.html',
                reportName: 'Build Information'
            ])
        }
        
        success {
            script {
                if (params.DEPLOY_ENVIRONMENT != 'none') {
                    slackSend(
                        channel: '#deployments',
                        color: 'good',
                        message: """
                            ✅ *Deployment Successful*
                            *Environment:* ${params.DEPLOY_ENVIRONMENT}
                            *Version:* ${env.BUILD_VERSION}
                            *Branch:* ${env.BRANCH_NAME}
                            *Build:* ${env.BUILD_URL}
                        """
                    )
                }
            }
        }
        
        failure {
            slackSend(
                channel: '#deployments',
                color: 'danger',
                message: """
                    ❌ *Build Failed*
                    *Branch:* ${env.BRANCH_NAME}
                    *Build:* ${env.BUILD_URL}
                    *Stage:* ${env.STAGE_NAME}
                """
            )
            
            // Send email notification
            emailext(
                subject: "Build Failed: ${env.JOB_NAME} - ${env.BUILD_NUMBER}",
                body: """
                    Build failed for ${env.JOB_NAME} - ${env.BUILD_NUMBER}
                    
                    Branch: ${env.BRANCH_NAME}
                    Commit: ${env.GIT_COMMIT_SHORT}
                    
                    View build: ${env.BUILD_URL}
                """,
                to: "${env.CHANGE_AUTHOR_EMAIL ?: 'dev-team@example.com'}"
            )
        }
        
        unstable {
            slackSend(
                channel: '#deployments',
                color: 'warning',
                message: """
                    ⚠️ *Build Unstable*
                    *Branch:* ${env.BRANCH_NAME}
                    *Build:* ${env.BUILD_URL}
                """
            )
        }
    }
}

// Custom deployment functions
def deployDockerCompose() {
    echo "Deploying with Docker Compose to ${params.DEPLOY_ENVIRONMENT}"
    sh """
        export ENVIRONMENT=${params.DEPLOY_ENVIRONMENT}
        export IMAGE_TAG=${env.IMAGE_TAG}
        export REGISTRY_URL=${DOCKER_REGISTRY}
        
        # Load environment variables
        if [ -f .env.${params.DEPLOY_ENVIRONMENT} ]; then
            export \$(cat .env.${params.DEPLOY_ENVIRONMENT} | xargs)
        fi
        
        # Deploy with docker-compose
        docker-compose -f docker-compose.onprem.yml up -d
        
        # Wait for services to be healthy
        sleep 30
        
        # Health check
        curl -f http://localhost/health || exit 1
    """
}

def deployKubernetes() {
    echo "Deploying to Kubernetes - ${params.DEPLOY_ENVIRONMENT}"
    withKubeConfig([credentialsId: 'kubeconfig']) {
        sh """
            # Set image tag
            export IMAGE_TAG=${env.IMAGE_TAG}
            
            # Apply Kubernetes manifests
            envsubst < k8s/deployment.yaml | kubectl apply -f -
            
            # Wait for rollout
            kubectl rollout status deployment/encrypted-chat-backend -n encrypted-chat --timeout=300s
            kubectl rollout status deployment/encrypted-chat-frontend -n encrypted-chat --timeout=300s
            
            # Verify deployment
            kubectl get pods -n encrypted-chat
        """
    }
}

def deployAnsibleVMs() {
    echo "Deploying with Ansible to VMs - ${params.DEPLOY_ENVIRONMENT}"
    withCredentials([
        sshUserPrivateKey(credentialsId: 'ansible-ssh-key', keyFileVariable: 'SSH_KEY')
    ]) {
        sh """
            # Set permissions for SSH key
            chmod 600 \$SSH_KEY
            
            # Run Ansible playbook
            ansible-playbook -i ansible/inventories/${params.DEPLOY_ENVIRONMENT}/hosts.yml \
                --private-key=\$SSH_KEY \
                --extra-vars "image_tag=${env.IMAGE_TAG}" \
                --extra-vars "registry_url=${DOCKER_REGISTRY}" \
                ansible/playbooks/deploy-application.yml
        """
    }
}
