pipeline {
    agent any

    options {
        skipStagesAfterUnstable()
    }

    stages {
        stage('Clean') {
            steps {
                withMaven jdk: 'JDK 11', maven: 'Maven 3.8.6' {
                    sh 'mvn clean'
                }
            }
        }
        stage('Format Check') {
            steps {
                withMaven jdk: 'JDK 11', maven: 'Maven 3.8.6' {
                    sh 'mvn spotless:check'
                }
            }
        }
        stage('Build') {
            steps {
                withMaven jdk: 'JDK 11', maven: 'Maven 3.8.6' {
                    sh 'mvn compile'
                }
            }
        }
        stage('Unit Tests') {
            steps {
                withMaven jdk: 'JDK 11', maven: 'Maven 3.8.6' {
                    sh 'mvn test jacoco:report'
                }
            }

            post {
                success {
                    junit testResults: '**/target/surefire-reports/TEST-*.xml'
                    publishCoverage adapters: [jacoco('**/target/site/jacoco/jacoco.xml')]
                }
            }
        }
        stage('Integration Tests') {
            steps {
                withMaven jdk: 'JDK 11', maven: 'Maven 3.8.6' {
                    sh 'mvn -Dmaven.test.failure.ignore=true failsafe:integration-test'
                }
            }
        }
        stage('Deploy to internal Nexus Repository') {
            when {
                branch 'main'
            }
            steps {
                withMaven jdk: 'JDK 11', maven: 'Maven 3.8.6' {
                    // Tests were already executed separately, so disable tests within this step
                    sh 'mvn -DskipTests=true install'
                }
            }

            post {
                success {
                    archiveArtifacts artifacts: '**/target/*.jar'
                }
            }
        }
    }
}
