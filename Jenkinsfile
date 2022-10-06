pipeline {
    agent any

    environment {
        JDK_TOOL_NAME = 'JDK 11'
        MAVEN_TOOL_NAME = 'Maven 3.8.6'
    }

    options {
        skipStagesAfterUnstable()
    }

    stages {
        stage('Clean') {
            steps {
                withMaven(jdk: env.JDK_TOOL_NAME, maven: env.MAVEN_TOOL_NAME) {
                    sh 'mvn clean'
                }
            }
        }
        stage('Format Check') {
            steps {
                withMaven(jdk: env.JDK_TOOL_NAME, maven: env.MAVEN_TOOL_NAME) {
                    sh 'mvn spotless:check'
                }
            }
        }
        stage('Build') {
            steps {
                withMaven(jdk: env.JDK_TOOL_NAME, maven: env.MAVEN_TOOL_NAME) {
                    sh 'mvn compile'
                }
            }
        }
        stage('Unit Tests') {
            steps {
                withMaven(jdk: env.JDK_TOOL_NAME, maven: env.MAVEN_TOOL_NAME) {
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
                withMaven(jdk: env.JDK_TOOL_NAME, maven: env.MAVEN_TOOL_NAME) {
                    sh 'mvn -Dmaven.test.failure.ignore=true failsafe:integration-test'
                }
            }
        }
        stage('Deploy to internal Nexus Repository') {
            when {
                branch 'main'
            }
            steps {
                withMaven(jdk: env.JDK_TOOL_NAME, maven: env.MAVEN_TOOL_NAME) {
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
