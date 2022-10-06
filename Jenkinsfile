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
                    sh 'mvn -DskipTests=true package'
                }
            }

            post {
                success {
                    archiveArtifacts artifacts: '**/target/*.jar'
                }
            }
        }
        stage('Unit Tests') {
            steps {
                withMaven(jdk: env.JDK_TOOL_NAME, maven: env.MAVEN_TOOL_NAME) {
                    sh 'mvn -Dskip.failsafe.tests=true verify'
                }
            }

            post {
                always {
                    junit testResults: '**/target/surefire-reports/TEST-*.xml'
                }
                success {
                    publishCoverage adapters: [jacoco(mergeToOneReport: true, '**/target/site/jacoco/jacoco.xml')], tag: 'SSH-Attacker'
                }
            }
        }
        stage('Integration Tests') {
            steps {
                withMaven(jdk: env.JDK_TOOL_NAME, maven: env.MAVEN_TOOL_NAME) {
                    sh 'mvn -Dskip.surefire.tests=true verify'
                }
            }

            post {
                always {
                    junit testResults: '**/target/failsafe-reports/TEST-*.xml', allowEmptyResults: true
                }
                success {
                    publishCoverage adapters: [jacoco(mergeToOneReport: true, '**/target/site/jacoco-it/jacoco.xml')], tag: 'SSH-Attacker'
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
        }
    }
}
