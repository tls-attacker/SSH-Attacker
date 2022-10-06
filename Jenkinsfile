pipeline {
    agent any

    def jdkName = 'JDK 11'
    def mvnName = 'Maven 3.8.6'

    options {
        skipStagesAfterUnstable()
    }

    stages {
        stage('Clean') {
            steps {
                withMaven(jdk: jdkName, maven: mvnName) {
                    sh 'mvn clean'
                }
            }
        }
        stage('Format Check') {
            steps {
                withMaven(jdk: jdkName, maven: mvnName) {
                    sh 'mvn spotless:check'
                }
            }
        }
        stage('Build') {
            steps {
                withMaven(jdk: jdkName, maven: mvnName) {
                    sh 'mvn compile'
                }
            }
        }
        stage('Unit Tests') {
            steps {
                withMaven(jdk: jdkName, maven: mvnName) {
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
                withMaven(jdk: jdkName, maven: mvnName) {
                    sh 'mvn -Dmaven.test.failure.ignore=true failsafe:integration-test'
                }
            }
        }
        stage('Deploy to internal Nexus Repository') {
            when {
                branch 'main'
            }
            steps {
                withMaven(jdk: jdkName, maven: mvnName) {
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
