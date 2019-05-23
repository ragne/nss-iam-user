node('build') {
    def artifact = "target/release/libnss_iam_user.so"
    def branchName = env.BRANCH_NAME
    def branchNameEscaped = branchName.replaceAll("[\\./]", "-").replaceAll("[^A-Za-z0-9\\-]", "")
    def workspace = pwd()
    def dockerBuildContainerName = 'aws-rust-build'
    def myID = sh(returnStdout: true, script: 'id -u').trim()

    stage("Cleanup Workspace") {
    try {
      // Wipe the workspace so we are building completely clean
      sh("sudo chown -R `id -u` ${workspace}")
      deleteDir()
    } catch (Exception e) {
      currentBuild.result = 'FAILURE'

      error('Workspace cleanup failed!')
    }
  }

  stage("Checkout") {
    try {
      checkout scm
    } catch (Exception e) {
      currentBuild.result = 'FAILURE'
      error('Stopping early...')
    }
  }

  stage("Build docker image for builing") {
      sh "docker build -t ${dockerBuildContainerName} ."
  }

  stage("Test") {
    try {
        ansiColor('xterm') {
            withDockerContainer(args: "-v ${pwd()}:/workdir -e 'RUST_BACKTRACE=1' -e CARGO_HOME=/workdir/.cache -t -w /workdir", image: dockerBuildContainerName) {
                    sh "cargo test --release"
                }
        }
    } catch (Exception e) {
      currentBuild.result = 'UNSTABLE'
      println('Test execution failed')
    }
  }

  stage("Build") {
    try {
        ansiColor('xterm') {
            withDockerContainer(args: "-v ${pwd()}:/workdir -e 'RUST_BACKTRACE=1' -e CARGO_HOME=/workdir/.cache -t -w /workdir", image: dockerBuildContainerName) {
                    sh "cargo build --release"
                }
        }
    } catch (Exception e) {
      currentBuild.result = 'FAILURE'
      error('Build failed')
    }
  }


  stage("Publish artifact") {
    try {
      withCredentials([usernamePassword(credentialsId: 'nexus-docker-creds', passwordVariable: 'nexusPass', usernameVariable: 'nexusUser')]) {
        sh "curl -v --user '${nexusUser}:${nexusPass}' --upload-file ${artifact} https://nexus.iii-conv.com/repository/deployment_tools/"
      }
    } catch (Exception e) {
      currentBuild.result = 'FAILURE'
      slackNotify('Build failed', 'danger')
      println(e)
      error('Publish tools failed!')
    }
  }

}