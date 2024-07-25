import argparse
from datetime import datetime
import json
from os import environ, path
import re
import string
import subprocess
from pathlib import Path
from threading import Lock, Thread
import traceback
import requests
import yaml
from git import Repo


class Replicaset:
    def __init__(self):
        self.image = ""
        self.replicas = 0
        self.available_replicas = 0
        self.ready_replicas = 0

    def toJson(self):
        return json.dumps(self, default=lambda o: o.__dict__,
                          sort_keys=True, indent=4)

    def toCsv(self):
        return f"{self.image}, {self.replicas}, {self.available_replicas}, {self.ready_replicas}"


class Deploy:
    def __init__(self):
        self.image = ""
        self.available_status = ""
        self.progress_status = ""
        self.stable_rs = Replicaset()

    def toJson(self):
        return json.dumps(self, default=lambda o: o.__dict__,
                          sort_keys=True, indent=4)

    def toCsv(self):
        return f"{self.image}, {self.available_status}, {self.progress_status}, {self.stable_rs.toCsv()}"


class Service:
    def __init__(self):
        self.image = ""
        self.name = ""
        self.status = ""
        self.deploy = Deploy()
        self.primary = Deploy()
        self.rollout_status = ""

    def toJson(self):
        return json.dumps(self, default=lambda o: o.__dict__,
                          sort_keys=True, indent=4)

    def toCsv(self):
        return f"{self.name}, {self.image}, {self.status}, {self.rollout_status}, {self.deploy.toCsv()}, {self.primary.toCsv()}"


class Config:
    def __init__(self):
        self.status = ""
        self.name = ""

    def toJson(self):
        return json.dumps(self, default=lambda o: o.__dict__,
                          sort_keys=True, indent=4)

    def toCsv(self):
        return f"{self.name}, {self.status}"


class Gitops:
    def __init__(self, name: string, namespace: string, charts_version: string, image: string):
        self.name = name
        self.namespace = namespace
        self.charts_version = charts_version
        self.image = image
        self.status = ""
        self.service = Service()
        self.config = Config()

    def toJson(self):
        return json.dumps(self, default=lambda o: o.__dict__,
                          sort_keys=True, indent=4)

    def toCsv(self):
        return f"{self.namespace}, {self.name}, {self.charts_version}, {self.image} ,{self.status}, {self.config.toCsv()}, {self.service.toCsv()}"


def get_response(resource_type: string, namespace: string, name: string, kubeconfig_path: string):
    try:
        output = subprocess.check_output(
            ['kubectl', 'get', resource_type, '-n', namespace, name, '--request-timeout', '300', '-o', 'yaml', '--kubeconfig', kubeconfig_path])
        response = yaml.safe_load(output)
        return response
    except:
        return None


def get_kubeconfig(aws_profile_name: string, cluster_name: string, region: string, kubeconfig_path: string):
    output = subprocess.check_call(
        ['aws', 'eks', 'update-kubeconfig', '--name', cluster_name, '--alias', cluster_name, '--region', region, '--kubeconfig', kubeconfig_path, '--profile', aws_profile_name])
    return output


def get_helm_history(namespace: string, name: string, kubeconfig_path: string):
    try:
        output = subprocess.check_output(
            ['helm', 'history', '-n', namespace, name, '-o', 'yaml', '--max', '1', '--kubeconfig', kubeconfig_path])
        response = yaml.safe_load(output)
        return response[0]["description"]
    except:
        return None


def get_hr_status_tropos(namespace: string, name: string, kubeconfig_path: string):
    output = get_response('hr', namespace, name, kubeconfig_path)
    if output is None:
        return None, None, None
    if "releaseStatus" in output["status"]:
        release_status = output["status"]["releaseStatus"]
    else:
        release_status = f'Phase - {output["status"]["phase"]}'
    image_tag = ""
    if "values" in output["spec"] and "image" in output["spec"]["values"]:
        image_tag = output["spec"]["values"]["image"]["tag"]

    return output["spec"]["chart"]["ref"], release_status, image_tag


def get_hr_status_onecloud(namespace: string, name: string, version: string, image_version: string, kubeconfig_path: string):
    output = get_response('hr', namespace, name, kubeconfig_path)
    if output is None:
        return None
    if not "lastAppliedRevision" in output["status"]:
        return "Chart Install Pending"
    if "lastAppliedRevision" in output["status"] and output["status"]["lastAppliedRevision"] != version:
        return "Pending Chart Upgrade"
    conditions = output["status"]["conditions"]
    if len(conditions) > 1 and conditions[1]["type"] == "Released" and conditions[1]["status"] != "True":
        return join_sentences(conditions[1]["message"])
    if conditions[0]["type"] == "Ready" and conditions[0]["status"] != "True":
        return join_sentences(conditions[0]["message"])
    if "image" in output["spec"]["values"] and image_version != output["spec"]["values"]["image"]["tag"]:
        return "Pending Helm Upgrade"
    return "deployed"


def join_sentences(message: string):
    pattern = re.compile(r'\n')
    message = re.sub(pattern, '---', message)
    message = re.sub(',', '##', message)
    return message.strip()


def get_canary_status(namespace: string, name: string, kubeconfig_path: string):
    output = get_response('canary', namespace, name, kubeconfig_path)
    if output is None:
        return None
    return output["status"]["phase"]


def get_rollout_status(namespace: string, name: string, kubeconfig_path: string):
    output = get_response('rollout', namespace, name, kubeconfig_path)
    if output is None:
        return None, None
    stable_rs = None
    phase = None
    if "stableRS" in output["status"]:
        stable_rs = output["status"]["stableRS"]
    if "phase" in output["status"]:
        phase = output["status"]["phase"]
    if phase != "Healthy" and "message" in output["status"]:
        phase = output["status"]["message"]
    return phase, stable_rs


def get_deploy_status(namespace: string, name: string, stable_rs: string, kubeconfig_path: string) -> Deploy:
    deploy = Deploy()
    if name is None:
        return deploy
    output = get_response('deploy', namespace, name, kubeconfig_path)
    if output is None:
        return deploy
    for container in output["spec"]["template"]["spec"]["containers"]:
        if container["name"] == "service":
            deploy.image = container["image"]
    for condition in output["status"]["conditions"]:
        if condition["type"] == "Available":
            deploy.available_status = f'{condition["status"]} - {condition["message"]}'
            if condition["status"] == "True":
                deploy.available_status = condition["status"]
        if condition["type"] == "Progressing":
            deploy.progress_status = f'{condition["status"]} - {condition["message"]}'
            if condition["status"] == "True":
                deploy.progress_status = condition["status"]
    if stable_rs is not None:
        deploy.stable_rs = get_rs(namespace, f'{name}-{stable_rs}', kubeconfig_path)
    return deploy


def get_rs(namespace: string, rs: string, kubeconfig_path: string):
    output = get_response('rs', namespace, rs, kubeconfig_path)
    if output is None:
        return None
    rs = Replicaset()
    if "replicas" in output["status"]:
        rs.replicas = output["status"]["replicas"]
    if "availableReplicas" in output["status"]:
        rs.available_replicas = output["status"]["availableReplicas"]
    if "readyReplicas" in output["status"]:
        rs.ready_replicas = output["status"]["readyReplicas"]
    rs.image = output["spec"]["template"]["spec"]["containers"][0]["image"]
    return rs


def read_file_onecloud(file_path: Path, lock: Lock, charts_version: string, primary_kubeconfig_path: string, failover_kubeconfig_path='', write_to_console=False):
    with open(file_path, 'r') as file:
        try:
            docs = list(yaml.safe_load_all(file))
            for doc in docs:
                if "spec" in doc and "values" in doc["spec"] and "image" in doc["spec"]["values"]:
                    config_only = False
                    if "configOnly" in doc["spec"]["values"]:
                        config_only = doc["spec"]["values"]["configOnly"]
                    image_tag = doc["spec"]["values"]["image"]["tag"]
                    harbor_repository = doc["spec"]["values"]["image"]["repository"]
                    harbor_registry = doc["spec"]["values"]["image"]["registry"]
                    namespace = doc["metadata"]["namespace"]
                    name = doc["metadata"]["name"]
                    service_name = name.removesuffix("-wrapper")
                    image = f"{harbor_registry}/{harbor_repository}:{image_tag}"
                    gitops = Gitops(name, namespace, charts_version, image)
                    # print(f"getting user from {git_url}")
                    # user = get_user_from_git(git_url, image_tag)
                    # print(f"User from Git {user}")
                    wrapper_hr_status = get_hr_status_onecloud(
                        namespace, f'{service_name}-wrapper', charts_version, image_tag, primary_kubeconfig_path)
                    gitops.status = wrapper_hr_status

                    if wrapper_hr_status != "deployed":
                        helm_history_status = get_helm_history(
                            namespace, f'{service_name}-wrapper', primary_kubeconfig_path)
                        if helm_history_status is not None:
                            gitops.status = helm_history_status
                    if not config_only:
                        config_hr_status = get_hr_status_onecloud(
                            namespace, f'{service_name}-c0nfig', charts_version, image_tag, primary_kubeconfig_path)
                        gitops.config.name = f'{service_name}-c0nfig'
                        gitops.config.status = config_hr_status

                        if config_hr_status == "deployed":
                            service_hr_status = get_hr_status_onecloud(
                                namespace, service_name, charts_version, image_tag, primary_kubeconfig_path)
                            gitops.service.status = service_hr_status
                            if service_hr_status != "deployed":
                                helm_history_status = get_helm_history(
                                    namespace, service_name, primary_kubeconfig_path)
                                if helm_history_status is not None:
                                    gitops.service.status = helm_history_status
                            gitops.service.image = image
                            gitops.service.name = service_name
                            gitops.service.status = service_hr_status

                            gitops.service.rollout_status, stable_rs = get_rollout_status(
                                namespace, service_name, primary_kubeconfig_path)
                            deploy = get_deploy_status(namespace, service_name, stable_rs, primary_kubeconfig_path)
                            gitops.service.deploy = deploy
                            if len(failover_kubeconfig_path) > 0:
                                _, failover_stable_rs = get_rollout_status(
                                namespace, service_name, failover_kubeconfig_path)
                                failover_deploy = get_deploy_status(
                                    namespace, service_name,failover_stable_rs, failover_kubeconfig_path)
                                if deploy.image != failover_deploy.image or (deploy.stable_rs.ready_replicas > 0 and failover_deploy.stable_rs.ready_replicas == 0) or gitops.service.rollout_status == "Failed":
                                    write_content_safely(
                                        _services_to_check_path, f"{namespace}, {service_name}, {deploy.image}, {failover_deploy.image}, {deploy.image == failover_deploy.image}, {deploy.stable_rs.ready_replicas}, {failover_deploy.stable_rs.ready_replicas}, {gitops.service.rollout_status}\n", lock)
                        else:
                            helm_history_status = get_helm_history(
                                namespace, f'{service_name}-c0nfig', primary_kubeconfig_path)
                            if helm_history_status is not None:
                                gitops.config.status = helm_history_status
                    write_content_safely(
                        _deploy_status_path, f"{gitops.toCsv()},{(gitops.service.deploy.image == gitops.service.deploy.stable_rs.image)}, {(image == gitops.service.deploy.stable_rs.image)}, {config_only}\n", lock)
                    if write_to_console:
                        print(f"{gitops.toJson()}\n")
                        print(
                            f"ConfigOnly: {config_only}\nCanaryAndPrimaryHaveSameImage: {(gitops.service.deploy.image == gitops.service.deploy.stable_rs.image)}\nPrimarySyncedWithGitops: {(image==gitops.service.deploy.image)}")

        except Exception as e:
            write_content(_failed_files_path,
                          f"Failed to load Yaml for {file_path} \n")
            print(f"Failed to read file {file_path}", e)
            traceback.print_exc()


def read_file_tropos(file_path: Path, lock: Lock, charts_version: string, primary_kubeconfig_path: string, failover_kubeconfig_path='', write_to_console=False):
    with open(file_path, 'r') as file:
        try:
            docs = list(yaml.safe_load_all(file))
            for doc in docs:
                if "spec" in doc and "values" in doc["spec"] and "image" in doc["spec"]["values"]:
                    config_only = False
                    if "configOnly" in doc["spec"]["values"]:
                        config_only = doc["spec"]["values"]["configOnly"]
                    image_tag = doc["spec"]["values"]["image"]["tag"]
                    harbor_repository = doc["spec"]["values"]["image"]["repository"]
                    harbor_registry = doc["spec"]["values"]["image"]["registry"]
                    service_chart_ref = doc["spec"]["values"]["chartBranch"]
                    namespace = doc["metadata"]["namespace"]
                    name = doc["metadata"]["name"]
                    git_url = (doc["spec"]["values"]["url"]
                               ).removesuffix(".git")
                    service_name = name.removesuffix("-app")
                    image = f"{harbor_registry}/{harbor_repository}:{image_tag}"
                    gitops = Gitops(name, namespace, charts_version, image)
                    user = get_user_from_git(git_url, image_tag)

                    app_hr_ref, app_hr_status, tag = get_hr_status_tropos(
                        namespace, f'{service_name}-app', primary_kubeconfig_path)
                    gitops.status = app_hr_status
                    if tag != image_tag:
                        gitops.status = "Helm Install yet to start."
                    if app_hr_ref != charts_version:
                        gitops.status = "Pending Upgrade"
                    if app_hr_status != "deployed":
                        helm_history_status = get_helm_history(
                            namespace, f'{service_name}-app', primary_kubeconfig_path)
                        if helm_history_status is not None:
                            gitops.status = helm_history_status
                    if not config_only:
                        config_hr_ref, config_hr_status, tag = get_hr_status_tropos(
                            namespace, f'{service_name}-tr0p0s-config', primary_kubeconfig_path)
                        gitops.config.name = f'{service_name}-tr0p0s-config'
                        gitops.config.status = config_hr_status
                        if config_hr_ref != charts_version:
                            gitops.status = "Pending Upgrade"

                        if config_hr_status == "deployed":
                            service_hr_ref, service_hr_status, tag = get_hr_status_tropos(
                                namespace, f'{service_name}-service', primary_kubeconfig_path)
                            gitops.service.status = service_hr_status
                            if service_hr_status != "deployed":
                                helm_history_status = get_helm_history(
                                    namespace, service_name, primary_kubeconfig_path)
                                if helm_history_status is not None:
                                    gitops.service.status = helm_history_status
                            gitops.service.image = image
                            gitops.service.name = f'{service_name}-service'
                            if tag != image_tag:
                                gitops.service.status = "Helm Install yet to start."
                            if service_hr_ref != service_chart_ref:
                                gitops.service.status = f"Pending Upgrade. from {service_hr_ref} to {service_chart_ref}"

                            gitops.service.canary_status = get_canary_status(
                                namespace, service_name, primary_kubeconfig_path)

                            canary_deploy = get_deploy_status(
                                namespace, service_name, primary_kubeconfig_path)
                            gitops.service.canary = canary_deploy

                            primary_deploy = get_deploy_status(
                                namespace, f"{service_name}-primary", primary_kubeconfig_path)
                            gitops.service.primary = primary_deploy

                            if len(failover_kubeconfig_path) > 0:
                                failover_primary_deploy = get_deploy_status(
                                    namespace, f"{service_name}-primary", failover_kubeconfig_path)
                                if primary_deploy.image != failover_primary_deploy.image or (primary_deploy.ready_replicas > 0 and failover_primary_deploy.ready_replicas == 0 ) or gitops.service.canary_status == "Failed":
                                    write_content_safely(
                                        _services_to_check_path, f"{namespace}, {service_name}, {primary_deploy.image}, {failover_primary_deploy.image}, {primary_deploy.image == failover_primary_deploy.image}, {primary_deploy.ready_replicas}, {failover_primary_deploy.ready_replicas}, {gitops.service.canary_status}, {user}\n", lock)
                        else:
                            helm_history_status = get_helm_history(
                                namespace, f'{service_name}-tr0p0s-config', primary_kubeconfig_path)
                            if helm_history_status is not None:
                                gitops.config.status = helm_history_status
                    write_content_safely(
                        _deploy_status_path, f"{gitops.toCsv()},{(gitops.service.canary.image == gitops.service.primary.image)}, {(image == gitops.service.primary.image)}, {config_only}, {user}\n", lock)
                    if write_to_console:
                        print(f"{gitops.toJson()}\n")
                        print(
                            f"ConfigOnly: {config_only}\nCanaryAndPrimaryHaveSameImage: {(gitops.service.canary.image == gitops.service.primary.image)}\nPrimarySyncedWithGitops: {(image==gitops.service.primary.image)}")
        except Exception as e:
            write_content(_failed_files_path,
                          f"Failed to load Yaml for {file_path} \n")
            print(f"Failed to read file {file_path}", e)
            traceback.print_exc()


def write_content(file_name: string, content: string, access_mode="a"):
    with open(file_name, access_mode) as file:
        file.write(content)
        file.close()


def write_content_safely(file_name: string, content: string, lock: Lock, access_mode="a"):
    with lock:
        with open(file_name, access_mode) as file:
            file.write(content)
            file.close()


def pull_orgin(gitops_path: string):
    repo = Repo(gitops_path)
    origin = repo.remote(name='origin')
    pull_result = origin.pull("master", rebase=True)
    for result in pull_result:
        print(result)


def get_user_from_git(git_repository_url: string, git_tag: string):
    retrieve = True
    author = ""
    default_branch = get_default_branch(git_repository_url)
    if default_branch is None:
        return "Unable to Access Git Repo"
    url = git_repository_url.replace("https://github.azc.ext.hp.com",
                                     "https://github.azc.ext.hp.com/api/v3/repos") + f"/commits/{default_branch}"
    authorization = environ["git_token"]
    headers = {
        'Authorization': f'Bearer {authorization}',
        'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28'
    }
    while retrieve:
        retrieve = False
        r = requests.get(url, headers=headers)
        if r.status_code != 200 and url.endswith(default_branch):
            retrieve = True
            url = get_commit_sha(git_repository_url, git_tag)
            if url is None:
                print(f"url couldn't be fetched for {git_repository_url}")
                return author
            continue
        if r.status_code != 200:
            print(
                f"Failed to fetch username for url: {r.url} with statusCode: {r.status_code}")
            continue
        response = json.loads(r.content)
        try:
            if "commit" in response and "author" in response["commit"] and "email" in response["commit"]["author"]:
                author = response["commit"]["author"]["email"]
        except Exception as e:
            print(f"Exception in retrieving user for {git_repository_url}", e)
    return author


def get_default_branch(git_repository_url: string):
    url = git_repository_url.replace("https://github.azc.ext.hp.com",
                                     "https://github.azc.ext.hp.com/api/v3/repos")
    authorization = environ["git_token"]
    headers = {
        'Authorization': f'Bearer {authorization}',
        'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28'
    }
    r = requests.get(url, headers=headers)
    if r.status_code != 200:
        print(
            f"Failed to fetch username for url: {r.url} with statusCode: {r.status_code}")
        return None
    response = json.loads(r.content)
    return response["default_branch"]


def get_commit_sha(git_repository_url: string, git_tag: string):
    url = git_repository_url.replace("https://github.azc.ext.hp.com",
                                     "https://github.azc.ext.hp.com/api/v3/repos") + "/tags"
    authorization = environ["git_token"]
    headers = {
        'Authorization': f'Bearer {authorization}',
        'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28'
    }
    r = requests.get(url, headers=headers)
    if r.status_code != 200:
        print(
            f"Failed to fetch username for url: {r.url} with statusCode: {r.status_code}")
        return None
    response = json.loads(r.content)
    for tag in response:
        if "name" in tag and tag["name"] == git_tag and "commit" in tag and "url" in tag["commit"]:
            return tag["commit"]["url"]
    print(
        f"Commit details couldn't be fetched for {git_tag} for url: {r.url} with statusCode: {r.status_code}")
    return None


def execute_work(gitops_path: string, lock: Lock, charts_version: string, primary_kubeconfig_path: string, failover_kubeconfig_path: string):
    threads = []
    pull_orgin(gitops_path)
    services_paths = Path(gitops_path).glob('projects/**/services/*.yaml')

    for path in services_paths:
        t = Thread(target=read_file, args=(path, lock, charts_version, primary_kubeconfig_path, failover_kubeconfig_path))
        threads.append(t)
        t.start()
        if (len(threads) == _number_of_threads):
            for t in threads:
                t.join()
            threads = []
            pull_orgin(gitops_path)


def get_current_context():
    output = ""
    try:
        output = subprocess.check_output(
            ['kubectl', 'config', 'current-context']).decode('utf-8')
    except Exception as e:
        print(f"Failed to get current context. {output}", e)
    return output.strip()


def main():
    global _number_of_threads
    global _failed_files_path
    global _deploy_status_path
    global _services_to_check_path
    global _primary_kubeconfig_path
    global _failover_kubeconfig_path

    _primary_kubeconfig_path = ""
    _failover_kubeconfig_path = ""

    _number_of_threads = 100
    lock = Lock()
    parser = argparse.ArgumentParser(
        description="Status of services",
        prog='Status of services')
    parser.add_argument(
        '--gitops-repo-path',
        help='Local Gitops repository path to be analyzed.')
    parser.add_argument(
        '--gitops-file-path',
        help='Local Gitops path of the service to be analyzed.')
    parser.add_argument(
        '--aws-profile',
        help='AWS Profile name.')
    parser.add_argument(
        '--cluster-region',
        help='EKS Cluster Region.')
    parser.add_argument(
        '--primary-cluster-name',
        help='Primary Cluster Name.')
    parser.add_argument(
        '--failover-cluster-name',
        help='Failover Cluster Name')
    parser.add_argument(
        '--primary-charts-version',
        help='Onecloud charts version in primary cluster')

    argsval = parser.parse_args()
    gitops_repo_path = argsval.gitops_repo_path
    gitops_file_path = argsval.gitops_file_path
    aws_profile = argsval.aws_profile
    cluster_region = argsval.cluster_region
    primary_cluster_name = argsval.primary_cluster_name
    failover_cluster_name = argsval.failover_cluster_name
    charts_version = argsval.primary_charts_version

    if (not path.exists(str(gitops_repo_path))) and (not path.exists(str(gitops_file_path))):
        print("Please provide valid gitops repo path or file path")
        return

    if aws_profile is None or len(aws_profile) == 0:
        aws_profile = input("Enter AWS Profile name: ")
    if cluster_region is None or len(cluster_region) == 0:
        cluster_region = input("Enter region of cluster: ")
    if primary_cluster_name is None or len(primary_cluster_name) == 0:
        primary_cluster_name = input("Enter Primary Cluster Name: ")

    is_failover_cluster_present = input(
        "Is there failover cluster (Y)es/(N)o: ").lower()
    is_fail_over = is_failover_cluster_present == "y" or is_failover_cluster_present == "yes"
    if is_fail_over and (cluster_region is None or len(cluster_region) == 0):
        failover_cluster_name = input("Enter Failover Cluster Name: ")

    if len(aws_profile) > 0 and len(primary_cluster_name) > 0 and len(cluster_region) > 0:
        _primary_kubeconfig_path = f"{Path.cwd().as_posix()}/{primary_cluster_name}"
        get_kubeconfig(aws_profile, primary_cluster_name, cluster_region,
                       _primary_kubeconfig_path)

    if len(aws_profile) > 0 and failover_cluster_name is not None and len(failover_cluster_name) > 0 and len(cluster_region) > 0:
        _failover_kubeconfig_path = f"{Path.cwd().as_posix()}/{failover_cluster_name}"
        get_kubeconfig(aws_profile, failover_cluster_name, cluster_region,
                       _failover_kubeconfig_path)
        _services_to_check_path = f"{failover_cluster_name}_services_to_check.csv"

        write_content(_services_to_check_path,
                      "Namespace, ServiceName, ImageName, FailoverImageName, PrimaryAndFailoverSameImage?, ReadyReplicas, FailoverReadyReplicas, CanaryStatus, Contact\n", "w")

    _failed_files_path = f"{primary_cluster_name}_failed_files.txt"
    _deploy_status_path = f"{primary_cluster_name}_deploy_status.csv"

    write_content_onecloud(_deploy_status_path, "Project, WrapperChartName, WrapperChartVersion, ImageVersion, WrapperChartStatus, ConfigChartName, ConfigChartStatus, ServiceChartName, ImageVersion, ServiceChartStatus, RolloutStatus, CanaryImageVersion, CanaryAvailableStatus, CanaryProgressStatus, StableRsImageVersion, StableRsReplicas, StableRsAvailableReplicas, StableRsReadyReplicas, CanaryPrimarySame?, PrimarySyncedWithGitops?, ConfigOnly?, Contact\n", "w")
    write_content_tropos(_deploy_status_path, "Project, WrapperChartName, WrapperChartVersion, ImageVersion, WrapperChartStatus, ConfigChartName, ConfigChartStatus, ServiceChartName, ImageVersion, ServiceChartStatus, CanaryStatus, CanaryImageVersion, CanaryAvailableStatus, CanaryProgressStatus, CanaryReplicas, CanaryAvailableReplicas, CanaryReadyReplicas, PrimaryImageVersion, PrimaryAvailableStatus, PrimaryProgressStatus, PrimaryReplicas, PrimaryAvailableReplicas, PrimaryReadyReplicas, CanaryPrimarySame?, PrimarySyncedWithGitops?, ConfigOnly?, Contact\n", "w")
    write_content(_failed_files_path, "", "w")

    if charts_version is None:
        charts_version = "2.0.32"
        default_chart_version = input(
        f"proceed to check with charts version {charts_version} in primary cluster (Y)es/(N)o: ").lower()
        default_chart_version = default_chart_version == "y" or default_chart_version == "yes"
        if not default_chart_version:
            charts_version = input("Enter primary cluster Charts Version: ")

    if gitops_file_path is not None:
        read_file(gitops_file_path, lock, charts_version, _primary_kubeconfig_path,
                  _failover_kubeconfig_path, True)
        return
    
    if gitops_repo_path is None:
        gitops_repo_path = input("Enter gitOpsPath: ")

    start_time = datetime.now()
    print(
        f"starting at analyzing files in path {gitops_repo_path} at {start_time}")

    execute_work(gitops_repo_path, lock, charts_version, _primary_kubeconfig_path,
                _failover_kubeconfig_path)

    end_time = datetime.now()
    print(
        f"completed analyzing files in path {gitops_repo_path} at {end_time}")
    print("timetaken: ", (end_time-start_time))


if __name__ == '__main__':
    main()
