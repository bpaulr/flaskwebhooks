import logging
import hmac
import json
import os
import subprocess
from pathlib import Path
from typing import List

import git
from dotenv import load_dotenv
from flask import Flask, request, abort

load_dotenv()

app = Flask(__name__)

logging.basicConfig(filename='requests.log', level=logging.DEBUG,
                    format='%(asctime)s %(levelname)s %(name)s %(threadName)s : %(message)s')

CONF_FILE = Path.joinpath(Path(__file__).parent.absolute(), 'hooks.json')


def hash_payload(secret: str, payload: bytes, digestmod: str) -> str:
    return hmac.new(secret.encode(), payload, digestmod).hexdigest()


def get_repo_conf(repo_name: str) -> dict:
    with open(CONF_FILE) as file:
        conf_data = json.load(file)
        return conf_data[repo_name]


def sync_local_repo(repo_path: Path) -> None:
    if not repo_path.exists() or not repo_path.is_dir():
        return

    if not is_git_repo(str(repo_path)):
        print('Not a git repo')
        return

    repo = git.Repo(str(repo_path))

    repo.remotes.origin.pull()


def is_git_repo(path):
    try:
        _ = git.Repo(path).git_dir
        return True
    except git.exc.InvalidGitRepositoryError:
        return False


def execute_commands(cmds: List[List[str]], cwd=None) -> None:
    for cmd in cmds:
        subprocess.check_call(cmd, cwd=cwd)


def sync_and_execute(repo_name: str):
    conf = get_repo_conf(repo_name)
    path = Path(conf['workspace'])
    sync_local_repo(path)

    if 'setup' in conf:
        execute_commands(conf['setup'], cwd=path)

    if 'startup' in conf:
        subprocess.Popen(conf['startup'], cwd=path)


@app.before_request
def log_request_info():
    app.logger.debug('Headers: %s', request.headers)
    app.logger.debug('Body: %s', request.get_data())


@app.route('/hooks/github-push', methods=['POST'])
def github_webhook_endpoint():
    print('Triggered flask hook')

    payload = request.get_json()

    repo_name = payload['repository']['name']

    SECRET = os.environ[f'{repo_name.upper()}_SECRET']

    # Extract signature header
    signature = request.headers.get('X-Hub-Signature')
    if not signature or not signature.startswith('sha1='):
        abort(400, 'X-Hub-Signature required')

    # Create local hash of payload
    digest = hash_payload(secret=SECRET, payload=request.data, digestmod='sha1')

    # Verify signature
    if not hmac.compare_digest(signature, 'sha1=' + digest):
        abort(400, 'Invalid signature')

    print('Passed hash check!')

    # sync git repo and run conf settings
    sync_and_execute(repo_name)

    return 'Pong'


if __name__ == '__main__':
    app.run(host='0.0.0.0', port='9000', debug=True)
