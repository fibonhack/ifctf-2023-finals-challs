from enum import Enum
from flask import Flask, request
import json
import requests
import os

ADMIN_SECRET = os.environ.get('ADMIN_SECRET', 'admin')
BACKEND_HOST = f"http://{os.environ.get('BACKEND_HOST')}:{os.environ.get('BACKEND_PORT')}"


app = Flask(__name__)

class AccessPolicy(Enum):
    PUBLIC = 1
    ADMIN = 2


class Rule:
    def __init__(self, endpoint : str, policy: AccessPolicy):
        self.endpoint = endpoint
        self.policy = policy
    

    def check(self, content : dict, headers : dict):
        return content.get('endpoint', None) == self.endpoint and \
            self._check_policy(content, headers)


    def _check_policy(self, content : dict, headers : dict):
        if self.policy == AccessPolicy.ADMIN:
            return Rule._admin(content, headers)
        elif self.policy == AccessPolicy.PUBLIC:
            return Rule._public(content, headers)

        raise Exception("Invalid policy")


    def _admin(content: dict, headers: dict):
        return headers.get('X-Admin', None) == ADMIN_SECRET


    def _public(content: dict, headers: dict):
        return True


rules = [
    Rule('admin', AccessPolicy.ADMIN),
    Rule('add_note', AccessPolicy.PUBLIC),
    Rule('get_note', AccessPolicy.PUBLIC),
]


@app.route('/', methods = ['POST'])
def router():
    try:
        request_body = request.get_data()
        request_body = request_body.decode('utf-8')
        content = json.loads(request_body)
        headers = request.headers
    except Exception:
        return "Invalid request", 400

    for rule in rules:
        if rule.check(content, headers):
            response = requests.post(BACKEND_HOST, data={
                'data' : request_body
            })

            return {
                "response" : response.text,
                "status" : response.status_code
            }
    return "Access Denied", 403



if __name__ == '__main__':
    app.run(debug=True, port=5000) 
