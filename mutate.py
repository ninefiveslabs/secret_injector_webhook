import base64
import jsonpatch
import logging
import hvac
from flask import Flask, request, jsonify

admission_controller = Flask(__name__)
admission_controller.logger.setLevel(logging.INFO)

mock_ssm = {'password': 'misiek123'}

vault_client = hvac.Client(
    url='http://vault.default.svc.cluster.local:8200',
    token='root',
)

container_path = "/spec/containers"

log_info = admission_controller.logger.info


@admission_controller.route('/mutate/pods', methods=['POST'])
def inject_secrets_webhook():
    log_info('Processing inject_secrets_webhook')
    request_info = request.get_json()
    containers = request_info['request']['object']['spec']['containers']
    log_info('containers: {}'.format(str(containers)))
    containers = update_containers(containers)
    return admission_response_patch(True,
                                    request_info['request']['uid'],
                                    "Adding side car",
                                    json_patch=jsonpatch.JsonPatch([{"op": "add",
                                                                     "path": container_path,
                                                                     "value": containers}]))


def update_containers(containers):
    log_info('In containers: {}'.format(str(containers)))
    for container in containers:
        for env in container['env']:
            log_info('env: {}'.format(str(env)))
            if "secret:" in env['value']:
                log_info('In {}: {}'.format(env['name'], env['value']))
                env['value'] = update_secret(env['value'])
                log_info('out {}: {}'.format(env['name'], env['value']))

    log_info('Out containers: {}'.format(str(containers)))
    return containers


def update_secret(secret):
    if ":vault:" in secret:
        try:
            _, _, path, sercert_name = secret.split(':')
            log_info('path: {}'.format(path))
            log_info('sercert_name: {}'.format(sercert_name))
            vault_secrets = vault_client.secrets.kv.read_secret_version(path=path)
            secret = vault_secrets['data']['data'][sercert_name]
            log_info('vault secret: {}'.format(secret))
            return secret
        except (KeyError, hvac.exceptions.InvalidPath):
            return "NOT_FOUND"
    elif ":ssm:" in secret:
        try:
            _, _, path = secret.split(':')
            log_info('path: {}'.format(path))
            secret = mock_ssm[path]
            log_info('ssm secret: {}'.format(secret))
            return secret
        except KeyError:
            return "NOT_FOUND"


def admission_response_patch(allowed, uid, message, json_patch):
    base64_patch = base64.b64encode(json_patch.to_string().encode("utf-8")).decode("utf-8")
    return jsonify({"apiVersion": "admission.k8s.io/v1",
                    "kind": "AdmissionReview",
                    "response": {"allowed": allowed,
                                 "status": {"message": message},
                                 "uid": uid,
                                 "patchType": "JSONPatch",
                                 "patch": base64_patch}})

if __name__ == '__main__':
    admission_controller.run(host='0.0.0.0', port=443, ssl_context=("/certs/cert.pem", "/certs/key.pem"))
