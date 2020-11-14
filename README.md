### Mutate webhook 
Example Mutating Admission Controller Webhook 

[Kind](https://kind.sigs.k8s.io/) used as Kubernetes cluster

1. Create cluster
```bash
kind create cluster --config cluster.yaml
```
1. Create signed cert/key pair (use script from https://github.com/morvencao/kube-mutating-webhook-tutorial)
```bash
git clone https://github.com/morvencao/kube-mutating-webhook-tutorial
./kube-mutating-webhook-tutorial/deployment/webhook-create-signed-cert.sh --service mutate-webhook-svc --namespace default --secret mutate-webhook-secret
export CA_BUNDLE=$(kubectl get secrets -o jsonpath="{.items[?(@.metadata.annotations['kubernetes\.io/service-account\.name']=='default')].data.ca\.crt}")
cat ./mutate_admission.yaml | ./kube-mutating-webhook-tutorial/deployment/webhook-patch-ca-bundle.sh > ./mutate_admission_ca.yaml 
```
 1. Create image
```bash
docker build . -t mutate
```

 2. Push image
```bash
kind load docker-image mutate
```
3. Create mutating webhook
```bash
kubectl apply -f webhook.yaml
```
4. Create Mutating Webhook Configuration
```bash
kubectl apply -f mutate_admission_ca.yaml
```
5. Mutate busbox
```bash
kubectl apply -f box.yaml
```

### Install Vault
https://www.vaultproject.io/docs/platform/k8s/helm/run

Add repo to helm
```
helm repo add hashicorp https://helm.releases.hashicorp.com
```

Install vault with dev mode
```
helm install vault hashicorp/vault --set "server.dev.enabled=true"
```

Forward port
```
kubectl port-forward vault-0 8200:8200
```
