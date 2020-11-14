#!/bin/bash
kubectl delete -f box.yaml
kubectl delete -f mutate_admission_ca.yaml
kubectl delete -f webhook.yaml