#!/bin/bash
docker build . -t mutate
kind load docker-image mutate

kubectl apply -f webhook.yaml
kubectl apply -f mutate_admission_ca.yaml
