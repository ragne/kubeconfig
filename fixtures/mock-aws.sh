#!/bin/bash

echo '{
  "kind": "ExecCredential",
  "apiVersion": "client.authentication.k8s.io/v1alpha1",
  "spec": {},
  "status": {
    "expirationTimestamp": "2019-08-14T18:44:27Z",
    "token": "k8s-aws-v1EXAMPLE_TOKEN_DATA_STRING..."
  }
}'
sleep 1;
exit 0;
