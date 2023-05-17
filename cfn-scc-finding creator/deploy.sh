#!/bin/bash
gcloud functions deploy cfn-scc-finding-creator \
                        --runtime=nodejs14 \
                        --trigger-topic=org-audit-log-topic \
                        --ingress-settings=internal-only \
                        --region us-central1 \
                        --project=prj-c-logging-1e91 \
                        --entry-point=createSccFinding 