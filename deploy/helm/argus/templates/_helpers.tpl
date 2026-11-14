{{- define "argus.name" -}}
{{- .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "argus.fullname" -}}
{{- if contains .Chart.Name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "argus.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{ include "argus.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: argus
{{- end -}}

{{- define "argus.selectorLabels" -}}
app.kubernetes.io/name: {{ include "argus.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "argus.image" -}}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) -}}
{{- end -}}

{{- define "argus.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "argus.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/* The chart's own Secret (bootstrap key, API keys, bundled-database password). */}}
{{- define "argus.secretName" -}}
{{- default (include "argus.fullname" .) .Values.secrets.existingSecret -}}
{{- end -}}

{{- define "argus.bundledPostgres" -}}
{{- if and .Values.postgresql.enabled (not .Values.externalDatabase.existingSecret) -}}true{{- end -}}
{{- end -}}

{{- define "argus.postgresHost" -}}
{{- printf "%s-postgresql" (include "argus.fullname" .) -}}
{{- end -}}

{{/*
A generated value that survives upgrades: reuse the one already stored in the release's
Secret if it exists, otherwise create a random one. (`lookup` is empty under `helm template`.)
*/}}
{{- define "argus.persistentRandom" -}}
{{- $root := index . 0 -}}{{- $key := index . 1 -}}{{- $length := index . 2 -}}
{{- $existing := lookup "v1" "Secret" $root.Release.Namespace (include "argus.fullname" $root) -}}
{{- if and $existing (index $existing.data $key) -}}
{{- index $existing.data $key | b64dec -}}
{{- else -}}
{{- randAlphaNum $length -}}
{{- end -}}
{{- end -}}

{{/* Environment shared by the API container and the migration init container. */}}
{{- define "argus.databaseEnv" -}}
{{- if include "argus.bundledPostgres" . }}
- name: ARGUS_DB_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ include "argus.fullname" . }}
      key: postgres-password
- name: ARGUS_DATABASE_URL
  value: {{ printf "postgresql+asyncpg://%s:$(ARGUS_DB_PASSWORD)@%s:5432/%s" .Values.postgresql.username (include "argus.postgresHost" .) .Values.postgresql.database | quote }}
{{- else if .Values.externalDatabase.existingSecret }}
- name: ARGUS_DATABASE_URL
  valueFrom:
    secretKeyRef:
      name: {{ .Values.externalDatabase.existingSecret }}
      key: {{ .Values.externalDatabase.existingSecretKey }}
{{- else }}
{{- fail "Set externalDatabase.existingSecret, or postgresql.enabled=true for an evaluation database." }}
{{- end }}
{{- end -}}

{{- define "argus.podSecurityContext" -}}
runAsNonRoot: true
runAsUser: 10001
runAsGroup: 10001
fsGroup: 10001
seccompProfile:
  type: RuntimeDefault
{{- end -}}

{{- define "argus.containerSecurityContext" -}}
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
privileged: false
capabilities:
  drop: ["ALL"]
{{- end -}}
