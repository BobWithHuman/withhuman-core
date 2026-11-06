{{- define "withhuman.fullname" -}}
{{- if contains .Chart.Name .Release.Name -}}
{{- .Release.Name | trunc 40 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 40 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{/* Labels selecting one component: pass (dict "root" $ "component" "collector"). */}}
{{- define "withhuman.selectorLabels" -}}
app.kubernetes.io/name: {{ .root.Chart.Name }}
app.kubernetes.io/instance: {{ .root.Release.Name }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{- define "withhuman.labels" -}}
{{ include "withhuman.selectorLabels" . }}
app.kubernetes.io/managed-by: {{ .root.Release.Service }}
app.kubernetes.io/version: {{ .root.Values.imageTag | default .root.Chart.AppVersion | trunc 63 | quote }}
helm.sh/chart: {{ printf "%s-%s" .root.Chart.Name .root.Chart.Version }}
{{- end -}}

{{- define "withhuman.postgresEnv" -}}
- name: DATABASE_URL
  valueFrom:
    secretKeyRef:
      name: {{ .Values.existingSecret }}
      key: database-url
- name: DATABASE_POOL_SIZE
  value: {{ .Values.postgres.poolSize | quote }}
{{- end -}}

{{- define "withhuman.env.collector" -}}
- name: COLLECTOR_ADDR
  value: 0.0.0.0:8080
- name: COLLECTOR_EXT_AUTHZ_ADDR
  value: 0.0.0.0:9000
- name: GENERATOR_URL
  value: http://{{ include "withhuman.fullname" . }}-generator:8081
- name: REDIS_URL
  valueFrom:
    secretKeyRef:
      name: {{ .Values.existingSecret }}
      key: redis-url
- name: WITHHUMAN_MODE
  value: {{ .Values.collector.mode | quote }}
- name: WITHHUMAN_ON_FAILURE
  value: {{ .Values.collector.onFailure | quote }}
- name: WITHHUMAN_ASK
  value: {{ .Values.collector.ask | quote }}
- name: WITHHUMAN_DECISION_TIMEOUT_MS
  value: {{ .Values.collector.decisionTimeoutMs | quote }}
- name: WITHHUMAN_INTENT_CAPTURE
  value: {{ .Values.collector.intentCapture | quote }}
- name: WITHHUMAN_MCP_ENFORCE
  value: {{ .Values.collector.mcpEnforce | quote }}
{{- end -}}

{{- define "withhuman.env.generator" -}}
- name: GENERATOR_ADDR
  value: 0.0.0.0:8081
- name: DECISION_URL
  value: http://{{ include "withhuman.fullname" . }}-decision:8082
{{ include "withhuman.postgresEnv" . }}
{{- end -}}

{{- define "withhuman.env.decision" -}}
- name: DECISION_ADDR
  value: 0.0.0.0:8082
- name: WITHHUMAN_ENV
  value: {{ .Values.decision.environment | quote }}
- name: DECISION_PROVIDER
  value: {{ .Values.decision.provider | quote }}
- name: JEV_URL
  value: {{ .Values.decision.jevUrl | quote }}
- name: JEV_TIMEOUT_MS
  value: {{ .Values.decision.jevTimeoutMs | quote }}
- name: WITHHUMAN_INTENT_BLOCK_THRESHOLD
  value: {{ .Values.decision.intentBlockThreshold | quote }}
{{- if eq .Values.decision.provider "jev" }}
- name: JEV_API_KEY
  valueFrom:
    secretKeyRef:
      name: {{ .Values.existingSecret }}
      key: jev-api-key
{{- end }}
{{ include "withhuman.postgresEnv" . }}
{{- end -}}

{{/* Spreads a component's Pods across nodes and zones where the cluster allows it. */}}
{{- define "withhuman.topologySpread" -}}
topologySpreadConstraints:
  - maxSkew: 1
    topologyKey: kubernetes.io/hostname
    whenUnsatisfiable: ScheduleAnyway
    labelSelector:
      matchLabels:
        {{- include "withhuman.selectorLabels" . | nindent 8 }}
  - maxSkew: 1
    topologyKey: topology.kubernetes.io/zone
    whenUnsatisfiable: ScheduleAnyway
    labelSelector:
      matchLabels:
        {{- include "withhuman.selectorLabels" . | nindent 8 }}
{{- end -}}
