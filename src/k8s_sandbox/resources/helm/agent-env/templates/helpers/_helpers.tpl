{{/*
Expand the name of the chart.
*/}}
{{- define "agentEnv.name" -}}
{{- default .Chart.Name .Values.global.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "agentEnv.fullname" -}}
{{- if .Values.global.fullnameOverride -}}
{{- .Values.global.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.global.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" $name .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "agentEnv.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Common labels
*/}}
{{- define "agentEnv.labels" -}}
{{- include "agentEnv.labelsFromValues" . -}}
helm.sh/chart: {{ include "agentEnv.chart" . }}
{{ include "agentEnv.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{/*
Labels from values
*/}}
{{- define "agentEnv.labelsFromValues" -}}
{{- range $key, $value := $.Values.labels -}}
{{ quote $key }}: {{ quote $value }}
{{ end -}}
{{- end -}}

{{/*
Selector labels
*/}}
{{- define "agentEnv.selectorLabels" -}}
app.kubernetes.io/name: {{ include "agentEnv.name" . | quote }}
app.kubernetes.io/instance: {{ .Release.Name | quote }}
{{- end -}}

{{/*
Whether to create a ClusterIP type Service (which implies a DNS record) for a service
*/}}
{{- define "shouldCreateDnsRecord" -}}
{{- $service := . -}}
{{- if or $service.dnsRecord $service.additionalDnsRecords $service.ports -}}
true
{{- else -}}
{{- /* An empty value represents false */ -}}
{{- end -}}
{{- end -}}

{{/* toYaml, failing where Helm's renders nothing (it swallows its marshal errors), writes a "<<" key back as a merge, U+0085 as a space, or U+2028 or U+2029 as a line break. */}}
{{- define "agentEnv.toYaml" -}}
{{- if mustRegexMatch "[{,]\"<<\":" (toRawJson .) }}{{ fail "a \"<<\" key would merge into the mapping that holds it: rename it" }}{{ end -}}
{{- if contains "\u0085" (toRawJson .) }}{{ fail "toYaml would turn the U+0085 in this value into a space: remove it" }}{{ end -}}
{{- $yaml := toYaml . | required "toYaml rendered nothing for this value: remove DEL, C1 control characters, U+FFFE and U+FFFF from its strings, and shorten any mapping key over 1022 characters as JSON" -}}
{{- if mustRegexMatch "[\u2028\u2029]" $yaml }}{{ fail "toYaml would break a line at the U+2028 or U+2029 in this value, and what follows can become fields: remove it" }}{{ end -}}
{{- $yaml -}}
{{- end -}}

{{/* Render a deduped list of ports for a single service object (svc) */}}
{{- define "agentEnv.servicePortsListFor" -}}
{{- $seen := dict -}}
{{- $out := list -}}
{{- with .svc }}
  {{- range .ports }}
    {{- $proto := (default "TCP" .protocol) | upper -}}
    {{- $key := printf "%s/%v" $proto .port -}}
    {{- if not (hasKey $seen $key) -}}
      {{- $_ := set $seen $key true -}}
      {{- $out = append $out (dict "port" (printf "%v" .port) "protocol" $proto) -}}
    {{- end }}
  {{- end }}
{{- end }}
{{ include "agentEnv.toYaml" $out -}}
{{- end -}}
