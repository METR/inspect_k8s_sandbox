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
{{ $key }}: {{ quote $value }}
{{ end -}}
{{- end -}}

{{/*
Selector labels
*/}}
{{- define "agentEnv.selectorLabels" -}}
app.kubernetes.io/name: {{ include "agentEnv.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/* The egress proxy a service's pod names, or nothing: takes a dict of root ($) and service. */}}
{{- define "agentEnv.egressProxy" -}}
{{- $key := "inspect-k8s-sandbox/egress-proxy" -}}
{{- $own := default (dict) .service.podAnnotations -}}
{{- with get (ternary $own (default (dict) .root.Values.annotations) (hasKey $own $key)) $key -}}
{{- /* A template here can name a Service of this release, whose name no values file knows. */ -}}
{{- $proxy := tpl . $.root -}}
{{- /* What the node's launcher takes, and a port a network policy can carry: Cilium reads port 0 as every port. */ -}}
{{- $form := printf "^[a-z0-9]([-a-z0-9]*[a-z0-9])?[.]%s[.]svc[.]cluster[.]local[.]?:[1-9][0-9]{0,4}$" $.root.Release.Namespace -}}
{{- if or (not (regexMatch $form $proxy)) (gt (atoi (regexFind "[0-9]+$" $proxy)) 65535) -}}
{{- fail (printf "the annotation %s is %q, not <service>.%s.svc.cluster.local:<port>, with a port from 1 to 65535: vsock-egress joins a pod only to a Service of its own namespace" $key $proxy $.root.Release.Namespace) -}}
{{- end -}}
{{- $proxy -}}
{{- end -}}
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
{{ toYaml $out -}}
{{- end -}}
