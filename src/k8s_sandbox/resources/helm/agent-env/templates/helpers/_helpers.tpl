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

{{/* Whether a service's pod has no network device, by the annotations its template gives it. Takes a dict of root ($) and name. */}}
{{- define "agentEnv.noCard" -}}
{{- $annotations := deepCopy (default (dict) .root.Values.annotations) -}}
{{- range $key, $value := (get .root.Values.services .name).podAnnotations }}{{ $_ := set $annotations $key $value }}{{ end -}}
{{- if eq (get $annotations "sandbox.amazonaws.com/network-isolated") "true" }}true{{ end -}}
{{- end -}}

{{/* A service's siblings over vsock-egress, as a JSON list of {service, address, named}: those with no network device on a network of its; named, if a DNS record lets its pod find one and it takes TCP. Takes a dict of root ($) and name. */}}
{{- define "agentEnv.siblings" -}}
{{- $own := get .root.Values.services .name -}}
{{- $siblings := list -}}
{{- if and (include "agentEnv.noCard" .) .root.Values.egressForwarderImage (not $own.networkIsolated) -}}
{{- $index := 0 -}}
{{- range $name, $service := .root.Values.services -}}
{{- $index = add1 $index -}}
{{- $shared := not $.root.Values.networks -}}
{{- range $own.networks }}{{ if has . (default (list) $service.networks) }}{{ $shared = true }}{{ end }}{{ end -}}
{{- if and (ne $name $.name) $shared (not $service.networkIsolated) (include "agentEnv.noCard" (dict "root" $.root "name" $name)) -}}
{{- $tcp := not $service.ports -}}
{{- range $service.ports }}{{ if eq (default "TCP" .protocol | upper) "TCP" }}{{ $tcp = true }}{{ end }}{{ end -}}
{{- $siblings = append $siblings (dict "service" $name "address" (printf "198.18.%d.%d" (div $index 256) (mod $index 256)) "named" (and $tcp (ne (include "shouldCreateDnsRecord" $service) ""))) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- toJson $siblings -}}
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

{{/* Render a deduped list of ports for a single service object (svc), and where vsock-egress carries its siblings to a TCP port of its (relayed), the port its pod's worker takes them at. */}}
{{- define "agentEnv.servicePortsListFor" -}}
{{- $seen := dict -}}
{{- $out := list -}}
{{- $tcp := false -}}
{{- with .svc }}
  {{- range .ports }}
    {{- $proto := (default "TCP" .protocol) | upper -}}
    {{- if eq $proto "TCP" }}{{ $tcp = true }}{{ end -}}
    {{- $key := printf "%s/%v" $proto .port -}}
    {{- if not (hasKey $seen $key) -}}
      {{- $_ := set $seen $key true -}}
      {{- $out = append $out (dict "port" (printf "%v" .port) "protocol" $proto) -}}
    {{- end }}
  {{- end }}
{{- end }}
{{- if and .relayed $tcp (not (hasKey $seen "TCP/3134")) }}{{ $out = append $out (dict "port" "3134" "protocol" "TCP") }}{{ end -}}
{{ include "agentEnv.toYaml" $out -}}
{{- end -}}
