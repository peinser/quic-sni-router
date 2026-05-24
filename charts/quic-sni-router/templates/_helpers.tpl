{{/*
Chart name (with override).
*/}}
{{- define "quic-sni-router.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Fully qualified name (release-name + chart-name), with override.
*/}}
{{- define "quic-sni-router.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Chart label value (Helm best-practice: name-version).
*/}}
{{- define "quic-sni-router.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Selector labels — stable across upgrades. Do NOT include chart version here:
spec.selector is immutable on Deployments, so a chart bump would break upgrades.
*/}}
{{- define "quic-sni-router.selectorLabels" -}}
app.kubernetes.io/name: {{ include "quic-sni-router.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/*
Common labels — applied to metadata.labels of every resource. Includes the
selector labels plus version/chart/managed-by per Kubernetes recommended-labels.
*/}}
{{- define "quic-sni-router.labels" -}}
helm.sh/chart: {{ include "quic-sni-router.chart" . }}
{{ include "quic-sni-router.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/component: router
app.kubernetes.io/part-of: quic-sni-router
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- with .Values.commonLabels }}
{{ toYaml . }}
{{- end }}
{{- end -}}

{{/*
ServiceAccount name in use (created or referenced).
*/}}
{{- define "quic-sni-router.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "quic-sni-router.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/*
Fully qualified image reference. Falls back to .Chart.AppVersion if no tag set.
*/}}
{{- define "quic-sni-router.image" -}}
{{- $tag := default .Chart.AppVersion .Values.image.tag -}}
{{- printf "%s:%s" .Values.image.repository $tag -}}
{{- end -}}

{{/*
Container-side port the router binds inside the pod. Parsed from
.Values.config.listen.udp (".:8443" or "0.0.0.0:8443" both yield 8443) so the
Deployment, NetworkPolicy and the rendered router.yaml never drift apart.
*/}}
{{- define "quic-sni-router.containerPort" -}}
{{- regexReplaceAll "^.*:" .Values.config.listen.udp "" -}}
{{- end -}}

{{/*
ConfigMap name (own or external).
*/}}
{{- define "quic-sni-router.configMapName" -}}
{{- if .Values.configMap.create -}}
{{- include "quic-sni-router.fullname" . -}}
{{- else -}}
{{- required "configMap.name is required when configMap.create=false" .Values.configMap.name -}}
{{- end -}}
{{- end -}}
