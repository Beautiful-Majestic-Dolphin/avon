{{/*
Expand the name of the chart.
*/}}
{{- define "avon.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "avon.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "avon.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "avon.labels" -}}
helm.sh/chart: {{ include "avon.chart" . }}
{{ include "avon.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "avon.selectorLabels" -}}
app.kubernetes.io/name: {{ include "avon.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "avon.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "avon.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Gateway fullname
*/}}
{{- define "avon.gateway.fullname" -}}
{{- printf "%s-gateway" (include "avon.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Gateway labels
*/}}
{{- define "avon.gateway.labels" -}}
{{ include "avon.labels" . }}
app.kubernetes.io/component: gateway
{{- end }}

{{/*
Gateway selector labels
*/}}
{{- define "avon.gateway.selectorLabels" -}}
{{ include "avon.selectorLabels" . }}
app.kubernetes.io/component: gateway
{{- end }}

{{/*
Control fullname
*/}}
{{- define "avon.control.fullname" -}}
{{- printf "%s-control" (include "avon.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Control labels
*/}}
{{- define "avon.control.labels" -}}
{{ include "avon.labels" . }}
app.kubernetes.io/component: control
{{- end }}

{{/*
Control selector labels
*/}}
{{- define "avon.control.selectorLabels" -}}
{{ include "avon.selectorLabels" . }}
app.kubernetes.io/component: control
{{- end }}

{{/*
CA fullname
*/}}
{{- define "avon.ca.fullname" -}}
{{- printf "%s-ca" (include "avon.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
CA labels
*/}}
{{- define "avon.ca.labels" -}}
{{ include "avon.labels" . }}
app.kubernetes.io/component: ca
{{- end }}

{{/*
CA selector labels
*/}}
{{- define "avon.ca.selectorLabels" -}}
{{ include "avon.selectorLabels" . }}
app.kubernetes.io/component: ca
{{- end }}

{{/*
Policy Engine fullname
*/}}
{{- define "avon.policyEngine.fullname" -}}
{{- printf "%s-policy-engine" (include "avon.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Policy Engine labels
*/}}
{{- define "avon.policyEngine.labels" -}}
{{ include "avon.labels" . }}
app.kubernetes.io/component: policy-engine
{{- end }}

{{/*
Policy Engine selector labels
*/}}
{{- define "avon.policyEngine.selectorLabels" -}}
{{ include "avon.selectorLabels" . }}
app.kubernetes.io/component: policy-engine
{{- end }}

{{/*
Admin API fullname
*/}}
{{- define "avon.adminApi.fullname" -}}
{{- printf "%s-admin-api" (include "avon.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Admin API labels
*/}}
{{- define "avon.adminApi.labels" -}}
{{ include "avon.labels" . }}
app.kubernetes.io/component: admin-api
{{- end }}

{{/*
Admin API selector labels
*/}}
{{- define "avon.adminApi.selectorLabels" -}}
{{ include "avon.selectorLabels" . }}
app.kubernetes.io/component: admin-api
{{- end }}

{{/*
Return the proper image name
*/}}
{{- define "avon.image" -}}
{{- $registryName := .global.imageRegistry -}}
{{- $repositoryName := .image.repository -}}
{{- $tag := .image.tag | default "latest" -}}
{{- if $registryName }}
{{- printf "%s/%s:%s" $registryName $repositoryName $tag -}}
{{- else }}
{{- printf "%s:%s" $repositoryName $tag -}}
{{- end }}
{{- end }}

{{/*
Return the PostgreSQL hostname
*/}}
{{- define "avon.postgresql.host" -}}
{{- if .Values.postgresql.enabled }}
{{- printf "%s-postgresql" (include "avon.fullname" .) }}
{{- else }}
{{- .Values.externalDatabase.host }}
{{- end }}
{{- end }}

{{/*
Return the Redis hostname
*/}}
{{- define "avon.redis.host" -}}
{{- if .Values.redis.enabled }}
{{- printf "%s-redis-master" (include "avon.fullname" .) }}
{{- else }}
{{- .Values.externalRedis.host }}
{{- end }}
{{- end }}

{{/*
Service mesh sidecar annotations for non-gateway services
*/}}
{{- define "avon.meshAnnotations" -}}
{{- if and .Values.serviceMesh.enabled (eq .Values.serviceMesh.provider "istio") }}
sidecar.istio.io/inject: "true"
{{- if .Values.serviceMesh.istio.revision }}
istio.io/rev: {{ .Values.serviceMesh.istio.revision | quote }}
{{- end }}
traffic.sidecar.istio.io/excludeInboundPorts: "9090"
{{- end }}
{{- if and .Values.serviceMesh.enabled (eq .Values.serviceMesh.provider "linkerd") }}
linkerd.io/inject: enabled
{{- end }}
{{- end }}

{{/*
Service mesh sidecar annotations for gateway (sidecar DISABLED)
*/}}
{{- define "avon.meshAnnotations.gateway" -}}
{{- if and .Values.serviceMesh.enabled (eq .Values.serviceMesh.provider "istio") }}
sidecar.istio.io/inject: "false"
{{- end }}
{{- if and .Values.serviceMesh.enabled (eq .Values.serviceMesh.provider "linkerd") }}
linkerd.io/inject: disabled
{{- end }}
{{- end }}
